"""hydra/plugins/vless_cdn/plugin.py — VLESS за внешним CDN: XHTTP packet-up, uplink GET.

Топология отличается от остальных протоколов: публичное имя принадлежит CDN, на наш
сервер приходит только origin-соединение, а сайт и туннель живут на одном имени и
различаются путём. Поэтому протокол живёт отдельным плагином, а не режимом внутри
существующего VLESS+XHTTP.
"""

from __future__ import annotations

from collections.abc import Callable

from hydra.contracts import JsonObject, JsonValue
from hydra.core.state_models import User
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.context import PluginStateAccess
from hydra.contracts.vless_cdn import (
    CLIENT_LABEL,
    CONFIG_DEFAULTS,
    DECOY_ROUTE,
    DEFAULT_ENCRYPTION_MODE,
    DEFAULT_XHTTP_PATH,
    PROTOCOL_NAME,
    as_int,
    as_int_or,
    normalize_hostname,
    normalize_media_mode,
    normalize_media_source,
    normalize_path,
    resolve_host,
    server_encryption_value,
)

# Имя функции берётся из модуля, а не из пакета: пакет реэкспортирует плагин,
# и импорт через него замыкал бы плагин на самого себя.
from hydra.plugins.vless_cdn.client import profile as client_profile
from hydra.plugins.vless_cdn.client import share_link as client_share_link
from hydra.plugins.vless_cdn.profile import xhttp_transport

INBOUND_TAG = "vless-cdn-in"


class VlessCdnPlugin(BasePlugin):
    """VLESS inbound, к которому CDN ходит по HTTPS с одним origin-именем."""

    meta = PluginMeta(
        name=PROTOCOL_NAME,
        description="VLESS через внешний CDN: XHTTP packet-up, uplink GET, сайт о регионе",
        display_name=CLIENT_LABEL,
        subscription_profile_name=CLIENT_LABEL,
        category=PluginCategory.TRANSPORT,
        version="0.1.0",
        # Публичное имя выдаёт CDN, а origin-имя спрашивается отдельно, поэтому
        # общий сценарий «спросить основной домен» здесь не подходит.
        needs_domain=False,
        commands=(
            "set_cdn_domain",
            "set_origin_host",
            "set_path",
            "set_cam_source_url",
            "set_media_mode",
            "set_stream_settings",
        ),
        queries=("get_summary",),
        config_defaults=CONFIG_DEFAULTS,
        connection_source="tracked",
    )

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        """Протокол живёт внутри ядра: без него ставить нечего."""
        from hydra.core.singbox import is_installed

        return is_installed()

    def uninstall(self) -> bool:
        """Своих артефактов пока нет: маршрут и inbound снимаются вместе с ними."""
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Маршрут
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def route_config() -> dict[str, JsonValue]:
        """Свежая копия декларации маршрута: планировщик читает её из состояния."""
        return dict(DECOY_ROUTE)

    # ═════════════════════════════════════════════════════════════════════
    #  configure
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: PluginStateAccess) -> None:
        """Не дать включить протокол, который не установлен.

        Маршрут читается из состояния сразу, как только протокол включён, а без
        сертификата origin сборка документа маршрутов падает — вместе со всей
        перестройкой мультиплексора. Поэтому отказ случается здесь, до неё.
        """
        plugin_state = state.protocols.get(PROTOCOL_NAME)
        config = plugin_state.config if plugin_state else {}
        required = (
            "cdn_domain",
            "origin_host",
            "xhttp_path",
            "cert_file",
            "key_file",
            "encryption_private_key",
        )
        missing = [key for key in required if not str(config.get(key, "") or "").strip()]
        if not as_int(config.get("core_port")):
            missing.append("core_port")
        if missing:
            raise ValueError(
                f"Протокол не установлен: сначала выполните установку (не хватает: {', '.join(missing)})",
            )

    def generate_client_config(self, user: User, state: PluginStateAccess) -> str:
        """Клиентский профиль одного пользователя — то, что уходит в подписку."""
        config = self._provisioned(state)
        if config is None:
            return ""
        try:
            return client_profile(user, config)
        except ValueError:
            return ""

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        """Share-ссылка для тех клиентов, которые её понимают."""
        config = self._provisioned(state)
        if config is None:
            return ""
        try:
            return client_share_link(user, config)
        except ValueError:
            return ""

    @staticmethod
    def _provisioned(state: PluginStateAccess) -> dict | None:
        """Конфиг отдаётся только включённым и полностью установленным протоколом."""
        plugin_state = state.protocols.get(PROTOCOL_NAME)
        if plugin_state is None or not plugin_state.enabled:
            return None
        return dict(plugin_state.config)

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        """Inbound VLESS с XHTTP packet-up и расшифровкой VLESS Encryption.

        Пока нет ключа, порта или хотя бы одного пользователя, слушателя не появляется:
        полупроверенный вход хуже отсутствующего, потому что выглядит рабочим.
        """
        protocol = state.protocols.get(PROTOCOL_NAME)
        if protocol is None:
            return ConfigFragment()
        config = protocol.config
        cdn = str(config.get("cdn_domain", "")).strip()
        origin = str(config.get("origin_host", "")).strip()
        path = str(config.get("xhttp_path", DEFAULT_XHTTP_PATH)).strip()
        port = as_int(config.get("core_port"))
        private_key = str(config.get("encryption_private_key", "")).strip()
        mode = str(config.get("encryption_mode", DEFAULT_ENCRYPTION_MODE)).strip()
        users: list[JsonValue] = [{"name": user.email, "uuid": user.uuid} for user in state.users if not user.blocked]
        if not (cdn and origin and path and port and private_key and users):
            return ConfigFragment()
        try:
            decryption = server_encryption_value(private_key, mode=mode)
        except ValueError:
            return ConfigFragment()
        return ConfigFragment(
            inbounds=[self._inbound(cdn, path, port, decryption, users)],
        )

    @staticmethod
    def _inbound(
        host: str,
        path: str,
        port: int,
        decryption: str,
        users: list[JsonValue],
    ) -> JsonObject:
        inbound: JsonObject = {
            "type": "vless",
            "tag": INBOUND_TAG,
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": users,
            "decryption": decryption,
            # TLS завершает web backend, поэтому внутри inbound его нет: сюда
            # приходит уже расшифрованный поток.
            "transport": xhttp_transport(path, host, client=False),
        }
        return inbound

    # ═════════════════════════════════════════════════════════════════════
    #  Команды
    # ═════════════════════════════════════════════════════════════════════

    def set_cdn_domain(self, state: PluginStateAccess, value: str) -> bool:
        """Публичное имя, к которому подключается клиент."""
        return self._store(state, "cdn_domain", value, field="CDN-домен")

    def set_origin_host(self, state: PluginStateAccess, value: str) -> bool:
        """Имя, под которым CDN ходит на наш сервер: SNI, сертификат, маршрут."""
        return self._store(state, "origin_host", value, field="Origin-имя")

    def set_path(self, state: PluginStateAccess, value: str) -> bool:
        """Путь XHTTP — общий для маршрута, ядра и клиентского профиля."""
        plugin_state = state.protocols.get(PROTOCOL_NAME)
        if plugin_state is None:
            return False
        try:
            path = normalize_path(value)
        except ValueError:
            return False
        plugin_state.config["xhttp_path"] = path
        return True

    def set_cam_source_url(
        self,
        state: PluginStateAccess,
        url: str,
        *,
        resolve: Callable[[str], list[str]] = resolve_host,
    ) -> bool:
        """Источник потока: пусто — очистить, иначе — SSRF-безопасный URL.

        Проверяем форму и SSRF (`normalize_media_source`): относительность сегментов — не
        наша забота, её держит сам плейлист, который пишет ffmpeg. `resolve` инжектируем —
        тесты не ходят в DNS.
        """
        plugin_state = state.protocols.get(PROTOCOL_NAME)
        if plugin_state is None:
            return False
        try:
            source = normalize_media_source(url, resolve=resolve)
        except ValueError:
            return False
        plugin_state.config["cam_source_url"] = source
        return True

    def set_media_mode(self, state: PluginStateAccess, mode: str) -> bool:
        """Что показывает страница: живое видео или фото региона.

        Режим ничего не пересобирает в маршрутах — медиа-путь живёт от источника, а не от
        режима, и боевой XHTTP-путь обязан оставаться на месте в любом случае. Неизвестное
        значение приводится к дефолту, а не отклоняется: оператор не должен запираться
        в режиме, который сам же и опечатал.
        """
        plugin_state = state.protocols.get(PROTOCOL_NAME)
        if plugin_state is None:
            return False
        plugin_state.config["media_mode"] = normalize_media_mode(mode)
        return True

    def set_stream_settings(
        self,
        state: PluginStateAccess,
        *,
        hls_time: object,
        list_size: object,
        idle_timeout: object,
    ) -> bool:
        """Три настройки потока разом: порознь они смысла не имеют.

        Границы — не украшение: слишком маленькое окно снова делает поток хрупким, а
        слишком короткая длительность сегмента заставляет ffmpeg резать чаще, чем он
        может (резать можно только по кейфреймам). Верхняя граница окна ограничивает
        диск: каждый сегмент — это мегабайты.
        """
        plugin_state = state.protocols.get(PROTOCOL_NAME)
        if plugin_state is None:
            return False
        plugin_state.config["stream_hls_time"] = min(30, max(1, as_int_or(hls_time, 1)))
        plugin_state.config["stream_hls_list_size"] = min(60, max(3, as_int_or(list_size, 3)))
        plugin_state.config["stream_idle_timeout"] = min(24 * 3600, max(0, as_int_or(idle_timeout, 0)))
        return True

    def get_summary(self, state: PluginStateAccess) -> dict[str, object]:
        """То, что оператор должен видеть про протокол в одном месте."""
        plugin_state = state.protocols.get(PROTOCOL_NAME)
        config = plugin_state.config if plugin_state else {}
        return {
            "cdn_domain": str(config.get("cdn_domain", "")),
            "origin_host": str(config.get("origin_host", "")),
            "xhttp_path": str(config.get("xhttp_path", DEFAULT_XHTTP_PATH)),
            "core_port": as_int(config.get("core_port", 0)),
            "media_mode": normalize_media_mode(config.get("media_mode")),
            "ready": self._ready(config),
        }

    # ═════════════════════════════════════════════════════════════════════
    #  Статус
    # ═════════════════════════════════════════════════════════════════════

    def status(self, state: PluginStateAccess | None = None) -> PluginStatus:
        plugin_state = state.protocols.get(PROTOCOL_NAME) if state else None
        config = plugin_state.config if plugin_state else {}
        return PluginStatus(
            installed=bool(plugin_state and plugin_state.installed),
            enabled=bool(plugin_state and plugin_state.enabled),
            running=bool(plugin_state and plugin_state.enabled and self._ready(config)),
            info=dict(self.get_summary(state)) if state else {},
        )

    # ═════════════════════════════════════════════════════════════════════
    #  Внутреннее
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _ready(config: dict) -> bool:
        return bool(config.get("cdn_domain") and config.get("origin_host"))

    def _store(self, state: PluginStateAccess, key: str, value: str, *, field: str) -> bool:
        plugin_state = state.protocols.get(PROTOCOL_NAME)
        if plugin_state is None:
            return False
        try:
            host = normalize_hostname(value, field=field)
        except ValueError:
            return False
        plugin_state.config[key] = host
        return True


__all__ = ["PROTOCOL_NAME", "VlessCdnPlugin"]
