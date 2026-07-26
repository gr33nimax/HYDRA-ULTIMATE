"""Specialised settings adapters kept outside the generic plugin menu."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui.tui import error, menu, prompt, success
from hydra.utils.crypto import gen_token


SettingsOption = tuple[str, str]
OptionFactory = Callable[[PluginState], SettingsOption | None]
SettingsHandler = Callable[[AppState, object, ApplicationService], None]


@dataclass(frozen=True)
class SettingsAdapter:
    option: OptionFactory
    open: SettingsHandler


def _desired_state(state: AppState, name: str) -> PluginState:
    return state.protocols.get(name) or PluginState()


def _report_change(changed: bool, success_text: str) -> None:
    if changed:
        success(success_text)
    else:
        error(
            "Не удалось применить настройки; "
            "предыдущая конфигурация восстановлена",
        )


def _naive_option(desired: PluginState) -> SettingsOption | None:
    if not desired.enabled:
        return None
    current = str(desired.config.get("network", "tcp"))
    label = {
        "tcp": "HTTP/2",
        "quic": "QUIC",
        "both": "HTTP/2+QUIC",
    }.get(current, current)
    return "🔀 Сменить транспорт", f"Текущий: {label}"


def _menu_naive(
    state: AppState,
    _plugin: object,
    app: ApplicationService,
) -> None:
    selected = menu(
        [
            ("1", "HTTP/2 (TCP)", "Максимальная совместимость"),
            ("2", "QUIC (UDP)", "HTTP/3 через UDP"),
            ("3", "HTTP/2 + QUIC", "Оба транспорта"),
            ("0", "↩ Отмена", ""),
        ],
        "Транспорт NaiveProxy",
    )
    network = {"1": "tcp", "2": "quic", "3": "both"}.get(selected)
    if network is None:
        return
    changed = app.plugin_command(
        state,
        "naive",
        "set_transport",
        network=network,
    )
    _report_change(changed, f"Транспорт изменён на {network}")
    prompt("Нажмите Enter")


def _shadowtls_option(desired: PluginState) -> SettingsOption:
    current = str(
        desired.config.get("handshake_sni", "не выбран"),
    )
    return "🌐 Сменить SNI", f"Текущий: {current}"


def _menu_shadowtls(
    state: AppState,
    _plugin: object,
    app: ApplicationService,
) -> None:
    from hydra.ui._menus.shadowtls_settings import choose_shadowtls_sni

    value = choose_shadowtls_sni()
    if value:
        try:
            changed = app.plugin_command(
                state,
                "shadowtls",
                "set_handshake_sni",
                value=value,
            )
            _report_change(
                changed,
                f"SNI ShadowTLS изменён на {value}",
            )
        except ValueError as exc:
            error(str(exc))
    prompt("Нажмите Enter")


def _standard_settings_option(
    _desired: PluginState,
) -> SettingsOption:
    return "⚙️  Настройки", "Параметры транспорта и обфускации"


def menu_hysteria2_settings(
    state: AppState,
    _plugin: object,
    app: ApplicationService,
) -> None:
    """Edit Hysteria2 desired settings through transactional commands."""
    while True:
        state = app.admin.load_state()
        desired = _desired_state(state, "hysteria2")
        mode = desired.config.get("congestion_mode", "bbr")
        bandwidth = ""
        if mode == "brutal":
            bandwidth = (
                f" · {desired.config.get('up_mbps', 100)}/"
                f"{desired.config.get('down_mbps', 100)} Mbps"
            )
        choice = menu(
            [
                (
                    "1",
                    "🌐 Домен и TLS",
                    desired.config.get("domain", "не задан"),
                ),
                (
                    "2",
                    "🔌 UDP-порт",
                    str(desired.config.get("port", 8443)),
                ),
                (
                    "3",
                    "🚀 Congestion control",
                    f"{str(mode).upper()}{bandwidth}",
                ),
                (
                    "4",
                    "🔑 Сменить Salamander-пароль",
                    "Ссылки обновятся",
                ),
                ("0", "↩ Назад", ""),
            ],
            "НАСТРОЙКИ HYSTERIA2",
        )
        if choice == "0":
            return
        try:
            changed = _change_hysteria2(
                choice,
                state,
                desired,
                app,
            )
            if changed is None:
                continue
            _report_change(changed, "Настройки Hysteria2 обновлены")
        except (TypeError, ValueError) as exc:
            error(str(exc))
        prompt("Нажмите Enter")


def _change_hysteria2(
    choice: str,
    state: AppState,
    desired: PluginState,
    app: ApplicationService,
) -> bool | None:
    if choice == "1":
        domain = prompt(
            "Новый домен Hysteria2",
            default=str(desired.config.get("domain", "")),
        )
        return bool(domain) and app.plugin_command(
            state,
            "hysteria2",
            "set_domain",
            domain=domain,
        )
    if choice == "2":
        port = int(
            prompt(
                "Новый UDP-порт",
                default=str(desired.config.get("port", 8443)),
            ),
        )
        return app.plugin_command(
            state,
            "hysteria2",
            "set_port",
            port=port,
        )
    if choice == "3":
        return _change_hysteria2_congestion(state, desired, app)
    if choice == "4":
        password = (
            prompt(
                "Новый пароль (пусто = сгенерировать)",
                default="",
            ).strip()
            or gen_token(24)
        )
        return app.plugin_command(
            state,
            "hysteria2",
            "set_obfs_password",
            password=password,
        )
    return None


def _change_hysteria2_congestion(
    state: AppState,
    desired: PluginState,
    app: ApplicationService,
) -> bool | None:
    selected = menu(
        [
            ("1", "BBR", "Автоматическая оценка"),
            ("2", "Brutal", "Явные upload/download Mbps"),
            ("0", "Отмена", ""),
        ],
        "CONGESTION CONTROL HYSTERIA2",
    )
    if selected == "0":
        return None
    parameters: dict[str, object] = {
        "mode": "bbr" if selected == "1" else "brutal",
    }
    if selected == "2":
        parameters.update(
            up_mbps=int(
                prompt(
                    "Upload Mbps",
                    default=str(desired.config.get("up_mbps", 100)),
                ),
            ),
            down_mbps=int(
                prompt(
                    "Download Mbps",
                    default=str(desired.config.get("down_mbps", 100)),
                ),
            ),
        )
    return app.plugin_command(
        state,
        "hysteria2",
        "set_congestion",
        **parameters,
    )


def menu_snell_settings(
    state: AppState,
    _plugin: object,
    app: ApplicationService,
) -> None:
    """Edit Snell desired settings through its public command."""
    while True:
        state = app.admin.load_state()
        desired = _desired_state(state, "snell")
        configured_version = int(desired.config.get("version", 4))
        if configured_version not in {4, 5}:
            raise ValueError("Hydra Snell supports version 4")
        mode = str(desired.config.get("obfs_mode", "http"))
        host = str(desired.config.get("obfs_host", "www.bing.com"))
        choice = menu(
            [
                (
                    "1",
                    "🎭 Simple obfs",
                    f"{mode.upper()} · {host}" if mode else "выключен",
                ),
                ("0", "↩ Назад", ""),
            ],
            "НАСТРОЙКИ SNELL v4",
        )
        if choice == "0":
            return
        try:
            changed = _change_snell(state, host, app)
            if changed is None:
                continue
            _report_change(changed, "Настройки Snell обновлены")
        except (TypeError, ValueError) as exc:
            error(str(exc))
        prompt("Нажмите Enter")


def _change_snell(
    state: AppState,
    host: str,
    app: ApplicationService,
) -> bool | None:
    selected = menu(
        [
            ("1", "HTTP obfs", "Имитация HTTP-трафика"),
            ("2", "Выключить", "Чистый Snell"),
            ("0", "Отмена", ""),
        ],
        "SIMPLE OBFS SNELL",
    )
    new_mode = {"1": "http", "2": ""}.get(selected)
    if new_mode is None:
        return None
    new_host = (
        prompt("Маскировочный host", default=host)
        if new_mode
        else host
    )
    return app.plugin_command(
        state,
        "snell",
        "set_settings",
        version=4,
        obfs_mode=new_mode,
        obfs_host=new_host,
    )


SETTINGS_ADAPTERS: dict[str, SettingsAdapter] = {
    "naive": SettingsAdapter(_naive_option, _menu_naive),
    "shadowtls": SettingsAdapter(
        _shadowtls_option,
        _menu_shadowtls,
    ),
    "hysteria2": SettingsAdapter(
        _standard_settings_option,
        menu_hysteria2_settings,
    ),
    "snell": SettingsAdapter(
        _standard_settings_option,
        menu_snell_settings,
    ),
}


def settings_option(
    plugin_name: str,
    desired: PluginState,
) -> SettingsOption | None:
    adapter = SETTINGS_ADAPTERS.get(plugin_name)
    return adapter.option(desired) if adapter else None


def open_settings(
    state: AppState,
    plugin: object,
    app: ApplicationService,
) -> bool:
    plugin_name = plugin.meta.name
    adapter = SETTINGS_ADAPTERS.get(plugin_name)
    if adapter is None:
        return False
    adapter.open(state, plugin, app)
    return True


__all__ = [
    "SETTINGS_ADAPTERS",
    "menu_hysteria2_settings",
    "menu_snell_settings",
    "open_settings",
    "settings_option",
]
