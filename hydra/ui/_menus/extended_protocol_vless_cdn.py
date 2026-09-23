"""Меню протокола «VLESS через CDN»: установка, профиль клиента, страница."""

from __future__ import annotations

from hydra.contracts.vless_cdn import as_int
from hydra.core.state_models import AppState
from hydra.plugins.base import BasePlugin
from hydra.plugins.vless_cdn.plugin import PROTOCOL_NAME
from hydra.services.application import ApplicationService
from hydra.ui.protocol_ui import protocol_menu_title, protocol_status_panel
from hydra.ui.tui import (
    BOLD,
    CYAN,
    NC,
    clear,
    confirm,
    error,
    info,
    menu,
    prompt,
    success,
)

from hydra.ui._menus.extended_protocol_common import _application, _desired_state


def _set_enabled(state: AppState, desired: object, app: ApplicationService) -> bool:
    return app.disable_vless_cdn(state) if getattr(desired, "enabled", False) else app.enable_vless_cdn(state)


def _install(state: AppState, plugin: BasePlugin, app: ApplicationService) -> None:
    """Спросить два имени, выпустить сертификат и поставить обновление страницы."""
    cdn_domain = prompt("CDN-домен (который вводит клиент):").strip()
    origin_host = prompt("Origin-имя (под которым CDN ходит на сервер):").strip()

    outcome = app.provision_vless_cdn(
        state,
        cdn_domain=cdn_domain,
        origin_host=origin_host,
    )
    if not outcome.ok:
        error(outcome.detail)
        prompt("Нажмите Enter")
        return

    success("Установлено")
    for line in outcome.lines():
        info(line)
    info("Настройте на стороне CDN: origin_protocol=https и origin SNI как выше.")
    prompt("Нажмите Enter")


def _set_camera(state: AppState, plugin: BasePlugin, app: ApplicationService) -> None:
    """URL источника камеры для go2rtc (пусто — медиа-эндпоинт пуст). Смена пересобирает сайт."""
    info("go2rtc тянет rtsp/hls/mjpeg сам и отдаёт HLS на /api/media/*. Пусто = медиа нет.")
    info("Примеры: rtsp://…, https://…/index.m3u8. Смена перезапускает go2rtc и пересобирает страницу.")
    url = prompt("URL источника камеры:").strip()
    if app.set_vless_cdn_camera(state, url):
        success("Медиа-эндпоинт пуст, сайт пересобран" if not url else "Источник сохранён, go2rtc перезапущен")
    else:
        error("URL отклонён: неверная форма или ссылка во внутреннюю сеть")
    prompt("Нажмите Enter")


def _menu_vless_cdn(
    state: AppState,
    plugin: BasePlugin,
    app: ApplicationService | None = None,
) -> None:
    """Меню протокола: два имени, профиль клиента и страница-прикрытие."""
    app = _application(app)

    while True:
        state = app.admin.load_state()
        desired = _desired_state(state, PROTOCOL_NAME)
        clear()

        config = desired.config
        details = [
            ("CDN-домен", str(config.get("cdn_domain", "") or "—")),
            ("Origin-имя", str(config.get("origin_host", "") or "—")),
            ("XHTTP путь", str(config.get("xhttp_path", "") or "—")),
            ("Порт ядра", str(config.get("core_port", 0) or "—")),
            ("Сертификат", str(config.get("cert_file", "") or "—")),
            ("Регион origin-сервера", str(config.get("region_city", "") or "—")),
            ("HLS-источник", str(config.get("cam_source_url", "") or "нет")),
        ]
        protocol_status_panel(
            PROTOCOL_NAME,
            installed=bool(config.get("cert_file")),
            enabled=desired.enabled,
            running=bool(desired.enabled and config.get("cert_file")),
            port=as_int(config.get("core_port")),
            details=details,
            display_name=plugin.meta.display_name,
        )

        options: list[tuple[str, str, str]] = []
        if config.get("cert_file"):
            options.append(
                (
                    "1",
                    "⏸️  Выключить" if desired.enabled else "▶️  Включить",
                    "Отключить протокол" if desired.enabled else "Активировать протокол",
                ),
            )
            options.extend(
                [
                    ("5", "📹 Источник камеры", "URL реальной камеры (HLS/RTSP/MJPEG/YouTube) или пусто — синтетика"),
                    ("8", "🔄 Переустановить", "Заменить домены и выпустить сертификат заново"),
                    ("9", "❌ Удалить", "Протокол, страница и таймер"),
                ],
            )
        else:
            options.append(
                ("1", "🔧 Установить", "Спросить CDN-домен и origin-имя"),
            )

        options.append(("0", "↩ Назад", ""))
        choice = menu(
            options,
            protocol_menu_title(PROTOCOL_NAME, plugin.meta.display_name),
        )

        if choice == "0":
            return
        if choice == "1" and not config.get("cert_file"):
            _install(state, plugin, app)
        elif choice == "1":
            if _set_enabled(state, desired, app):
                success("Отключено" if desired.enabled else "Активировано")
            else:
                error("Не удалось изменить состояние протокола")
            prompt("Нажмите Enter")
        elif choice == "5" and config.get("cert_file"):
            _set_camera(state, plugin, app)
        elif choice == "8":
            if confirm("Переустановить протокол с новыми доменами?", default=False):
                _install(state, plugin, app)
        elif choice == "9":
            if not confirm("Удалить протокол, страницу и таймер?", default=False):
                continue
            if app.uninstall_vless_cdn(state):
                success("Удалено")
                prompt("Нажмите Enter")
                return
            error("Ошибка удаления")
            prompt("Нажмите Enter")


__all__ = ["_menu_vless_cdn"]
