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
from hydra.ui._menus.protocol_activation import run_lifecycle_action


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
            ("Регион", str(config.get("region_city", "") or "—")),
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
            run_lifecycle_action(
                state,
                plugin,
                desired,
                app,
                ask=prompt,
                report_error=error,
                report_info=info,
                report_success=success,
                pause=prompt,
            )
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
