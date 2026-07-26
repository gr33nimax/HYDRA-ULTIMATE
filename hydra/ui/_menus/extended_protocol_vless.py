"""Dedicated TUI controller for the VLESS/XHTTP transport."""
from __future__ import annotations

from hydra.core.state_models import AppState
from hydra.plugins.vless_xhttp import presets, tuning
from hydra.services.application import ApplicationService
from hydra.ui._menus.extended_protocol_common import (
    _application,
    _desired_state,
    _show_plugin_clients,
)
from hydra.ui._menus.decoy_theme import choose_theme
from hydra.ui._menus.protocol_activation import run_lifecycle_action
from hydra.ui._menus.vless_xhttp_profiles import (
    open_menu as open_profiles_menu,
)
from hydra.ui._menus.vless_xhttp_settings import (
    open_menu as open_settings_menu,
)
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


def _menu_vless(
    state: AppState,
    plugin: object,
    app: ApplicationService | None = None,
) -> None:
    """Render VLESS with the same first-class workflow as AnyTLS."""
    app = _application(app)

    while True:
        state = app.admin.load_state()
        desired = _desired_state(state, plugin.meta.name)
        clear()

        preset_name = "custom"
        preset_display = presets.preset_label(preset_name)
        try:
            runtime = app.protocols.status(plugin.meta.name, state)
            tuning_info = app.plugin_query(
                "vless",
                "get_tuning",
                state=state,
            )
            if not isinstance(tuning_info, dict):
                raise ValueError("VLESS XHTTP tuning query returned no data")
            preset_name = str(tuning_info.get("preset", "custom"))
            preset_display = presets.preset_label(preset_name)
            details = [
                (
                    "Домен",
                    str(desired.config.get("domain", "")) or "не настроен",
                ),
                ("XHTTP path", str(tuning_info.get("path", "/xhttp"))),
                ("Режим XHTTP", str(tuning_info.get("mode", "stream-up"))),
                (
                    "Профиль XHTTP",
                    f"{BOLD}{CYAN}{preset_display}{NC}",
                ),
                ("Параметры", tuning.summary(desired.config)),
            ]
            protocol_status_panel(
                plugin.meta.name,
                installed=runtime.installed,
                enabled=runtime.enabled,
                running=runtime.running,
                port=runtime.port,
                details=details,
                display_name=plugin.meta.display_name,
            )
        except Exception as exc:
            protocol_status_panel(
                plugin.meta.name,
                installed=desired.installed,
                enabled=desired.enabled,
                running=False,
                port=desired.port,
                error=str(exc) or exc.__class__.__name__,
                display_name=plugin.meta.display_name,
            )

        options: list[tuple[str, str, str]] = []
        if not desired.installed:
            options.append(
                ("1", "🔧 Установить", plugin.meta.description),
            )
        else:
            options.append(
                (
                    "1",
                    "⏸️  Выключить"
                    if desired.enabled
                    else "▶️  Включить",
                    "Отключить протокол"
                    if desired.enabled
                    else "Активировать протокол",
                ),
            )
            if desired.enabled:
                options.append(
                    (
                        "2",
                        "👥 Клиенты",
                        "Подключённые клиенты и трафик",
                    ),
                )
            options.extend(
                [
                    (
                        "3",
                        "🌐 Профиль транспорта",
                        f"Текущий профиль: {preset_display}",
                    ),
                    (
                        "4",
                        "⚙️  Настройки XHTTP",
                        "Домен, путь, режим и тонкая настройка",
                    ),
                    (
                        "8",
                        "🔄 Переустановить",
                        "Переустановка протокола",
                    ),
                    ("9", "❌ Удалить", "Полное удаление"),
                ],
            )
        options.append(("0", "↩ Назад", ""))

        choice = menu(
            options,
            protocol_menu_title(
                plugin.meta.name,
                plugin.meta.display_name,
            ),
        )
        if choice == "0":
            return
        if choice == "1":
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
                choose_decoy=choose_theme,
            )
        elif choice == "2" and desired.installed and desired.enabled:
            _show_plugin_clients(state, plugin, app)
        elif choice == "3" and desired.installed:
            open_profiles_menu(state, app)
        elif choice == "4" and desired.installed:
            open_settings_menu(state, plugin, app)
        elif choice == "8" and desired.installed:
            if confirm("Переустановить VLESS + XHTTP?", default=False):
                if app.protocols.reinstall(state, plugin.meta.name):
                    success("Переустановлено!")
                else:
                    error("Ошибка переустановки")
                prompt("Нажмите Enter")
        elif choice == "9" and desired.installed:
            if not confirm(
                "Полностью удалить VLESS + XHTTP?",
                default=False,
            ):
                continue
            if app.protocols.uninstall(state, plugin.meta.name):
                success("Удалено")
                prompt("Нажмите Enter")
                return
            error("Ошибка удаления")
            prompt("Нажмите Enter")


__all__ = ["_menu_vless"]
