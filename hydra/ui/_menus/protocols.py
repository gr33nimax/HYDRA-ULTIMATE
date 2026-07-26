"""Generic transport and network-service menu controllers."""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui._menus import plugin_settings
from hydra.ui._menus.protocol_activation import run_lifecycle_action
from hydra.ui._menus.plugin_dispatch import (
    open_plugin_settings,
    open_special_plugin_menu,
    plugin_settings_option,
)
from hydra.ui.protocol_menu import (
    enhancement_options,
    enhancement_summary_lines,
    menu_footer,
    transport_options,
    transport_summary_lines,
)
from hydra.ui.protocol_ui import protocol_menu_title, protocol_status_panel
from hydra.ui.tui import (
    BOLD,
    NC,
    clear,
    confirm,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
)


def _apply_error_text(
    default: str = "Ошибка применения конфигурации",
    app: ApplicationService | None = None,
) -> str:
    if app is None:
        raise ValueError("ApplicationService must be injected")
    return app.apply_error() or default


def _desired_state(state: AppState, name: str) -> PluginState:
    return state.protocols.get(name) or PluginState()


def _render_status(
    state: AppState,
    plugin,
    app: ApplicationService,
) -> None:
    name = plugin.meta.name
    desired = _desired_state(state, name)
    try:
        runtime = app.protocols.status(name, state)
        protocol_status_panel(
            name,
            installed=runtime.installed,
            enabled=runtime.enabled,
            running=runtime.running,
            port=runtime.port,
            error=str(getattr(runtime, "error", "") or ""),
            display_name=getattr(plugin.meta, "display_name", ""),
        )
    except Exception as exc:
        protocol_status_panel(
            name,
            installed=desired.installed,
            enabled=desired.enabled,
            running=False,
            port=desired.port,
            error=str(exc),
            display_name=getattr(plugin.meta, "display_name", ""),
        )


def menu_protocols(state: AppState, app: ApplicationService) -> None:
    while True:
        state = app.admin.load_state()
        clear()
        statuses = app.protocols.statuses(state)
        plugins = app.protocols.list(PluginCategory.TRANSPORT)
        panel(
            "Протоколы · обзор",
            [
                f"  {BOLD}Транспортные протоколы{NC}",
                *transport_summary_lines(plugins, statuses),
            ],
        )
        choice = menu(
            transport_options(plugins, statuses) + menu_footer(),
            "ПРОТОКОЛЫ · УПРАВЛЕНИЕ",
        )
        if choice == "0":
            return
        try:
            plugin = plugins[int(choice) - 1]
        except (ValueError, IndexError):
            continue
        menu_plugin(state, plugin, app)


def menu_network_services(
    state: AppState,
    app: ApplicationService,
) -> None:
    while True:
        state = app.admin.load_state()
        clear()
        statuses = app.protocols.statuses(state)
        plugins = app.protocols.list(PluginCategory.ENHANCEMENT)
        panel(
            "Сетевые службы",
            [
                f"  {BOLD}Сетевые службы (DNS / маршрутизация):{NC}",
                *enhancement_summary_lines(plugins, statuses),
            ],
        )
        choice = menu(
            enhancement_options(plugins, statuses) + menu_footer(),
            "СЕТЕВЫЕ СЛУЖБЫ",
        )
        if choice == "0":
            return
        try:
            plugin = plugins[int(choice) - 1]
        except (ValueError, IndexError):
            continue
        menu_plugin(state, plugin, app)


def _plugin_options(
    plugin,
    desired: PluginState,
) -> list[tuple[str, str, str]]:
    if not desired.installed:
        return [("1", "🔧 Установить", plugin.meta.description)]
    options: list[tuple[str, str, str]] = [
        (
            "1",
            "⏸️  Выключить" if desired.enabled else "▶️  Включить",
            (
                "Отключить протокол"
                if desired.enabled
                else "Активировать протокол"
            ),
        ),
    ]
    if (
        plugin.meta.category == PluginCategory.TRANSPORT
        and desired.enabled
    ):
        options.append(
            (
                "2",
                "👥 Клиенты",
                "Подключённые клиенты и трафик",
            ),
        )
    if settings := plugin_settings_option(
        plugin.meta.name,
        desired,
    ):
        options.append(("3", *settings))
    options.extend(
        [
            ("8", "🔄 Переустановить", "Переустановка протокола"),
            ("9", "❌ Удалить", "Полное удаление"),
        ],
    )
    return options


def _toggle_or_install(
    state: AppState,
    plugin,
    desired: PluginState,
    app: ApplicationService,
) -> None:
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


def _reinstall_or_remove(
    choice: str,
    state: AppState,
    plugin,
    app: ApplicationService,
) -> bool:
    name = plugin.meta.name
    if choice == "8":
        if confirm("Переустановить?", default=False):
            if app.protocols.reinstall(state, name):
                success("Переустановлено!")
            else:
                error("Ошибка переустановки")
            prompt("Нажмите Enter")
        return False
    if choice != "9":
        return False
    if not confirm(f"Удалить {name}?", default=False):
        return False
    if app.protocols.uninstall(state, name):
        success("Удалено")
    else:
        error("Ошибка удаления")
    prompt("Нажмите Enter")
    return True


def menu_plugin(
    state: AppState,
    plugin,
    app: ApplicationService,
) -> None:
    """Open a specialised controller or the contract-driven generic menu."""
    if open_special_plugin_menu(state, plugin, app):
        return
    name = plugin.meta.name
    while True:
        state = app.admin.load_state()
        desired = _desired_state(state, name)
        clear()
        _render_status(state, plugin, app)
        options = [
            *_plugin_options(plugin, desired),
            ("0", "↩ Назад", ""),
        ]
        choice = menu(
            options,
            protocol_menu_title(
                name,
                getattr(plugin.meta, "display_name", ""),
            ),
        )
        if choice == "0":
            return
        if choice == "1":
            _toggle_or_install(state, plugin, desired, app)
        elif (
            choice == "2"
            and desired.installed
            and desired.enabled
        ):
            _show_plugin_clients(state, plugin, app)
        elif choice == "3":
            open_plugin_settings(state, plugin, app)
        elif choice in {"8", "9"} and desired.installed:
            if _reinstall_or_remove(choice, state, plugin, app):
                return


def _menu_hysteria2_settings(
    state: AppState,
    plugin,
    app: ApplicationService,
) -> None:
    """Compatibility facade for the specialised settings adapter."""
    plugin_settings.menu_hysteria2_settings(state, plugin, app)


def _menu_snell_settings(
    state: AppState,
    plugin,
    app: ApplicationService,
) -> None:
    """Compatibility facade for the specialised settings adapter."""
    plugin_settings.menu_snell_settings(state, plugin, app)


def _show_plugin_clients(
    state: AppState,
    plugin,
    app: ApplicationService,
) -> None:
    from hydra.ui._menus.extended_protocols import (
        _show_plugin_clients as show,
    )

    show(state, plugin, app)


__all__ = [
    "_menu_hysteria2_settings",
    "_menu_snell_settings",
    "_show_plugin_clients",
    "menu_network_services",
    "menu_plugin",
    "menu_protocols",
]
