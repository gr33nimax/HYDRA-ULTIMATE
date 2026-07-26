"""Security-plugin menu controller."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from hydra.core.state_models import AppState
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.ui._menus.protocols import menu_plugin
from hydra.ui.tui import (
    BOLD,
    DIM,
    GREEN,
    NC,
    RED,
    YELLOW,
    clear,
    menu,
    panel,
    prompt,
    success,
    warn,
)


@dataclass(frozen=True)
class SecurityMenuDependencies:
    clear: Callable[[], None]
    panel: Callable[..., None]
    menu: Callable[..., str]
    success: Callable[[str], None]
    warn: Callable[[str], None]
    prompt: Callable[[str], str]
    open_plugin_menu: Callable[[AppState, object, ApplicationService], None]
    green: str
    yellow: str
    red: str
    dim: str
    bold: str
    reset: str


def _security_plugins(app: ApplicationService) -> list:
    return list(app.protocols.list(PluginCategory.SECURITY))


def run_security_menu(
    state: AppState,
    app: ApplicationService,
    deps: SecurityMenuDependencies,
) -> None:
    while True:
        state = app.admin.load_state()
        deps.clear()
        statuses = app.protocols.statuses(state)
        plugins = _security_plugins(app)
        lines: list[str] = []
        for plugin in plugins:
            status = statuses.get(plugin.meta.name, {})
            marker = (
                f"{deps.green}●{deps.reset}"
                if status.get("running")
                else f"{deps.yellow}●{deps.reset}"
                if status.get("installed")
                else f"{deps.dim}●{deps.reset}"
            )
            enabled = "вкл" if status.get("enabled") else "выкл"
            lines.append(
                f"  {marker} {plugin.meta.name:<14} "
                f"{deps.dim}{enabled:>4}{deps.reset}",
            )
        deps.panel(
            "Безопасность",
            [f"  {deps.bold}Плагины безопасности:{deps.reset}", *lines],
        )

        options: list[tuple[str, str, str]] = []
        for index, plugin in enumerate(plugins, 1):
            status = statuses.get(plugin.meta.name, {})
            marker = (
                f"{deps.green}✓{deps.reset}"
                if status.get("running")
                else f"{deps.yellow}⚠{deps.reset}"
                if status.get("installed")
                else f"{deps.red}✗{deps.reset}"
            )
            options.append(
                (
                    str(index),
                    f"{marker} {plugin.meta.name}",
                    plugin.meta.description,
                ),
            )
        options.extend(
            [
                ("-", "", ""),
                (
                    "A",
                    "✅ Включить всё",
                    "Включить все зарегистрированные плагины безопасности",
                ),
                ("B", "❌ Выключить всё", ""),
                ("0", "↩ Назад", ""),
            ],
        )
        choice = deps.menu(options, "БЕЗОПАСНОСТЬ")
        if choice == "0":
            return
        if choice in {"A", "B"}:
            target_enabled = choice == "A"
            failures: list[str] = []
            for plugin in plugins:
                try:
                    toggle_security_plugin(
                        state,
                        plugin.meta.name,
                        app,
                        force_enable=target_enabled,
                    )
                except Exception as exc:
                    failures.append(f"{plugin.meta.name}: {exc}")
            for detail in failures:
                deps.warn(detail)
            if failures:
                message = (
                    "Часть служб безопасности включена (см. ошибки выше)"
                    if target_enabled
                    else "Часть служб безопасности не удалось выключить"
                )
                (deps.success if target_enabled else deps.warn)(message)
            else:
                deps.success(
                    "Все службы безопасности включены"
                    if target_enabled
                    else "Все службы безопасности выключены",
                )
            deps.prompt("Нажмите Enter")
            continue
        try:
            plugin = plugins[int(choice) - 1]
        except (ValueError, IndexError):
            continue
        deps.open_plugin_menu(state, plugin, app)


def toggle_security_plugin(
    state: AppState,
    name: str,
    app: ApplicationService,
    *,
    force_enable: bool | None = None,
) -> None:
    """Toggle a security plugin through the application boundary."""
    status = app.protocols.status(name)
    target_enable = force_enable if force_enable is not None else not status.enabled
    if target_enable:
        if not status.installed and not app.protocols.install(state, name):
            raise RuntimeError(f"Не удалось установить плагин {name}")
        if not app.protocols.enable(state, name):
            raise RuntimeError(f"Не удалось включить плагин {name}")
    elif not app.protocols.disable(state, name):
        raise RuntimeError(f"Не удалось выключить плагин {name}")


def menu_security(state: AppState, app: ApplicationService) -> None:
    run_security_menu(
        state,
        app,
        SecurityMenuDependencies(
            clear=clear,
            panel=panel,
            menu=menu,
            success=success,
            warn=warn,
            prompt=prompt,
            open_plugin_menu=menu_plugin,
            green=GREEN,
            yellow=YELLOW,
            red=RED,
            dim=DIM,
            bold=BOLD,
            reset=NC,
        ),
    )


def _toggle_security_plugin(
    state: AppState,
    name: str,
    force_enable: bool | None = None,
    app: ApplicationService | None = None,
) -> None:
    if app is None:
        raise ValueError("ApplicationService must be injected")
    toggle_security_plugin(
        state,
        name,
        app,
        force_enable=force_enable,
    )


__all__ = [
    "SecurityMenuDependencies",
    "_toggle_security_plugin",
    "menu_security",
    "run_security_menu",
    "toggle_security_plugin",
]
