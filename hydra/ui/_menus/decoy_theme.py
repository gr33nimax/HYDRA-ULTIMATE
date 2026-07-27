"""Shared TUI adapter for choosing a protocol's decoy site."""
from __future__ import annotations

from hydra.core.decoy_sites.registry import THEMES
from hydra.core.state_models import AppState, PluginState
from hydra.plugins.decoy_support import (
    DECOY_THEME_KEY,
    supports_decoy_theme,
)
from hydra.services.application import ApplicationService
from hydra.ui.tui import error, menu, prompt, success


def current_theme(plugin: object, desired: PluginState) -> str:
    """Return the theme the protocol serves today."""
    configured = str(desired.config.get(DECOY_THEME_KEY, "")).strip().lower()
    if configured in THEMES:
        return configured
    return str(getattr(plugin, "decoy_default_theme", "landing"))


def theme_label(name: str) -> str:
    """Return the operator-facing label of a theme name."""
    theme = THEMES.get(name)
    return theme.label if theme else name


def decoy_option(
    plugin: object,
    desired: PluginState,
) -> tuple[str, str] | None:
    """Return an optional menu row for protocols with a decoy site."""
    if not supports_decoy_theme(plugin):
        return None
    return "🎭 Сайт-заглушка", theme_label(current_theme(plugin, desired))


def choose_theme(current: str) -> str:
    """Ask the operator to pick one theme; empty means keep the current one."""
    names = tuple(THEMES)
    options = [
        (
            str(index),
            THEMES[name].label + (" ·" if name == current else ""),
            THEMES[name].description,
        )
        for index, name in enumerate(names, start=1)
    ]
    selected = menu(
        [*options, ("0", "Отмена", "")],
        "САЙТ-ЗАГЛУШКА НА ДОМЕНЕ",
    )
    if not selected.isdigit() or selected == "0":
        return ""
    index = int(selected) - 1
    return names[index] if 0 <= index < len(names) else ""


def open_decoy_menu(
    state: AppState,
    plugin: object,
    app: ApplicationService,
) -> None:
    """Change the decoy theme through the plugin's own command."""
    name = plugin.meta.name
    desired = state.protocols.get(name) or PluginState()
    selected = choose_theme(current_theme(plugin, desired))
    if not selected:
        return
    try:
        if app.plugin_command(state, name, "set_decoy_theme", theme=selected):
            success(f"Заглушка обновлена: {theme_label(selected)}")
        else:
            error("Не удалось применить тему заглушки")
    except (TypeError, ValueError) as exc:
        error(str(exc))
    prompt("Нажмите Enter")


__all__ = [
    "choose_theme",
    "current_theme",
    "decoy_option",
    "open_decoy_menu",
    "theme_label",
]
