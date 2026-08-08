"""Declarative routing to optional specialised plugin controllers."""
from __future__ import annotations

from collections.abc import Callable
from types import ModuleType

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui._menus import extended_protocol_vless, extended_protocols, plugin_settings
from hydra.ui.plugin_managers import (
    antidpi,
    calls,
    dnscrypt,
    fail2ban,
    honeypot,
    ipban,
    telemt,
    warp,
    wdtt,
)


MenuHandler = Callable[[AppState, object, ApplicationService], None]


def _plugin_handler(module: ModuleType, attribute: str) -> MenuHandler:
    def dispatch(
        state: AppState,
        plugin: object,
        app: ApplicationService,
    ) -> None:
        getattr(module, attribute)(state, plugin, app)

    return dispatch


def _application_handler(module: ModuleType, attribute: str) -> MenuHandler:
    def dispatch(
        state: AppState,
        _plugin: object,
        app: ApplicationService,
    ) -> None:
        getattr(module, attribute)(state, app)

    return dispatch


SPECIAL_PLUGIN_MENUS: dict[str, MenuHandler] = {
    "amneziawg": _plugin_handler(
        extended_protocols,
        "_menu_amneziawg",
    ),
    "anytls": _plugin_handler(extended_protocols, "_menu_anytls"),
    "mieru": _plugin_handler(extended_protocols, "_menu_mieru"),
    "trusttunnel": _plugin_handler(extended_protocols, "_menu_trusttunnel"),
    "vless": _plugin_handler(extended_protocol_vless, "_menu_vless"),
    "antidpi": _application_handler(antidpi, "menu_antidpi"),
    "calls": _application_handler(calls, "menu_calls"),
    "dnscrypt": _application_handler(dnscrypt, "menu_dnscrypt"),
    "fail2ban": _application_handler(fail2ban, "menu_fail2ban"),
    "honeypot": _application_handler(honeypot, "menu_honeypot"),
    "ipban": _application_handler(ipban, "menu_ipban"),
    "telemt": _application_handler(telemt, "menu_telemt"),
    "warp": _application_handler(warp, "menu_warp"),
    "wdtt": _application_handler(wdtt, "menu_wdtt"),
}


def open_special_plugin_menu(
    state: AppState,
    plugin,
    app: ApplicationService,
) -> bool:
    """Open a registered specialised menu, if one exists."""
    handler = SPECIAL_PLUGIN_MENUS.get(plugin.meta.name)
    if handler is None:
        return False
    handler(state, plugin, app)
    return True


def plugin_settings_option(
    plugin_name: str,
    desired: PluginState,
) -> tuple[str, str] | None:
    """Return an optional adapter-owned settings menu row."""
    return plugin_settings.settings_option(plugin_name, desired)


def open_plugin_settings(
    state: AppState,
    plugin,
    app: ApplicationService,
) -> bool:
    """Open optional adapter-owned settings without a name branch."""
    return plugin_settings.open_settings(state, plugin, app)


__all__ = ["SPECIAL_PLUGIN_MENUS", "open_plugin_settings", "open_special_plugin_menu", "plugin_settings_option"]
