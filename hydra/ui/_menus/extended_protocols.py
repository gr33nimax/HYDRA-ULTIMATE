"""Compatibility facade for the extended protocol menu controllers.

Protocol-specific behavior lives in sibling modules.  This facade preserves
the historical import and monkeypatch surface used by :mod:`hydra.ui.menus`.
"""
from __future__ import annotations

from functools import wraps
from types import ModuleType
from typing import Callable

from hydra.ui._menus import (
    extended_protocol_anytls,
    extended_protocol_awg,
    extended_protocol_awg_profiles,
    extended_protocol_awg_wizard,
    extended_protocol_common,
    extended_protocol_mieru,
    extended_protocol_trusttunnel,
)
from hydra.ui._menus.extended_protocol_common import (
    _application,
    _apply_error_text,
    _desired_state,
)
from hydra.ui.protocol_ui import protocol_menu_title, protocol_status_panel
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    RED,
    WHITE,
    YELLOW,
    _bytes_auto,
    clear,
    confirm,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
)


_TARGETS: dict[str, ModuleType] = {
    "_show_plugin_traffic": extended_protocol_common,
    # Historical name kept for adapters and tests that still import it.
    "_show_plugin_clients": extended_protocol_common,
    "_menu_amneziawg": extended_protocol_awg,
    "_manage_awg_profiles": extended_protocol_awg_profiles,
    "_rotate_awg_obfuscation": extended_protocol_awg_profiles,
    "_tune_awg_hardware": extended_protocol_awg,
    "_menu_mieru": extended_protocol_mieru,
    "_menu_mieru_obfuscation": extended_protocol_mieru,
    "_menu_anytls": extended_protocol_anytls,
    "_menu_anytls_obfuscation": extended_protocol_anytls,
    "_menu_trusttunnel": extended_protocol_trusttunnel,
    "_awg_generate_wizard_menu": extended_protocol_awg_profiles,
    "_awg_generate_wizard": extended_protocol_awg_wizard,
}
_MODULES = frozenset(_TARGETS.values())
_DEFAULTS: dict[ModuleType, dict[str, object]] = {}
_SYNC_NAMES = (
    "_application",
    "_apply_error_text",
    "_desired_state",
    *tuple(_TARGETS),
    "protocol_menu_title",
    "protocol_status_panel",
    "BOLD",
    "CYAN",
    "DIM",
    "GREEN",
    "NC",
    "PANEL_W",
    "RED",
    "WHITE",
    "YELLOW",
    "_bytes_auto",
    "clear",
    "confirm",
    "error",
    "info",
    "menu",
    "panel",
    "prompt",
    "success",
)


def _bind(module: ModuleType) -> ModuleType:
    """Copy facade patches into one controller without replacing its target."""
    defaults = _DEFAULTS.setdefault(module, {})
    namespace = globals()
    for name in _SYNC_NAMES:
        if name not in namespace or not hasattr(module, name):
            continue
        defaults.setdefault(name, getattr(module, name))
        candidate = namespace[name]
        if (
            getattr(candidate, "_extended_protocol_forwarder", False)
            and getattr(candidate, "_extended_protocol_module", None) is module
        ):
            candidate = defaults[name]
        setattr(module, name, candidate)
    return module


def _make_forwarder(name: str, module: ModuleType) -> Callable:
    target = getattr(module, name)

    @wraps(target)
    def forward(*args, **kwargs):
        return getattr(_bind(module), name)(*args, **kwargs)

    # hydra.ui.menus uses ``__module__`` to identify and restore a facade's
    # original forwarder while propagating monkeypatches.
    forward.__module__ = __name__
    forward._extended_protocol_forwarder = True
    forward._extended_protocol_module = module
    return forward


for _name, _module in _TARGETS.items():
    globals()[_name] = _make_forwarder(_name, _module)
