"""Compatibility facade for modular monitoring menu controllers."""
from __future__ import annotations

from functools import wraps
from types import ModuleType
from typing import Callable

from hydra.ui import log_viewer, system_monitor
from hydra.ui._menus import (
    monitoring_connections,
    monitoring_logs,
    monitoring_overview,
    monitoring_realtime,
    monitoring_services,
    monitoring_support,
    monitoring_traffic,
)
from hydra.ui._menus.users import _select_user, _show_user_detail
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    RED,
    YELLOW,
    _bytes_auto,
    clear,
    error,
    info,
    kv,
    menu,
    panel,
    prompt,
    success,
    title,
    warn,
)


_CONTROLLERS: tuple[ModuleType, ...] = (
    monitoring_support,
    monitoring_overview,
    monitoring_traffic,
    monitoring_connections,
    monitoring_realtime,
    monitoring_logs,
    monitoring_services,
)

_IMPLEMENTATIONS: dict[str, ModuleType] = {
    "_application": monitoring_support,
    "_apply_error_text": monitoring_support,
    "_unit_active": monitoring_support,
    "_unit_known": monitoring_support,
    "_is_enter_pressed": monitoring_support,
    "menu_monitoring": monitoring_overview,
    "_menu_service_settings": monitoring_overview,
    "_show_traffic_combined": monitoring_traffic,
    "_show_connections": monitoring_connections,
    "_show_status": monitoring_realtime,
    "_read_proc_cpu": monitoring_realtime,
    "_read_proc_mem": monitoring_realtime,
    "_read_proc_net": monitoring_realtime,
    "_show_realtime_sys_monitor": monitoring_realtime,
    "_menu_logs": monitoring_logs,
    "_log_source_status": monitoring_logs,
    "_read_log_source": monitoring_logs,
    "_show_log_source": monitoring_logs,
    "_show_log_file": monitoring_logs,
    "_watch_log_file": monitoring_logs,
    "_watch_journal": monitoring_logs,
    "_sync_agent_log_snapshot": monitoring_logs,
    "_menu_sync_agent": monitoring_services,
    "_menu_clash_api": monitoring_services,
}

_PATCHABLE_NAMES = (
    "BOLD", "CYAN", "DIM", "GREEN", "NC", "PANEL_W", "RED", "YELLOW",
    *_IMPLEMENTATIONS,
    "_bytes_auto", "_select_user", "_show_user_detail", "clear", "error",
    "info", "kv", "log_viewer", "menu", "panel", "prompt", "success",
    "system_monitor", "title", "warn",
)

_CONTROLLER_DEFAULTS = {
    controller: {
        name: getattr(controller, name)
        for name in _PATCHABLE_NAMES
        if hasattr(controller, name)
    }
    for controller in _CONTROLLERS
}
_FACADE_DEFAULTS: dict[str, object] = {}


def _sync_controller_dependencies() -> None:
    facade = globals()
    for controller in _CONTROLLERS:
        defaults = _CONTROLLER_DEFAULTS[controller]
        for name, controller_default in defaults.items():
            candidate = facade[name]
            if candidate is _FACADE_DEFAULTS.get(name):
                candidate = controller_default
            setattr(controller, name, candidate)


def _make_forwarder(
    controller: ModuleType,
    name: str,
) -> Callable:
    target = getattr(controller, name)

    @wraps(target)
    def forward(*args, **kwargs):
        _sync_controller_dependencies()
        return getattr(controller, name)(*args, **kwargs)

    return forward


for _name, _controller in _IMPLEMENTATIONS.items():
    globals()[_name] = _make_forwarder(_controller, _name)

_FACADE_DEFAULTS.update({
    name: globals()[name]
    for name in _PATCHABLE_NAMES
    if name in globals()
})
