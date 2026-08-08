"""Public compatibility facade for HYDRA's modular TUI controllers.

The implementation lives in :mod:`hydra.ui._menus`.  This module keeps the
historical import and monkeypatch surface while owning only adapter composition.
"""
from __future__ import annotations

from functools import wraps
from types import ModuleType
from typing import Callable

from hydra.core.state_models import AppState, User
from hydra.bootstrap import production_application
from hydra.services.application import ApplicationService
from hydra.services.subscriptions.generator import (
    get_subscription_urls,
    get_user_access_status,
    get_user_entitlement_status,
)
from hydra.ui import log_viewer, system_monitor
from hydra.ui._menus.facade_contract import BINDER_SPECS, FORWARD_GROUPS
from hydra.ui.protocol_menu import (
    enhancement_options,
    enhancement_summary_lines,
    menu_footer,
    render_protocol_status,
    transport_options,
    transport_summary_lines,
)
from hydra.ui.protocol_ui import (
    protocol_label,
    protocol_menu_title,
    protocol_status_panel,
    status_badge,
)
from hydra.ui.tui import (
    BANNER,
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    RED,
    WHITE,
    YELLOW,
    _bar,
    _bytes_auto,
    _ok,
    clear,
    confirm,
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


_CONTROLLER_DEFAULTS: dict[ModuleType, dict[str, object]] = {}


def _application(app: ApplicationService | None = None) -> ApplicationService:
    """Validate explicit dependencies for every controller below the root."""
    if app is None:
        raise ValueError("ApplicationService must be injected by the UI adapter")
    return app


def _apply_error_text(
    default: str = "Ошибка применения конфигурации",
    app: ApplicationService | None = None,
) -> str:
    return _application(app).apply_error() or default


def _bind_controller(controller: ModuleType, names: tuple[str, ...]):
    defaults = _CONTROLLER_DEFAULTS.setdefault(controller, {})
    facade = globals()
    for name in names:
        if name not in facade or not hasattr(controller, name):
            continue
        defaults.setdefault(name, getattr(controller, name))
        candidate = facade[name]
        if (
            getattr(candidate, "_facade_forwarder", False)
            and getattr(candidate, "_facade_module", "") == controller.__name__
        ):
            candidate = defaults[name]
        setattr(controller, name, candidate)
    return controller


def _make_binder(
    controller: ModuleType,
    names: tuple[str, ...],
    companions: tuple[ModuleType, ...],
) -> Callable[[], object]:
    def bind():
        for companion in companions:
            _bind_controller(companion, names)
        return _bind_controller(controller, names)

    return bind


for _binder_name, (_controller, _sync_names, _companions) in BINDER_SPECS.items():
    globals()[_binder_name] = _make_binder(
        _controller,
        _sync_names,
        _companions,
    )


def _make_forwarder(binder_name: str, function_name: str) -> Callable:
    binder = globals()[binder_name]
    controller = binder()
    target = getattr(controller, function_name)

    @wraps(target)
    def forward(*args, **kwargs):
        return getattr(binder(), function_name)(*args, **kwargs)

    forward._facade_forwarder = True
    forward._facade_module = controller.__name__
    return forward


for _binder_name, _exports in FORWARD_GROUPS.items():
    for _export in _exports:
        globals()[_export] = _make_forwarder(_binder_name, _export)


def _open_diagnostics(state: AppState, app: ApplicationService) -> None:
    from hydra.ui.diagnostics import menu_diagnostics

    menu_diagnostics(state, app)


def main_menu(
    state: AppState,
    app: ApplicationService | None = None,
) -> None:
    """Compose production once, then delegate to the dependency-clean root."""
    application = app if app is not None else production_application()
    from hydra.ui._menus.headless_creator import menu_headless_creator
    from hydra.ui._menus.root import RootMenuDependencies

    globals()["_root_menus"]().run_main_menu(
        state,
        application,
        RootMenuDependencies(
            core=globals()["menu_core"],
            protocols=globals()["menu_protocols"],
            users=globals()["menu_users"],
            telegram=globals()["menu_telegram"],
            monitoring=globals()["menu_monitoring"],
            security=globals()["menu_security"],
            network_services=globals()["menu_network_services"],
            diagnostics=_open_diagnostics,
            headless_creator=menu_headless_creator,
        ),
    )


__all__ = sorted(
    {
        "main_menu",
        *(
            export
            for exports in FORWARD_GROUPS.values()
            for export in exports
        ),
    },
)
