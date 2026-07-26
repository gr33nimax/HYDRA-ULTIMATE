"""Stable TeleMT UI facade.

The implementation is split by responsibility while legacy imports and
monkeypatch seams continue to resolve through this module.
"""
from __future__ import annotations

import re
import sys
from dataclasses import asdict as asdict
from typing import Optional

from hydra.core.state_models import AppState as AppState
from hydra.core.state_models import PluginState as PluginState
from hydra.plugins.telemt.plugin import BIN_PATH as BIN_PATH
from hydra.plugins.telemt.plugin import CONFIG_FILE as CONFIG_FILE
from hydra.plugins.telemt.plugin import DEFAULT_PORT as DEFAULT_PORT
from hydra.plugins.telemt.plugin import SERVICE_NAME as SERVICE_NAME
from hydra.plugins.telemt.tg_nets import (
    tg_nets_status_line as tg_nets_status_line,
)
from hydra.plugins.telemt.tg_nets import (
    update_tg_nets_interactive as update_tg_nets_interactive,
)
from hydra.services.application import (
    ApplicationService as ApplicationService,
)
from hydra.ui.plugin_managers._facade_bridge import bind_facade
from hydra.ui.protocol_ui import protocol_menu_title as protocol_menu_title
from hydra.ui.protocol_ui import (
    protocol_status_panel as protocol_status_panel,
)
from hydra.ui.tui import BOLD as BOLD
from hydra.ui.tui import CYAN as CYAN
from hydra.ui.tui import DIM as DIM
from hydra.ui.tui import GREEN as GREEN
from hydra.ui.tui import NC as NC
from hydra.ui.tui import RED as RED
from hydra.ui.tui import YELLOW as YELLOW
from hydra.ui.tui import clear as clear
from hydra.ui.tui import confirm as confirm
from hydra.ui.tui import error as error
from hydra.ui.tui import info as info
from hydra.ui.tui import menu as menu
from hydra.ui.tui import panel as panel
from hydra.ui.tui import prompt as prompt
from hydra.ui.tui import success as success
from hydra.ui.tui import warn as warn


def _implementation_scope():
    return bind_facade(sys.modules[__name__])


class _Cancelled(Exception):
    pass


def _get_fallback_module():
    try:
        from hydra.plugins.telemt import telemt_fallback as fallback

        return fallback
    except ImportError:
        return None


def _get_syn_limiter_module():
    try:
        from hydra.plugins.telemt import telemt_syn_limiter as syn_limiter

        return syn_limiter
    except ImportError:
        return None


def _get_ios_fix_module():
    try:
        from hydra.plugins.telemt import telemt_ios_fix as ios_fix

        return ios_fix
    except ImportError:
        return None


def _get_mss_module():
    try:
        from hydra.plugins.telemt import telemt_mss_selector as selector

        return selector
    except ImportError:
        return None


def _get_self_route_module():
    try:
        from hydra.plugins.telemt import telemt_self_route as self_route

        return self_route
    except ImportError:
        return None


def _get_stats_module():
    try:
        from hydra.plugins.telemt import mtproto_stats as stats

        return stats
    except ImportError:
        return None


def _run(
    app: ApplicationService,
    cmd: list,
    capture: bool = False,
):
    options = {}
    if capture:
        options.update(
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    else:
        options.update(
            stdout=app.diagnostics.devnull,
            stderr=app.diagnostics.devnull,
        )
    return app.admin.run_command(cmd, **options)


def _get_installed_version(
    app: ApplicationService,
) -> Optional[str]:
    if not app.diagnostics.path_exists(str(BIN_PATH)):
        return None
    result = _run(app, [str(BIN_PATH), "--version"], capture=True)
    match = re.search(
        r"(\d+\.\d+[\.\d]*)",
        result.stdout + result.stderr,
    )
    return match.group(1) if match else "unknown"


def _pause() -> None:
    print(
        f"\n  {DIM}Нажмите Enter для продолжения...{NC}",
        end="",
        flush=True,
    )
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        print()


def _ask(
    label: str,
    default: str = "",
    required: bool = False,
) -> str:
    try:
        value = prompt(label, default=default).strip()
        if required and not value:
            raise _Cancelled()
        return value
    except KeyboardInterrupt:
        print()
        raise _Cancelled()


def _make_tls_secret(base_secret: str, domain: str) -> str:
    return f"ee{base_secret}{domain.encode().hex()}"


def _set_telemt_enabled(
    state: AppState,
    enabled: bool,
    app: ApplicationService,
) -> bool:
    """Change desired TeleMT state through the transactional lifecycle API."""
    protocol = state.protocols.get("telemt")
    if protocol is not None and protocol.enabled is enabled:
        return True
    return (
        app.protocols.enable(state, "telemt")
        if enabled
        else app.protocols.disable(state, "telemt")
    )


def menu_telemt(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._telemt_menu import run

    with _implementation_scope():
        run(state, app)


def _run_install(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._telemt_operations import run_install

    with _implementation_scope():
        run_install(state, app)


def _view_links(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._telemt_operations import view_links

    with _implementation_scope():
        view_links(state, app)


def _run_update(app: ApplicationService) -> None:
    from hydra.ui.plugin_managers._telemt_operations import run_update

    with _implementation_scope():
        run_update(app)


def _view_logs(app: ApplicationService) -> None:
    from hydra.ui.plugin_managers._telemt_operations import view_logs

    with _implementation_scope():
        view_logs(app)


def _menu_singbox_integration(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._telemt_features import (
        menu_singbox_integration,
    )

    with _implementation_scope():
        menu_singbox_integration(state, app)


def _menu_fallback(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._telemt_features import menu_fallback

    with _implementation_scope():
        menu_fallback(state, app)


def _menu_syn_limiter() -> None:
    from hydra.ui.plugin_managers._telemt_features import menu_syn_limiter

    with _implementation_scope():
        menu_syn_limiter()


def _menu_ios_fix() -> None:
    from hydra.ui.plugin_managers._telemt_features import menu_ios_fix

    with _implementation_scope():
        menu_ios_fix()


def _menu_update_tg_nets(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._telemt_features import (
        menu_update_tg_nets,
    )

    with _implementation_scope():
        menu_update_tg_nets(state, app)


def _run_uninstall(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._telemt_operations import run_uninstall

    with _implementation_scope():
        run_uninstall(state, app)


def _apply_optimizations(app: ApplicationService) -> None:
    from hydra.ui.plugin_managers._telemt_operations import (
        apply_optimizations,
    )

    with _implementation_scope():
        apply_optimizations(app)
