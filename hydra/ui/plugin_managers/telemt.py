"""Stable Telemt UI facade."""

from __future__ import annotations

import re
import sys
from typing import Optional

from hydra.core.state_models import AppState as AppState
from hydra.core.state_models import PluginState as PluginState
from hydra.plugins.telemt.plugin import BIN_PATH as BIN_PATH
from hydra.plugins.telemt.plugin import CONFIG_FILE as CONFIG_FILE
from hydra.plugins.telemt.plugin import DEFAULT_PORT as DEFAULT_PORT
from hydra.plugins.telemt.plugin import SERVICE_NAME as SERVICE_NAME
from hydra.services.application import ApplicationService as ApplicationService
from hydra.ui.plugin_managers._facade_bridge import bind_facade
from hydra.ui.protocol_ui import protocol_menu_title as protocol_menu_title
from hydra.ui.protocol_ui import protocol_status_panel as protocol_status_panel
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


def _run(app: ApplicationService, cmd: list, capture: bool = False):
    if capture:
        return app.admin.run_command(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    return app.admin.run_command(
        cmd,
        stdout=app.diagnostics.devnull,
        stderr=app.diagnostics.devnull,
    )


def _get_installed_version(app: ApplicationService) -> Optional[str]:
    if not app.diagnostics.path_exists(str(BIN_PATH)):
        return None
    result = _run(app, [str(BIN_PATH), "--version"], capture=True)
    match = re.search(r"(\d+\.\d+[\.\d]*)", result.stdout + result.stderr)
    return match.group(1) if match else "unknown"


def _pause() -> None:
    print(f"\n  {DIM}Нажмите Enter для продолжения...{NC}", end="", flush=True)
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        print()


def _ask(label: str, default: str = "", required: bool = False) -> str:
    try:
        value = prompt(label, default=default).strip()
        if required and not value:
            raise _Cancelled()
        return value
    except KeyboardInterrupt:
        print()
        raise _Cancelled()


def _set_telemt_enabled(state: AppState, enabled: bool, app: ApplicationService) -> bool:
    protocol = state.protocols.get("telemt")
    if protocol is not None and protocol.enabled is enabled:
        return True
    return app.protocols.enable(state, "telemt") if enabled else app.protocols.disable(state, "telemt")


def menu_telemt(state: AppState, app: ApplicationService) -> None:
    from hydra.ui.plugin_managers._telemt_menu import run

    with _implementation_scope():
        run(state, app)


def _run_install(state: AppState, app: ApplicationService) -> None:
    from hydra.ui.plugin_managers._telemt_operations import run_install

    with _implementation_scope():
        run_install(state, app)


def _run_advanced(state: AppState, app: ApplicationService) -> None:
    from hydra.ui.plugin_managers._telemt_operations import run_advanced

    with _implementation_scope():
        run_advanced(state, app)


def _view_links(state: AppState, app: ApplicationService) -> None:
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


def _run_uninstall(state: AppState, app: ApplicationService) -> None:
    from hydra.ui.plugin_managers._telemt_operations import run_uninstall

    with _implementation_scope():
        run_uninstall(state, app)
