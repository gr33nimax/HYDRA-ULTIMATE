"""Stable qWDTT UI facade.

The implementation lives in focused modules while legacy imports and test
patches keep resolving through this module.
"""
from __future__ import annotations

import sys

from hydra.core.errors import HostOperationError
from hydra.core.state_models import AppState as AppState
from hydra.core.state_models import get_protocol as get_protocol
from hydra.plugins.wdtt.plugin import DEFAULT_DTLS_PORT as DEFAULT_DTLS_PORT
from hydra.plugins.wdtt.plugin import DEFAULT_WG_PORT as DEFAULT_WG_PORT
from hydra.plugins.wdtt.plugin import LOCAL_TUN_PORT as LOCAL_TUN_PORT
from hydra.plugins.wdtt.plugin import SERVICE_NAME as SERVICE_NAME
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
from hydra.ui.tui import title as title
from hydra.ui.tui import warn as warn


def _implementation_scope():
    return bind_facade(sys.modules[__name__])


def _load_passwords(app: ApplicationService) -> dict:
    return app.plugin_query("wdtt", "password_registry")


def _save_passwords(
    data: dict,
    app: ApplicationService,
) -> None:
    app.plugin_action("wdtt", "save_password_registry", data=data)


def _hot_reload(app: ApplicationService) -> bool:
    return bool(app.plugin_action("wdtt", "hot_reload"))


def _get_server_ip(app: ApplicationService) -> str:
    return str(app.plugin_query("wdtt", "public_server_ip"))


def _save_link_to_file(
    link: str,
    filename: str,
    app: ApplicationService,
) -> None:
    try:
        path = app.plugin_action(
            "wdtt",
            "save_client_link",
            link=link,
            filename=filename,
        )
        print(
            f"\n  {DIM}📄 Ссылка сохранена в файл: "
            f"{NC}{CYAN}{path}{NC}",
        )
    except Exception:
        pass


def _diagnostic_output(
    app: ApplicationService,
    command: list[str],
    empty_message: str,
    timeout: int = 5,
) -> str:
    """Run a read-only diagnostic command without freezing the TUI."""
    try:
        result = app.admin.run_command(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except HostOperationError:
        return (
            f"Команда не ответила за {timeout} сек. "
            "Вывод пропущен."
        )
    except FileNotFoundError:
        return f"Команда {command[0]} не найдена."
    except OSError as exc:
        return f"Не удалось выполнить {command[0]}: {exc}"
    except Exception:
        return (
            f"Команда не ответила за {timeout} сек. "
            "Вывод пропущен."
        )
    return (result.stdout or result.stderr or empty_message).strip()


def menu_wdtt(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._wdtt_menu import run

    with _implementation_scope():
        run(state, app)


def _run_install(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._wdtt_install import run_install

    with _implementation_scope():
        run_install(state, app)


def _passwords_menu(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._wdtt_passwords import menu_passwords

    with _implementation_scope():
        menu_passwords(state, app)


def _create_password_wizard(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._wdtt_passwords import create_password

    with _implementation_scope():
        create_password(state, app)


def _show_password_link_wizard(
    state: AppState,
    passwords: dict,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._wdtt_passwords import (
        show_password_link,
    )

    with _implementation_scope():
        show_password_link(state, passwords, app)


def _delete_password_wizard(
    passwords: dict,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._wdtt_passwords import delete_password

    with _implementation_scope():
        delete_password(passwords, app)


def _show_main_link(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._wdtt_operations import show_main_link

    with _implementation_scope():
        show_main_link(state, app)


def _restart_service(app: ApplicationService) -> None:
    from hydra.ui.plugin_managers._wdtt_operations import restart_service

    with _implementation_scope():
        restart_service(app)


def _show_status_logs(app: ApplicationService) -> None:
    from hydra.ui.plugin_managers._wdtt_operations import show_status_logs

    with _implementation_scope():
        show_status_logs(app)


def _uninstall_wdtt(
    state: AppState,
    app: ApplicationService,
) -> None:
    from hydra.ui.plugin_managers._wdtt_operations import uninstall_wdtt

    with _implementation_scope():
        uninstall_wdtt(state, app)


def _show_guide() -> None:
    from hydra.ui.plugin_managers._wdtt_guides import show_guide

    with _implementation_scope():
        show_guide()


def _guide_android() -> None:
    from hydra.ui.plugin_managers._wdtt_guides import guide_android

    with _implementation_scope():
        guide_android()


def _guide_vk_hash() -> None:
    from hydra.ui.plugin_managers._wdtt_guides import guide_vk_hash

    with _implementation_scope():
        guide_vk_hash()


def _guide_telegram() -> None:
    from hydra.ui.plugin_managers._wdtt_guides import guide_telegram

    with _implementation_scope():
        guide_telegram()
