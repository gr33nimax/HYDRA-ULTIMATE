"""Compatibility facade for Telegram security actions and controls."""
from __future__ import annotations

import threading
from typing import Callable

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.security_notifications import send_admin_notification
from hydra.services.telegram import (
    security_ip_actions,
    security_keyboards,
    security_monitors,
    security_settings,
)


NotificationSender = Callable[..., bool]


def _mapping_projection(value: object) -> dict:
    return security_ip_actions._mapping_projection(value)


def unban_ip_everywhere(ip: str, app: ApplicationService) -> str:
    return security_ip_actions.unban_ip_everywhere(ip, app)


def ban_ip_antidpi(ip: str, app: ApplicationService) -> dict:
    return security_ip_actions.ban_ip_antidpi(ip, app)


def _process_fail2ban_log_line(
    line: str,
    *,
    notify: NotificationSender = send_admin_notification,
) -> None:
    security_monitors._process_fail2ban_log_line(line, notify=notify)


def _fail2ban_monitor_worker(
    stop_event: threading.Event,
    app: ApplicationService,
    *,
    notify: NotificationSender = send_admin_notification,
) -> None:
    security_monitors._fail2ban_monitor_worker(
        stop_event,
        app,
        notify=notify,
    )


def _process_honeypot_log_line(
    line: str,
    app: ApplicationService,
    *,
    notify: NotificationSender = send_admin_notification,
) -> None:
    security_monitors._process_honeypot_log_line(
        line,
        app,
        notify=notify,
    )


def _projected_lines(value: object) -> list[str]:
    return security_monitors._projected_lines(value)


def _log_overlap(previous: list[str], current: list[str]) -> int:
    return security_monitors._log_overlap(previous, current)


def _follow_plugin_log(
    stop_event: threading.Event,
    fetch: Callable[[], object],
    process: Callable[[str], None],
) -> None:
    security_monitors._follow_plugin_log(stop_event, fetch, process)


def _honeypot_monitor_worker(
    stop_event: threading.Event,
    app: ApplicationService,
    *,
    notify: NotificationSender = send_admin_notification,
) -> None:
    security_monitors._honeypot_monitor_worker(
        stop_event,
        app,
        notify=notify,
    )


def _notification_settings_text() -> str:
    return security_settings._notification_settings_text()


def _toggle_notification(field: str) -> bool:
    return security_settings._toggle_notification(field)


def _main_keyboard():
    return security_keyboards._main_keyboard()


def _back_keyboard(*, refresh: str = "home", extra: list | None = None):
    return security_keyboards._back_keyboard(refresh=refresh, extra=extra)


def _notification_keyboard():
    return security_keyboards._notification_keyboard()


def _antidpi_keyboard(app: ApplicationService):
    return security_keyboards._antidpi_keyboard(app)


def _set_plugin_running(
    state: AppState,
    name: str,
    *,
    running: bool,
    app: ApplicationService,
) -> bool:
    return security_keyboards._set_plugin_running(
        state,
        name,
        running=running,
        app=app,
    )


def _toggle_antidpi(app: ApplicationService) -> tuple[bool, str]:
    return security_keyboards._toggle_antidpi(app)


def _honeypot_keyboard(app: ApplicationService):
    return security_keyboards._honeypot_keyboard(app)


def _toggle_honeypot(app: ApplicationService) -> tuple[bool, str]:
    return security_keyboards._toggle_honeypot(app)


def _fail2ban_keyboard(app: ApplicationService):
    return security_keyboards._fail2ban_keyboard(app)


def _toggle_fail2ban(app: ApplicationService) -> tuple[bool, str]:
    return security_keyboards._toggle_fail2ban(app)


__all__ = [
    "_antidpi_keyboard",
    "_back_keyboard",
    "_fail2ban_keyboard",
    "_fail2ban_monitor_worker",
    "_honeypot_keyboard",
    "_honeypot_monitor_worker",
    "_main_keyboard",
    "_notification_keyboard",
    "_notification_settings_text",
    "_process_fail2ban_log_line",
    "_process_honeypot_log_line",
    "_set_plugin_running",
    "_toggle_antidpi",
    "_toggle_fail2ban",
    "_toggle_honeypot",
    "_toggle_notification",
    "ban_ip_antidpi",
    "unban_ip_everywhere",
]
