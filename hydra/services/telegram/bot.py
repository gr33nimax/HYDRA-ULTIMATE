"""Compatibility façade for the decomposed Telegram administration adapter."""
from __future__ import annotations

import threading

from hydra.core.host import HOST
from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.security_notifications import (
    format_security_event as _format_security_event,
    notification_allowed as _notification_allowed,
    send_admin_notification as _send_admin_notification,
)
from hydra.services.telegram import dashboards, security_actions
from hydra.services.telegram.controller import AdminBot
from hydra.services.telegram.sdk import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    TELEGRAM_AVAILABLE,
)


def send_admin_notification(
    text: str,
    state: AppState | None = None,
    *,
    category: str = "system",
    force: bool = False,
    reply_markup: dict | None = None,
) -> bool:
    return _send_admin_notification(
        text,
        state=state,
        category=category,
        force=force,
        reply_markup=reply_markup,
    )


def notification_allowed(state: AppState, category: str) -> bool:
    return _notification_allowed(state, category)


def format_security_event(
    component: str,
    action: str,
    fields: list[tuple[str, object]],
) -> str:
    return _format_security_event(component, action, fields)


def get_system_info_text(app: ApplicationService) -> str:
    return dashboards.get_system_info_text(app)


def get_antidpi_status_text(app: ApplicationService) -> str:
    return dashboards.get_antidpi_status_text(app)


def get_antidpi_dashboard_text(app: ApplicationService) -> str:
    return dashboards.get_antidpi_dashboard_text(app)


def get_honeypot_status_text(app: ApplicationService) -> str:
    return dashboards.get_honeypot_status_text(app)


def get_fail2ban_status_text(app: ApplicationService) -> str:
    return dashboards.get_fail2ban_status_text(app)


def get_fail2ban_dashboard_text(app: ApplicationService) -> str:
    return dashboards.get_fail2ban_dashboard_text(app)


def unban_ip_everywhere(ip: str, app: ApplicationService) -> str:
    return security_actions.unban_ip_everywhere(ip, app)


def ban_ip_antidpi(ip: str, app: ApplicationService) -> dict:
    return security_actions.ban_ip_antidpi(ip, app)


def _process_fail2ban_log_line(line: str) -> None:
    security_actions._process_fail2ban_log_line(
        line,
        notify=send_admin_notification,
    )


def _process_honeypot_log_line(
    line: str,
    app: ApplicationService,
) -> None:
    security_actions._process_honeypot_log_line(
        line,
        app,
        notify=send_admin_notification,
    )


def _honeypot_monitor_worker(
    stop_event: threading.Event,
    app: ApplicationService,
) -> None:
    security_actions._honeypot_monitor_worker(
        stop_event,
        app,
        notify=send_admin_notification,
    )


def _format_period(seconds: object) -> str:
    return dashboards._format_period(seconds)


def _legacy_honeypot_status_text(app: ApplicationService) -> str:
    return dashboards._legacy_honeypot_status_text(app)


def _parse_fail2ban_jail(detail: str) -> dict:
    return dashboards._parse_fail2ban_jail(detail)


def _legacy_fail2ban_dashboard_text(app: ApplicationService) -> str:
    return dashboards._legacy_fail2ban_dashboard_text(app)


def _format_security_timestamp(value: object) -> str:
    return dashboards._format_security_timestamp(value)


def _parse_fail2ban_ban_lines(
    lines: list[str],
    limit: int = 5,
) -> list[dict[str, str]]:
    return dashboards._parse_fail2ban_ban_lines(lines, limit)


def _lookup_security_intel(
    addresses: list[str],
) -> dict[str, dict[str, str]]:
    return dashboards._lookup_security_intel(addresses)


def _network_label(intel: dict[str, str]) -> str:
    return dashboards._network_label(intel)


def _notification_settings_text() -> str:
    return security_actions._notification_settings_text()


def _toggle_notification(field: str) -> bool:
    return security_actions._toggle_notification(field)


def _main_keyboard():
    return security_actions._main_keyboard()


def _back_keyboard(*, refresh: str = "home", extra: list | None = None):
    return security_actions._back_keyboard(refresh=refresh, extra=extra)


def _notification_keyboard():
    return security_actions._notification_keyboard()


def _antidpi_keyboard(app: ApplicationService):
    return security_actions._antidpi_keyboard(app)


def _toggle_antidpi(app: ApplicationService) -> tuple[bool, str]:
    return security_actions._toggle_antidpi(app)


def _honeypot_keyboard(app: ApplicationService):
    return security_actions._honeypot_keyboard(app)


def _toggle_honeypot(app: ApplicationService) -> tuple[bool, str]:
    return security_actions._toggle_honeypot(app)


def _fail2ban_keyboard(app: ApplicationService):
    return security_actions._fail2ban_keyboard(app)


def _toggle_fail2ban(app: ApplicationService) -> tuple[bool, str]:
    return security_actions._toggle_fail2ban(app)


def run_admin_bot(
    token: str,
    admin_chat_id: str,
    *,
    application: ApplicationService,
) -> None:
    """Start the Telegram adapter with explicitly composed dependencies."""
    AdminBot(token, admin_chat_id, application).run()


def run_client_bot(token: str, admin_chat_id: str) -> None:
    """Compatibility with the retired client-bot entrypoint."""
    print(
        "ClientBot устарел и отключён. Используйте AdminBot "
        "для мониторинга и уведомлений.",
    )


__all__ = [
    "AdminBot",
    "HOST",
    "InlineKeyboardButton",
    "InlineKeyboardMarkup",
    "TELEGRAM_AVAILABLE",
    "_antidpi_keyboard",
    "_back_keyboard",
    "_fail2ban_keyboard",
    "_format_period",
    "_format_security_timestamp",
    "_honeypot_keyboard",
    "_honeypot_monitor_worker",
    "_legacy_fail2ban_dashboard_text",
    "_legacy_honeypot_status_text",
    "_lookup_security_intel",
    "_main_keyboard",
    "_network_label",
    "_notification_keyboard",
    "_notification_settings_text",
    "_parse_fail2ban_ban_lines",
    "_parse_fail2ban_jail",
    "_process_fail2ban_log_line",
    "_process_honeypot_log_line",
    "_toggle_antidpi",
    "_toggle_fail2ban",
    "_toggle_honeypot",
    "_toggle_notification",
    "ban_ip_antidpi",
    "format_security_event",
    "get_antidpi_dashboard_text",
    "get_antidpi_status_text",
    "get_fail2ban_dashboard_text",
    "get_fail2ban_status_text",
    "get_honeypot_status_text",
    "get_system_info_text",
    "notification_allowed",
    "run_admin_bot",
    "run_client_bot",
    "send_admin_notification",
    "unban_ip_everywhere",
]
