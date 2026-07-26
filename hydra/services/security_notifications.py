"""Outbound security-notification service.

This module owns Telegram's HTTP delivery details without importing the
Telegram admin adapter or any plugin.  Plugins receive ``notify_security_event``
as an injected outbound port from the composition root.
"""
from __future__ import annotations

import html
import json
import sys
import urllib.request
from typing import Iterable

from hydra.core.state import load_state
from hydra.core.state_models import AppState


_NOTIFICATION_FIELDS = {
    "antidpi": "notify_antidpi",
    "honeypot": "notify_honeypot",
    "fail2ban": "notify_fail2ban",
    "fail2ban_unban": "notify_unbans",
    "system": "notify_system",
}


def notification_allowed(state: AppState, category: str) -> bool:
    telegram = state.telegram
    if not getattr(telegram, "notifications_enabled", True):
        return False
    field = _NOTIFICATION_FIELDS.get(category, "notify_system")
    return bool(getattr(telegram, field, True))


def send_admin_notification(
    text: str,
    state: AppState | None = None,
    *,
    category: str = "system",
    force: bool = False,
    reply_markup: dict | None = None,
) -> bool:
    """Send a categorized message through Telegram's direct HTTP API."""
    try:
        current = state or load_state()
        token = getattr(current.telegram, "admin_token", "").strip()
        chat_id = getattr(current.telegram, "admin_chat_id", "").strip()
        if not token or not chat_id or (
            not force and not notification_allowed(current, category)
        ):
            return False

        request_data: dict[str, object] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if reply_markup:
            request_data["reply_markup"] = reply_markup
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=json.dumps(request_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status == 200
    except Exception as exc:
        # Exceptions can contain the full Bot API URL, including the token.
        status = getattr(exc, "code", None)
        suffix = f" status={status}" if status is not None else ""
        sys.stderr.write(
            f"[AdminBot Notification Error] {type(exc).__name__}{suffix}\n",
        )
        return False


def format_security_event(
    component: str,
    action: str,
    fields: Iterable[tuple[str, object]],
) -> str:
    """Render a compact, escaped technical security notification."""
    title = f"<b>{html.escape(component)} · {html.escape(action.upper())}</b>"
    rows = [
        f"<b>{html.escape(label)}:</b> <code>{html.escape(str(value))}</code>"
        for label, value in fields
        if value not in (None, "")
    ]
    return "\n".join((title, *rows))


def notify_security_event(
    component: str,
    action: str,
    fields: Iterable[tuple[str, object]],
    *,
    category: str,
    reply_markup: dict | None = None,
    state: AppState | None = None,
) -> bool:
    """Format and deliver one security event through the configured channel."""
    return send_admin_notification(
        format_security_event(component, action, fields),
        state=state,
        category=category,
        reply_markup=reply_markup,
    )


__all__ = [
    "format_security_event",
    "notification_allowed",
    "notify_security_event",
    "send_admin_notification",
]
