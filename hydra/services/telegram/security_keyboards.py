"""Inline keyboards and lifecycle toggles for security dashboards."""
from __future__ import annotations

from collections.abc import Mapping

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.telegram.sdk import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)

def _mapping_projection(value: object) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}

def _main_keyboard():
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "🖥 Система",
                    callback_data="view:system",
                ),
                InlineKeyboardButton(
                    "🛡 AntiDPI",
                    callback_data="view:antidpi",
                ),
            ],
            [
                InlineKeyboardButton(
                    "🚫 Fail2ban",
                    callback_data="view:fail2ban",
                ),
                InlineKeyboardButton(
                    "🍯 Honeypot",
                    callback_data="view:honeypot",
                ),
            ],
            [
                InlineKeyboardButton(
                    "🔔 Уведомления",
                    callback_data="view:notifications",
                ),
            ],
            [
                InlineKeyboardButton(
                    "🔄 Обновить",
                    callback_data="view:home",
                ),
            ],
        ],
    )

def _back_keyboard(*, refresh: str = "home", extra: list | None = None):
    rows = list(extra or [])
    rows.append(
        [
            InlineKeyboardButton(
                "🔄 Обновить",
                callback_data=f"view:{refresh}",
            ),
            InlineKeyboardButton(
                "⬅️ Меню",
                callback_data="view:home",
            ),
        ],
    )
    return InlineKeyboardMarkup(rows)

def _notification_keyboard():
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "Все",
                    callback_data="notify:notifications_enabled",
                ),
                InlineKeyboardButton(
                    "AntiDPI",
                    callback_data="notify:notify_antidpi",
                ),
            ],
            [
                InlineKeyboardButton(
                    "Honeypot",
                    callback_data="notify:notify_honeypot",
                ),
                InlineKeyboardButton(
                    "Fail2ban",
                    callback_data="notify:notify_fail2ban",
                ),
            ],
            [
                InlineKeyboardButton(
                    "UNBAN",
                    callback_data="notify:notify_unbans",
                ),
                InlineKeyboardButton(
                    "Системные",
                    callback_data="notify:notify_system",
                ),
                InlineKeyboardButton(
                    "⬅️ Меню",
                    callback_data="view:home",
                ),
            ],
        ],
    )

def _antidpi_keyboard(app: ApplicationService):
    status = app.protocols.status("antidpi")
    action = "⏸ Остановить" if status.running else "▶️ Запустить"
    rows = [
        [
            InlineKeyboardButton(
                action,
                callback_data="ask:antidpi_toggle",
            ),
        ],
    ]
    try:
        data = _mapping_projection(
            app.plugin_query("antidpi", "management_snapshot"),
        )
        banned = _mapping_projection(data.get("banned"))
        addresses = [
            address
            for address, _metadata in sorted(
                banned.items(),
                key=lambda item: float(item[1].get("at", 0) or 0),
                reverse=True,
            )[:5]
        ]
    except Exception:
        addresses = []
    for address in addresses:
        rows.append(
            [
                InlineKeyboardButton(
                    f"🔓 {address}",
                    callback_data=f"ask-unban:{address}",
                ),
            ],
        )
    return _back_keyboard(refresh="antidpi", extra=rows)

def _set_plugin_running(
    state: AppState,
    name: str,
    *,
    running: bool,
    app: ApplicationService,
) -> bool:
    """Route lifecycle changes through the injected application service."""
    if running:
        return app.protocols.disable(state, name)
    return app.protocols.enable(state, name)

def _toggle_antidpi(app: ApplicationService) -> tuple[bool, str]:
    state = app.admin.load_state()
    running = app.protocols.status("antidpi").running
    ok = _set_plugin_running(
        state,
        "antidpi",
        running=running,
        app=app,
    )
    return ok, "остановлен" if running else "запущен"

def _honeypot_keyboard(app: ApplicationService):
    status = app.protocols.status("honeypot")
    rows = [
        [
            InlineKeyboardButton(
                "⏹ Остановить" if status.running else "▶️ Запустить",
                callback_data="ask:honeypot_toggle",
            ),
        ],
    ]
    data = _mapping_projection(
        app.plugin_query("honeypot", "management_snapshot"),
    )
    banned = (
        data.get("banned", {})
        if isinstance(data.get("banned"), dict)
        else {}
    )
    ordered = sorted(
        banned.items(),
        key=lambda item: str(item[1].get("banned_at", "")),
        reverse=True,
    )
    for address, _metadata in ordered[:5]:
        rows.append(
            [
                InlineKeyboardButton(
                    f"🔓 {address}",
                    callback_data=f"ask-hp-unban:{address}",
                ),
            ],
        )
    return _back_keyboard(refresh="honeypot", extra=rows)

def _toggle_honeypot(app: ApplicationService) -> tuple[bool, str]:
    state = app.admin.load_state()
    running = app.protocols.status("honeypot").running
    ok = _set_plugin_running(
        state,
        "honeypot",
        running=running,
        app=app,
    )
    return ok, "остановлен" if running else "запущен"

def _fail2ban_keyboard(app: ApplicationService):
    running = app.protocols.status("fail2ban").running
    action = "⏹ Остановить" if running else "▶️ Запустить"
    return _back_keyboard(
        refresh="fail2ban",
        extra=[
            [
                InlineKeyboardButton(
                    action,
                    callback_data="ask:fail2ban_toggle",
                ),
            ],
        ],
    )

def _toggle_fail2ban(app: ApplicationService) -> tuple[bool, str]:
    state = app.admin.load_state()
    running = app.protocols.status("fail2ban").running
    ok = _set_plugin_running(
        state,
        "fail2ban",
        running=running,
        app=app,
    )
    return ok, "остановлен" if running else "запущен"

