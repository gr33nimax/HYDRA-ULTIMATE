"""Inline keyboards and lifecycle toggles for security dashboards."""
from __future__ import annotations

from collections.abc import Mapping

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.services.telegram import navigation
from hydra.services.telegram.security_chrome import (
    _back_keyboard,
    address_keyboard,
    antidpi_list_keyboard,
    navigation_rows,
    quiet_hours_keyboard,
)
from hydra.services.telegram.sdk import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)

__all__ = [
    "_antidpi_keyboard",
    "_back_keyboard",
    "_fail2ban_keyboard",
    "_honeypot_keyboard",
    "_main_keyboard",
    "_notification_keyboard",
    "_set_plugin_running",
    "_toggle_antidpi",
    "_toggle_fail2ban",
    "_toggle_honeypot",
    "address_keyboard",
    "antidpi_list_keyboard",
    "navigation_rows",
    "quiet_hours_keyboard",
]

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
            ],
            [
                InlineKeyboardButton(
                    "🌙 Тихие часы",
                    callback_data=navigation.view_callback("quiet"),
                ),
                InlineKeyboardButton(
                    "🔕 Только блокировки",
                    callback_data="notify:notify_only_blocks",
                ),
            ],
            *navigation_rows("notifications"),
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
            InlineKeyboardButton(
                "🧾 Подробнее",
                callback_data=navigation.view_callback("antidpi_details"),
            ),
        ],
        [
            InlineKeyboardButton(
                "🚫 Блокировки",
                callback_data=navigation.view_callback("antidpi_bans"),
            ),
            InlineKeyboardButton(
                "👁 Наблюдение",
                callback_data=navigation.view_callback("antidpi_watch"),
            ),
        ],
    ]
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
