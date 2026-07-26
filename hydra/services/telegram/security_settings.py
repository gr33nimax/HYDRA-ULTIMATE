"""Telegram notification settings projection and mutation."""
from __future__ import annotations

from hydra.core.state import load_state, update_state
from hydra.core.state_models import AppState

def _notification_settings_text() -> str:
    telegram = load_state().telegram

    def mark(value: object) -> str:
        return "✅" if value else "❌"

    return (
        "<b>🔔 Настройки уведомлений</b>\n\n"
        "Все уведомления: "
        f"{mark(getattr(telegram, 'notifications_enabled', True))}\n"
        f"AntiDPI: {mark(getattr(telegram, 'notify_antidpi', True))}\n"
        f"Honeypot: {mark(getattr(telegram, 'notify_honeypot', True))}\n"
        "Fail2ban BAN: "
        f"{mark(getattr(telegram, 'notify_fail2ban', True))}\n"
        f"События UNBAN: {mark(getattr(telegram, 'notify_unbans', False))}\n"
        f"Системные: {mark(getattr(telegram, 'notify_system', True))}"
    )

def _toggle_notification(field: str) -> bool:
    allowed = {
        "notifications_enabled",
        "notify_antidpi",
        "notify_honeypot",
        "notify_fail2ban",
        "notify_unbans",
        "notify_system",
    }
    if field not in allowed:
        raise ValueError("unknown notification setting")

    def mutate(state: AppState) -> bool:
        value = not bool(getattr(state.telegram, field, True))
        setattr(state.telegram, field, value)
        return value

    _, value = update_state(mutate)
    return value
