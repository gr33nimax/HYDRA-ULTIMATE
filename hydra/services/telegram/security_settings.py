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
        f"Системные: {mark(getattr(telegram, 'notify_system', True))}\n\n"
        "Только блокировки: "
        f"{mark(getattr(telegram, 'notify_only_blocks', False))}\n"
        "Тихие часы: "
        f"{mark(getattr(telegram, 'quiet_hours_enabled', False))} "
        f"<code>{int(getattr(telegram, 'quiet_hours_start', 23)) % 24:02d}:00"
        f"—{int(getattr(telegram, 'quiet_hours_end', 8)) % 24:02d}:00</code>"
    )

def quiet_hours_text() -> str:
    """Describe when the panel stays silent and what still gets through."""
    telegram = load_state().telegram
    enabled = bool(getattr(telegram, "quiet_hours_enabled", False))
    start = int(getattr(telegram, "quiet_hours_start", 23)) % 24
    end = int(getattr(telegram, "quiet_hours_end", 8)) % 24
    only_blocks = bool(getattr(telegram, "notify_only_blocks", False))
    return (
        "<b>🌙 Тихие часы и уровень шума</b>\n\n"
        f"Тихие часы: {'✅ включены' if enabled else '❌ выключены'}\n"
        f"Окно: <code>{start:02d}:00 — {end:02d}:00</code> "
        "(время сервера)\n"
        f"Только блокировки: {'✅' if only_blocks else '❌'}\n\n"
        "<i>Блокировки, разблокировки и отказы защиты приходят всегда — "
        "тихие часы и фильтр шума задерживают только предупреждения "
        "и оповещения о наблюдении.</i>"
    )


def shift_quiet_hour(field: str, delta: int) -> int:
    """Move one edge of the quiet window and return the stored hour."""
    if field not in {"quiet_hours_start", "quiet_hours_end"}:
        raise ValueError("unknown quiet hours setting")

    def mutate(state: AppState) -> int:
        current = int(getattr(state.telegram, field, 0) or 0)
        value = (current + int(delta)) % 24
        setattr(state.telegram, field, value)
        return value

    _, value = update_state(mutate)
    return value


def _toggle_notification(field: str) -> bool:
    allowed = {
        "notifications_enabled",
        "notify_antidpi",
        "notify_honeypot",
        "notify_fail2ban",
        "notify_unbans",
        "notify_system",
        "notify_only_blocks",
        "quiet_hours_enabled",
    }
    if field not in allowed:
        raise ValueError("unknown notification setting")

    def mutate(state: AppState) -> bool:
        value = not bool(getattr(state.telegram, field, True))
        setattr(state.telegram, field, value)
        return value

    _, value = update_state(mutate)
    return value
