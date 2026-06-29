"""
hydra/services/sync_agent.py — Фоновый агент синхронизации v2.

Проверяет лимиты трафика и сроки действия подписок.
Уведомляет плагины при блокировке пользователя.
Запускается через systemd timer каждые 5 минут.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from hydra.core.state import load_state, save_state
from hydra.plugins.registry import get_enabled
from hydra.services.traffic import check_traffic_limits


def run_sync() -> None:
    """
    Основная логика синхронизации:
      1. Проверить лимиты трафика -> заблокировать превысивших
      2. Проверить TTL (срок действия) -> заблокировать истёкших
      3. Уведомить плагины о блокировке
    """
    state = load_state()

    # 1. Проверка лимитов трафика
    exceeded = check_traffic_limits(state)
    for email in exceeded:
        for user in state.users:
            if user.email == email and not user.blocked:
                user.blocked = True
                _log(f"User {email} blocked: traffic limit exceeded")
                for p in get_enabled(state):
                    try:
                        p.on_user_block(user, state)
                    except Exception:
                        pass

    # 2. Проверка TTL
    now = datetime.now(timezone.utc)
    for user in state.users:
        if user.blocked:
            continue
        if not user.expiry_date:
            continue
        try:
            expiry = datetime.fromisoformat(user.expiry_date)
            if expiry < now:
                user.blocked = True
                _log(f"User {user.email} blocked: subscription expired")
                for p in get_enabled(state):
                    try:
                        p.on_user_block(user, state)
                    except Exception:
                        pass
        except (ValueError, TypeError):
            pass

    save_state(state)


def _log(msg: str) -> None:
    try:
        log = Path("/var/log/hydra/sync-agent.log")
        log.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with log.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


if __name__ == "__main__":
    try:
        run_sync()
    except Exception as e:
        print(f"Sync agent error: {e}", file=sys.stderr)
        sys.exit(1)
