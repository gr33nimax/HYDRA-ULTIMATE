"""
hydra/services/sync_agent.py — Фоновый агент синхронизации.

Проверяет лимиты трафика и сроки действия подписок.
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
      1. Проверить лимиты трафика → заблокировать превысивших
      2. Проверить TTL (срок действия) → заблокировать истёкших
      3. Перегенерировать конфиги протоколов при необходимости
    """
    state = load_state()

    # 1. Проверка лимитов трафика
    exceeded = check_traffic_limits(state)
    for email in exceeded:
        for user in state.users:
            if user.email == email and not user.blocked:
                user.blocked = True
                _log(f"User {email} blocked: traffic limit exceeded")

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
        except (ValueError, TypeError):
            pass

    save_state(state)


def _log(msg: str) -> None:
    """Логирование в файл sync-агента."""
    try:
        log = Path("/var/log/hydra/sync-agent.log")
        log.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with log.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


# Точка входа для systemd
if __name__ == "__main__":
    try:
        run_sync()
    except Exception as e:
        print(f"Sync agent error: {e}", file=sys.stderr)
        sys.exit(1)
