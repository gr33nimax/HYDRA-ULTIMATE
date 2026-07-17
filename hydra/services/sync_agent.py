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

from hydra.core.state import load_state, update_state
from hydra.plugins.registry import get_enabled
from hydra.services.traffic import check_traffic_limits


def run_sync() -> None:
    """
    Основная логика синхронизации:
      1. Проверить лимиты трафика -> заблокировать превысивших
      2. Проверить TTL (срок действия) -> заблокировать истёкших
      3. Уведомить плагины о блокировке
      4. Применить измененный конфиг к службам
    """
    state = load_state()
    any_blocked = False

    # 1. Проверка лимитов трафика
    # Refresh counters and persist them under the same cross-process lock used
    # by the traffic daemon.
    def refresh_and_check(latest):
        return check_traffic_limits(latest)

    state, exceeded = update_state(refresh_and_check)
    for email in exceeded:
        for user in state.users:
            if user.email == email and not user.blocked:
                user.blocked = True
                any_blocked = True
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
            dt_str = user.expiry_date
            if dt_str.endswith("Z"):
                dt_str = dt_str[:-1] + "+00:00"
            expiry = datetime.fromisoformat(dt_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry < now:
                user.blocked = True
                any_blocked = True
                _log(f"User {user.email} blocked: subscription expired")
                for p in get_enabled(state):
                    try:
                        p.on_user_block(user, state)
                    except Exception:
                        pass
        except (ValueError, TypeError):
            pass

    if any_blocked:
        from hydra.core.orchestrator import apply_config
        blocked_emails = {user.email for user in state.users if user.blocked}

        def merge_blocks(latest):
            changed = False
            for user in latest.users:
                if user.email in blocked_emails and not user.blocked:
                    user.blocked = True
                    changed = True
            return changed

        state, _ = update_state(merge_blocks)
        apply_config(state)
        _log("Applied server config due to new user block(s)")

    # 3. WARP: автообновление внешних списков (раз в 24 часа)
    try:
        from hydra.plugins.warp.plugin import WarpPlugin
        from hydra.core.orchestrator import apply_config
        p = WarpPlugin()
        status = p.status()
        if status.enabled:
            # Проверяем кэш
            cache_file = Path("/var/lib/hydra/warp_external.json")
            need_update = True
            if cache_file.exists():
                try:
                    import json
                    data = json.loads(cache_file.read_text(encoding="utf-8"))
                    up_str = data.get("updated_at")
                    if up_str:
                        updated_at = datetime.fromisoformat(up_str)
                        diff = datetime.now() - updated_at
                        if diff.total_seconds() < 86400:
                            need_update = False
                except Exception:
                    pass
            
            if need_update:
                _log("WARP: Triggering daily auto-update of external rules...")
                ok, msg = p.update_external_rules()
                _log(f"WARP: Update result: {msg}")
                if ok:
                    apply_config(state)
    except Exception as e:
        _log(f"WARP auto-update check failed: {e}")

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
