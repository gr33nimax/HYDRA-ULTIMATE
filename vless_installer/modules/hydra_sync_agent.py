#!/usr/bin/env python3
"""
vless_installer/modules/hydra_sync_agent.py
───────────────────────────────────────────────────────────────────────────────
Периодический агент фоновой проверки лимитов трафика и TTL для пользователей.
Запускается через systemd.timer каждые 5 минут.
───────────────────────────────────────────────────────────────────────────────
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from vless_installer.modules.user_lifecycle import check_and_sync_all_users_limits
    check_and_sync_all_users_limits()
except Exception as e:
    print(f"Error running sync agent: {e}", file=sys.stderr)
    sys.exit(1)
