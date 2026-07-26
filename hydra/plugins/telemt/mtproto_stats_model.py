"""Storage model for Telemt traffic statistics."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

STATS_FILE = Path("/var/lib/telemt/stats.json")
CONFIG_FILE = Path("/etc/telemt/telemt.toml")
CRON_FILE = Path("/etc/cron.d/telemt-stats")
CHAIN_IN = "TELEMT_STATS_IN"
CHAIN_OUT = "TELEMT_STATS_OUT"
SERVICE_NAME = "telemt"


def now_string() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def empty_stats() -> dict:
    return {
        "total": {"rx": 0, "tx": 0, "updated": "", "since": now_string()},
        "daily": {},
        "users": {},
        "ipt_ok": False,
    }


def load_stats(path: Path = STATS_FILE) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return empty_stats()


def save_stats(data: dict, path: Path = STATS_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2))
