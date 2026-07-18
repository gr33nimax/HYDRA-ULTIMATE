"""Build an honest active-session view from traffic-daemon snapshots."""
from __future__ import annotations

import time

from hydra.core.state import AppState


TRACKED_PROTOCOLS = frozenset({"anytls", "mieru", "trusttunnel", "shadowtls"})


def traffic_daemon_fresh(state: AppState, max_age: float = 15.0) -> bool:
    try:
        return time.time() - float(state.install.get("traffic_daemon_last_poll", 0)) <= max_age
    except (TypeError, ValueError):
        return False


def tracked_active_connections(state: AppState) -> list[dict]:
    if not state.network.clash_api_enabled or not traffic_daemon_fresh(state):
        return []
    grouped: dict[tuple[str, str], dict] = {}
    counters = state.install.get("traffic_connection_counters", {})
    for record in counters.values():
        if int(record.get("missed_polls", 0)) != 0:
            continue
        protocol = str(record.get("protocol", ""))
        user = str(record.get("user", ""))
        if protocol not in TRACKED_PROTOCOLS or not user:
            continue
        key = (protocol, user)
        item = grouped.setdefault(key, {
            "plugin": protocol,
            "email": user,
            "online": True,
            "rx": 0,
            "tx": 0,
            "connections": 0,
            "last_handshake": int(record.get("seen_at", time.time())),
            "traffic_scope": "active",
        })
        item["rx"] += max(0, int(record.get("download", 0)))
        item["tx"] += max(0, int(record.get("upload", 0)))
        item["connections"] += 1
        item["last_handshake"] = max(
            item["last_handshake"], int(record.get("seen_at", item["last_handshake"])),
        )
    return list(grouped.values())
