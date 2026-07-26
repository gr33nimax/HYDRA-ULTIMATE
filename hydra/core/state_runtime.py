"""Which parts of persisted state are runtime observations.

Background writers own traffic counters, device sessions and check
results. Separating them from the desired configuration keeps a poll
every two seconds from turning an operator's open menu into a conflict.
"""
from __future__ import annotations

import copy

from dataclasses import asdict, is_dataclass

from hydra.core.state_models import AppState


_RUNTIME_INSTALL_KEYS = frozenset(
    {
        "certificates_last_check",
        "certificates_report",
        "device_sessions",
        "protocol_traffic_totals",
        "singbox_last_update_check",
        "singbox_latest_version",
        "singbox_update_available",
        "sync_config_pending",
        "sync_config_pending_source",
        "traffic_connection_counters",
        "traffic_daemon_last_poll",
        "traffic_log_cursors",
    },
)


def desired_payload(state: AppState) -> dict:
    """Return persisted configuration without volatile accounting fields."""
    data = asdict(state) if is_dataclass(state) else copy.deepcopy(state)
    data.pop("revision", None)
    install = data.get("install", {})
    for key in _RUNTIME_INSTALL_KEYS:
        install.pop(key, None)
    for user in data.get("users", []):
        user.pop("traffic_used_bytes", None)
        # Device bindings are observed request metadata. They are updated
        # atomically by the subscription service and merged into stale
        # long-lived state before a settings save.
        user.pop("devices", None)
        credentials = user.get("credentials", {})
        for protocol, values in list(credentials.items()):
            if not isinstance(values, dict):
                continue
            for key in list(values):
                if key.startswith("traffic_"):
                    values.pop(key, None)
            if not values:
                credentials.pop(protocol, None)
    return data


def merge_runtime_state(
    state: AppState,
    latest: AppState,
    device_resets: set[str],
) -> None:
    """Keep runtime accounting owned by background writers.

    Long-running menus hold an older AppState while the traffic daemon updates
    counters in another process. Preserve the monotonic runtime fields instead
    of letting an unrelated settings save roll them back.
    """
    latest_users = {user.email: user for user in latest.users}
    for user in state.users:
        current = latest_users.get(user.email)
        if current is None:
            continue
        user.traffic_used_bytes = max(
            int(user.traffic_used_bytes), int(current.traffic_used_bytes),
        )
        # Subscription requests can register a device while a long-lived
        # TUI process still holds an older copy of AppState. Never erase
        # those bindings during an unrelated settings save.
        if user.uuid not in device_resets:
            user.devices = {**current.devices, **user.devices}
        for protocol, current_stats in current.credentials.items():
            if not isinstance(current_stats, dict):
                continue
            target_stats = user.credentials.setdefault(protocol, {})
            current_total = int(current_stats.get("traffic_used_bytes", 0))
            target_total = int(target_stats.get("traffic_used_bytes", 0))
            if current_total >= target_total:
                target_stats["traffic_used_bytes"] = current_total
                if "traffic_last_raw_bytes" in current_stats:
                    target_stats["traffic_last_raw_bytes"] = current_stats["traffic_last_raw_bytes"]
                for stat_key, stat_value in current_stats.items():
                    if stat_key.startswith("traffic_") and stat_key not in {
                        "traffic_used_bytes", "traffic_last_raw_bytes",
                    }:
                        target_stats[stat_key] = copy.deepcopy(stat_value)
    for key in _RUNTIME_INSTALL_KEYS:
        if key in latest.install:
            state.install[key] = copy.deepcopy(latest.install[key])
        else:
            state.install.pop(key, None)



__all__ = [
    "_RUNTIME_INSTALL_KEYS",
    "desired_payload",
    "merge_runtime_state",
]
