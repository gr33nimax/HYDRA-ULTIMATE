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
        "local_user_traffic_totals",
        "node_traffic_contributions",
        "retired_node_traffic_totals",
        "singbox_last_update_check",
        "singbox_latest_version",
        "singbox_update_available",
        "sync_config_pending",
        "sync_config_pending_source",
        "traffic_connection_counters",
        "traffic_daemon_last_poll",
        "traffic_log_cursors",
        "traffic_report_totals",
        "traffic_user_reset_epochs",
        "managed_node_user_reset_epochs",
        "managed_node_traffic_baselines",
        "managed_node_local_traffic_totals",
        "managed_node_usage_contributions",
        "managed_node_retired_usage",
    },
)


def desired_payload(state: AppState) -> dict:
    """Return persisted configuration without volatile accounting fields."""
    data = asdict(state) if is_dataclass(state) else copy.deepcopy(state)
    data.pop("revision", None)
    install = data.get("install", {})
    for key in _RUNTIME_INSTALL_KEYS:
        install.pop(key, None)
    extensions = data.get("feature_extensions", {})
    if isinstance(extensions, dict):
        managed_nodes = extensions.get("managed_nodes")
        if isinstance(managed_nodes, dict):
            managed_nodes.pop("operations", None)
            managed_nodes.pop("apply_intents", None)
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
    latest_users = {user.uuid: user for user in latest.users}
    traffic_resets = latest.install.get("traffic_user_reset_epochs", {})
    target_resets = state.install.get("traffic_user_reset_epochs", {})
    new_resets: set[str] = set()
    for user in state.users:
        current = latest_users.get(user.uuid)
        if current is None:
            continue
        latest_epoch = int(traffic_resets.get(user.uuid, traffic_resets.get(current.email, 0)))
        target_epoch = int(target_resets.get(user.uuid, target_resets.get(user.email, 0)))
        if target_epoch > latest_epoch:
            new_resets.add(user.uuid)
            continue
        reset = latest_epoch > 0
        user.traffic_used_bytes = (
            int(current.traffic_used_bytes)
            if reset
            else max(
                int(user.traffic_used_bytes),
                int(current.traffic_used_bytes),
            )
        )
        # Subscription requests can register a device while a long-lived
        # TUI process still holds an older copy of AppState. Never erase
        # those bindings during an unrelated settings save.
        if user.uuid not in device_resets:
            user.devices = {**current.devices, **user.devices}
        protocols = set(user.credentials) | set(current.credentials)
        for protocol in protocols:
            current_stats = current.credentials.get(protocol, {})
            if not isinstance(current_stats, dict):
                continue
            target_stats = user.credentials.setdefault(protocol, {})
            if reset:
                for key in tuple(target_stats):
                    if key.startswith("traffic_"):
                        target_stats.pop(key, None)
                target_stats.update(
                    {key: copy.deepcopy(value) for key, value in current_stats.items() if key.startswith("traffic_")}
                )
                continue
            current_total = int(current_stats.get("traffic_used_bytes", 0))
            target_total = int(target_stats.get("traffic_used_bytes", 0))
            if current_total >= target_total:
                target_stats["traffic_used_bytes"] = current_total
                if "traffic_last_raw_bytes" in current_stats:
                    target_stats["traffic_last_raw_bytes"] = current_stats["traffic_last_raw_bytes"]
                for stat_key, stat_value in current_stats.items():
                    if stat_key.startswith("traffic_") and stat_key not in {
                        "traffic_used_bytes",
                        "traffic_last_raw_bytes",
                    }:
                        target_stats[stat_key] = copy.deepcopy(stat_value)
    reset_keys = {
        "traffic_user_reset_epochs",
        "local_user_traffic_totals",
        "retired_node_traffic_totals",
        "node_traffic_contributions",
    }
    node_runtime_keys = {
        "managed_node_user_reset_epochs",
        "managed_node_traffic_baselines",
        "managed_node_local_traffic_totals",
        "managed_node_usage_contributions",
        "managed_node_retired_usage",
    }
    for key in _RUNTIME_INSTALL_KEYS:
        target = state.install.get(key, {})
        merged = copy.deepcopy(latest.install.get(key, {}))
        if key in node_runtime_keys and isinstance(target, dict) and isinstance(merged, dict):
            merged.update(copy.deepcopy(target))
        if key in reset_keys and new_resets:
            if key == "node_traffic_contributions":
                for node_id, by_user in target.items():
                    for user_id in new_resets:
                        if user_id in by_user:
                            merged.setdefault(node_id, {})[user_id] = copy.deepcopy(by_user[user_id])
            else:
                for user_id in new_resets:
                    if user_id in target:
                        merged[user_id] = copy.deepcopy(target[user_id])
        if key in latest.install or key in node_runtime_keys and target or (key in reset_keys and new_resets):
            state.install[key] = merged
        else:
            state.install.pop(key, None)
    _merge_managed_node_operations(state, latest)


def _merge_managed_node_operations(state: AppState, latest: AppState) -> None:
    target = state.feature_extensions.get("managed_nodes")
    source = latest.feature_extensions.get("managed_nodes")
    if not isinstance(source, dict) or not isinstance(target, dict):
        return
    if source.get("version") != 1 or target.get("version") != 1:
        return
    target["operations"] = copy.deepcopy(source.get("operations", []))
    target["apply_intents"] = copy.deepcopy(source.get("apply_intents", {}))


__all__ = [
    "_RUNTIME_INSTALL_KEYS",
    "desired_payload",
    "merge_runtime_state",
]
