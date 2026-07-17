"""Monotonic per-user traffic accounting.

Live plugin counters are snapshots and may reset after a restart or log rotation.
This module converts those snapshots to deltas and keeps the authoritative,
monotonic totals in per-protocol user credentials.
"""
from __future__ import annotations

from hydra.core.state import AppState, load_state, update_state
from hydra.plugins.registry import enabled, get


_SNAPSHOT_PROTOCOLS = ("amneziawg", "telemt")


def _as_non_negative_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _accumulate_snapshot(state: AppState, protocol: str,
                         snapshot: dict[str, int]) -> None:
    """Convert a resettable absolute counter to a monotonic stored total."""
    users = {user.email: user for user in state.users}
    for email, raw_value in snapshot.items():
        user = users.get(email)
        if user is None:
            continue
        raw = _as_non_negative_int(raw_value)
        stats = user.credentials.setdefault(protocol, {})
        previous_raw = stats.get("traffic_last_raw_bytes")
        accumulated = _as_non_negative_int(stats.get("traffic_used_bytes", 0))
        if previous_raw is None:
            # Migration from the old snapshot-only accounting model.
            accumulated = max(accumulated, raw)
        else:
            previous_raw = _as_non_negative_int(previous_raw)
            # A lower value means that the interface/process counter reset.
            accumulated += raw - previous_raw if raw >= previous_raw else raw
        stats["traffic_last_raw_bytes"] = raw
        stats["traffic_used_bytes"] = accumulated


def refresh_user_traffic(state: AppState) -> dict[str, int]:
    """Refresh resettable sources and rebuild authoritative user totals."""
    enabled_names = {plugin.meta.name for plugin in enabled(state)}

    for protocol in _SNAPSHOT_PROTOCOLS:
        if protocol not in enabled_names:
            continue
        plugin = get(protocol)
        if plugin is None:
            continue
        try:
            _accumulate_snapshot(state, protocol, plugin.traffic(state))
        except Exception:
            # Keep the last good totals when a runtime counter is unavailable.
            continue

    # Naive uses an inode/offset cursor because its access log is rotated.
    if "naive" in enabled_names:
        plugin = get("naive")
        updater = getattr(plugin, "update_traffic", None) if plugin else None
        if updater:
            try:
                updater(state)
            except Exception:
                pass

    totals: dict[str, int] = {}
    for user in state.users:
        total = 0
        for stats in user.credentials.values():
            if isinstance(stats, dict):
                total += _as_non_negative_int(stats.get("traffic_used_bytes", 0))
        # Never reduce an existing total during migration or a partial outage.
        user.traffic_used_bytes = max(_as_non_negative_int(user.traffic_used_bytes), total)
        totals[user.email] = user.traffic_used_bytes
    return totals


def refresh_traffic_state() -> AppState:
    """Atomically refresh and persist traffic, returning the latest state."""
    state, _ = update_state(refresh_user_traffic)
    return state


def collect_traffic(state: AppState | None = None) -> dict[str, int]:
    """Return authoritative totals; persist a refresh when no state is passed."""
    if state is None:
        state = refresh_traffic_state()
    else:
        refresh_user_traffic(state)
    return {user.email: user.traffic_used_bytes for user in state.users}


def update_user_traffic(state: AppState) -> None:
    """Backward-compatible in-memory refresh."""
    refresh_user_traffic(state)


def protocol_totals(state: AppState) -> dict[str, int]:
    totals: dict[str, int] = {}
    for user in state.users:
        for protocol, stats in user.credentials.items():
            if not isinstance(stats, dict):
                continue
            used = _as_non_negative_int(stats.get("traffic_used_bytes", 0))
            if used:
                totals[protocol] = totals.get(protocol, 0) + used
    return totals


def check_traffic_limits(state: AppState) -> list[str]:
    refresh_user_traffic(state)
    exceeded: list[str] = []
    for user in state.users:
        if user.blocked:
            continue
        limit_bytes = int(user.traffic_limit_gb * 1073741824)
        if limit_bytes > 0 and user.traffic_used_bytes >= limit_bytes:
            exceeded.append(user.email)
    return exceeded
