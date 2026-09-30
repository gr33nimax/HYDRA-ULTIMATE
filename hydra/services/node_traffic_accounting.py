"""Combine local usage with restart-safe absolute counters from managed nodes."""

from __future__ import annotations

from collections.abc import Iterable

from hydra.contracts.node_traffic import NodeTrafficReport
from hydra.core.state_models import AppState, User

_LOCAL_TOTALS = "local_user_traffic_totals"
_NODE_TOTALS = "node_traffic_contributions"
_RETIRED_TOTALS = "retired_node_traffic_totals"
_RESET_EPOCHS = "traffic_user_reset_epochs"


def _counter(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def traffic_reset_epoch(state: AppState, user: User) -> int:
    epochs = state.install.get(_RESET_EPOCHS, {})
    if not isinstance(epochs, dict):
        return 0
    return _counter(epochs.get(user.uuid, epochs.get(user.email, 0)))


def set_traffic_reset_epoch(state: AppState, user: User, epoch: int) -> None:
    if type(epoch) is not int or epoch < 0:
        raise ValueError("traffic reset epoch must be a non-negative integer")
    epochs = state.install.setdefault(_RESET_EPOCHS, {})
    if not isinstance(epochs, dict):
        raise ValueError("traffic reset epoch state is invalid")
    epochs.pop(user.email, None)
    epochs[user.uuid] = epoch


def local_traffic_total(state: AppState, user: User) -> int:
    totals = state.install.setdefault(_LOCAL_TOTALS, {})
    if not isinstance(totals, dict):
        raise ValueError("local traffic totals are invalid")
    if user.uuid not in totals:
        from_credentials = sum(
            _counter(stats.get("traffic_used_bytes", 0))
            for stats in user.credentials.values()
            if isinstance(stats, dict)
        )
        totals[user.uuid] = max(_counter(user.traffic_used_bytes), from_credentials)
    total = _counter(totals[user.uuid])
    totals[user.uuid] = total
    return total


def sync_local_traffic_from_credentials(state: AppState, user: User) -> None:
    current = local_traffic_total(state, user)
    from_credentials = sum(
        _counter(stats.get("traffic_used_bytes", 0))
        for stats in user.credentials.values()
        if isinstance(stats, dict)
    )
    totals = state.install[_LOCAL_TOTALS]
    totals[user.uuid] = max(current, from_credentials)


def record_local_traffic_delta(state: AppState, user: User, delta: int) -> None:
    totals = state.install.setdefault(_LOCAL_TOTALS, {})
    if not isinstance(totals, dict):
        raise ValueError("local traffic totals are invalid")
    totals[user.uuid] = local_traffic_total(state, user) + _counter(delta)


def _node_usage(state: AppState, user: User) -> int:
    contributions = state.install.get(_NODE_TOTALS, {})
    if not isinstance(contributions, dict):
        return 0
    epoch = traffic_reset_epoch(state, user)
    total = 0
    for by_user in contributions.values():
        if not isinstance(by_user, dict):
            continue
        entry = by_user.get(user.uuid, {})
        if not isinstance(entry, dict) or _counter(entry.get("reset_epoch")) != epoch:
            continue
        total += _counter(entry.get("used_bytes"))
    retired = state.install.get(_RETIRED_TOTALS, {})
    if isinstance(retired, dict):
        total += _counter(retired.get(user.uuid, 0))
    return total


def recompute_user_traffic_totals(state: AppState) -> None:
    for user in state.users:
        user.traffic_used_bytes = local_traffic_total(state, user) + _node_usage(state, user)


def apply_node_traffic_reports(
    state: AppState,
    reports: Iterable[NodeTrafficReport],
) -> None:
    """Store the newest absolute sample for each node/user/epoch tuple."""
    users = {user.uuid: user for user in state.users}
    contributions = state.install.setdefault(_NODE_TOTALS, {})
    if not isinstance(contributions, dict):
        raise ValueError("node traffic contributions are invalid")
    for report in reports:
        report.validate()
        by_user = contributions.setdefault(report.node_id, {})
        if not isinstance(by_user, dict):
            raise ValueError("node traffic contribution is invalid")
        for user_id, usage in report.users.items():
            user = users.get(user_id)
            if user is None or usage.reset_epoch != traffic_reset_epoch(state, user):
                continue
            previous = by_user.get(user_id, {})
            previous_epoch = _counter(previous.get("reset_epoch")) if isinstance(previous, dict) else 0
            previous_bytes = _counter(previous.get("used_bytes")) if isinstance(previous, dict) else 0
            used_bytes = max(previous_bytes, usage.used_bytes) if previous_epoch == usage.reset_epoch else usage.used_bytes
            by_user[user_id] = {
                "reset_epoch": usage.reset_epoch,
                "used_bytes": used_bytes,
            }
    recompute_user_traffic_totals(state)


def reset_node_traffic_for_user(state: AppState, user: User) -> int:
    """Advance the base-owned epoch and clear local/current/retired usage."""
    epoch = traffic_reset_epoch(state, user) + 1
    set_traffic_reset_epoch(state, user, epoch)
    local = state.install.setdefault(_LOCAL_TOTALS, {})
    retired = state.install.setdefault(_RETIRED_TOTALS, {})
    contributions = state.install.setdefault(_NODE_TOTALS, {})
    if not all(isinstance(item, dict) for item in (local, retired, contributions)):
        raise ValueError("traffic accounting state is invalid")
    local[user.uuid] = 0
    retired[user.uuid] = 0
    for by_user in contributions.values():
        if isinstance(by_user, dict) and user.uuid in by_user:
            by_user[user.uuid] = {"reset_epoch": epoch, "used_bytes": 0}
    user.traffic_used_bytes = 0
    return epoch


def retire_node_traffic(state: AppState, node_id: str) -> None:
    """Keep already-counted bytes when a node is permanently removed."""
    contributions = state.install.setdefault(_NODE_TOTALS, {})
    retired = state.install.setdefault(_RETIRED_TOTALS, {})
    if not isinstance(contributions, dict) or not isinstance(retired, dict):
        raise ValueError("traffic accounting state is invalid")
    by_user = contributions.pop(node_id, {})
    if isinstance(by_user, dict):
        for user_id, entry in by_user.items():
            if isinstance(entry, dict):
                retired[user_id] = _counter(retired.get(user_id, 0)) + _counter(entry.get("used_bytes"))
    recompute_user_traffic_totals(state)


__all__ = [
    "apply_node_traffic_reports",
    "local_traffic_total",
    "record_local_traffic_delta",
    "recompute_user_traffic_totals",
    "reset_node_traffic_for_user",
    "retire_node_traffic",
    "set_traffic_reset_epoch",
    "sync_local_traffic_from_credentials",
    "traffic_reset_epoch",
]
