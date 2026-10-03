"""Restart-safe local and remote byte accounting for managed nodes."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from hydra.contracts.managed_node_observations import TrafficSample
from hydra.core.state_models import AppState, User

_LOCAL_TOTALS = "local_user_traffic_totals"
_NODE_TOTALS = "managed_node_usage_contributions"
_RETIRED_TOTALS = "managed_node_retired_usage"
_RESET_EPOCHS = "managed_node_user_reset_epochs"
_NODE_BASELINES = "managed_node_traffic_baselines"


def _counter(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def _context_total(context: object) -> int:
    """Read cumulative context usage as a high-water mark across counter epochs."""
    if not isinstance(context, dict):
        return 0
    epochs = context.get("epochs", {})
    if not isinstance(epochs, dict):
        return 0
    return max((_counter(value) for value in epochs.values()), default=0)


def traffic_reset_epoch(state: AppState, user: User) -> int:
    epochs = state.install.get(_RESET_EPOCHS, {})
    return _counter(epochs.get(user.uuid, 0)) if isinstance(epochs, dict) else 0


def local_traffic_total(state: AppState, user: User) -> int:
    totals = state.install.setdefault(_LOCAL_TOTALS, {})
    if not isinstance(totals, dict):
        raise ValueError("local managed-node traffic totals are invalid")
    if user.uuid not in totals:
        credentials = sum(
            _counter(stats.get("traffic_used_bytes", 0))
            for stats in user.credentials.values()
            if isinstance(stats, dict)
        )
        totals[user.uuid] = max(_counter(user.traffic_used_bytes), credentials)
    return _counter(totals[user.uuid])


def sync_local_traffic_from_credentials(state: AppState, user: User) -> None:
    state.install.setdefault(_LOCAL_TOTALS, {})[user.uuid] = max(
        local_traffic_total(state, user),
        sum(
            _counter(stats.get("traffic_used_bytes", 0))
            for stats in user.credentials.values()
            if isinstance(stats, dict)
        ),
    )


def record_local_traffic_delta(state: AppState, user: User, delta: int) -> None:
    totals = state.install.setdefault(_LOCAL_TOTALS, {})
    totals[user.uuid] = local_traffic_total(state, user) + _counter(delta)


def apply_traffic_samples(state: AppState, node_id: str, samples: Iterable[TrafficSample]) -> None:
    """Store cumulative context totals, taking a high-water mark across counter epochs."""
    users = {user.uuid: user for user in state.users}
    all_nodes = state.install.setdefault(_NODE_TOTALS, {})
    if not isinstance(all_nodes, dict):
        raise ValueError("managed-node traffic contribution state is invalid")
    by_user = all_nodes.setdefault(node_id, {})
    for sample in samples:
        sample.validate()
        if sample.kind not in {"direct", "cascade_entry"}:
            continue
        user = users.get(sample.uuid)
        if user is None or sample.reset_epoch != traffic_reset_epoch(state, user):
            continue
        contexts = by_user.setdefault(sample.uuid, {})
        entry = contexts.setdefault(sample.context_id, {"reset_epoch": sample.reset_epoch, "epochs": {}})
        if entry.get("reset_epoch") != sample.reset_epoch:
            entry.clear()
            entry.update({"reset_epoch": sample.reset_epoch, "epochs": {}})
        epochs = entry.setdefault("epochs", {})
        epochs[sample.counter_epoch] = max(_counter(epochs.get(sample.counter_epoch)), sample.used_bytes)
    recompute_user_traffic_totals(state)


def recompute_user_traffic_totals(state: AppState) -> None:
    nodes = state.install.get(_NODE_TOTALS, {})
    retired = state.install.get(_RETIRED_TOTALS, {})
    for user in state.users:
        epoch = traffic_reset_epoch(state, user)
        remote = (
            _counter(retired.get(user.uuid, {}).get("used_bytes"))
            if isinstance(retired, dict)
            and isinstance(retired.get(user.uuid), dict)
            and retired[user.uuid].get("reset_epoch") == epoch
            else 0
        )
        if isinstance(nodes, dict):
            for by_user in nodes.values():
                contexts = by_user.get(user.uuid, {}) if isinstance(by_user, dict) else {}
                if not isinstance(contexts, dict):
                    continue
                for context in contexts.values():
                    if isinstance(context, dict) and context.get("reset_epoch") == epoch:
                        remote += _context_total(context)
        user.traffic_used_bytes = local_traffic_total(state, user) + remote


def reset_managed_node_traffic(state: AppState, user: User) -> int:
    epoch = traffic_reset_epoch(state, user) + 1
    state.install.setdefault(_RESET_EPOCHS, {})[user.uuid] = epoch
    state.install.setdefault(_LOCAL_TOTALS, {})[user.uuid] = 0
    state.install.setdefault(_RETIRED_TOTALS, {})[user.uuid] = {"reset_epoch": epoch, "used_bytes": 0}
    for by_user in state.install.setdefault(_NODE_TOTALS, {}).values():
        if isinstance(by_user, dict) and user.uuid in by_user:
            by_user[user.uuid] = {}
    user.traffic_used_bytes = 0
    return epoch


def retire_node_traffic(state: AppState, node_id: str) -> None:
    nodes = state.install.setdefault(_NODE_TOTALS, {})
    retired = state.install.setdefault(_RETIRED_TOTALS, {})
    if not isinstance(nodes, dict) or not isinstance(retired, dict):
        raise ValueError("managed-node traffic accounting state is invalid")
    by_user = nodes.pop(node_id, {})
    current_epochs = {user.uuid: traffic_reset_epoch(state, user) for user in state.users}
    if isinstance(by_user, dict):
        for user_id, contexts in by_user.items():
            entry = retired.get(user_id, {})
            old_epoch = _counter(entry.get("reset_epoch")) if isinstance(entry, dict) else None
            epoch = current_epochs.get(user_id, old_epoch)
            if epoch is None:
                epoch = (
                    max(
                        (
                            _counter(context.get("reset_epoch"))
                            for context in contexts.values()
                            if isinstance(context, dict)
                        ),
                        default=0,
                    )
                    if isinstance(contexts, dict)
                    else 0
                )
            usage = _counter(entry.get("used_bytes")) if isinstance(entry, dict) and old_epoch == epoch else 0
            if isinstance(contexts, dict):
                for context in contexts.values():
                    if isinstance(context, dict) and context.get("reset_epoch") == epoch:
                        usage += _context_total(context)
            retired[user_id] = {"reset_epoch": epoch, "used_bytes": usage}
    recompute_user_traffic_totals(state)


def read_node_counters(state: AppState, *, protocols) -> list[tuple[str, str, int]]:
    """Read plugin-owned counters before taking the state storage lock."""
    users = {user.email: user for user in state.users}
    counters: list[tuple[str, str, int]] = []
    for plugin in protocols.list():
        name = plugin.meta.name
        desired = state.protocols.get(name)
        if plugin.meta.category.value != "transport" or not desired or not desired.enabled:
            continue
        try:
            snapshot = protocols.traffic_snapshot(state, name)
        except Exception:
            continue
        if snapshot is None:
            continue
        counters.extend(
            (users[email].uuid, name, raw)
            for email, raw in snapshot.items()
            if email in users and type(raw) is int and raw >= 0
        )
    return counters


def record_node_counters(
    state: AppState,
    counters: Iterable[tuple[str, str, int]],
    *,
    runtime_id: str,
) -> list[TrafficSample]:
    """Emit cumulative per-context bytes; counter_epoch identifies the raw counter lifecycle."""
    if not isinstance(runtime_id, str) or not runtime_id:
        raise ValueError("managed-node runtime identity is required for counter persistence")
    baselines = state.install.setdefault(_NODE_BASELINES, {})
    if not isinstance(baselines, dict):
        raise ValueError("managed-node traffic baselines are invalid")
    users = {user.uuid: user for user in state.users}
    result: list[TrafficSample] = []
    for user_id, protocol, raw in counters:
        user = users.get(user_id)
        if user is None or type(raw) is not int or raw < 0:
            continue
        reset_epoch = traffic_reset_epoch(state, user)
        key = f"{user.uuid}:{protocol}"
        previous = baselines.get(key, {})
        prior_used = _counter(previous.get("used_bytes")) if isinstance(previous, dict) else 0
        prior_raw = _counter(previous.get("raw_bytes")) if isinstance(previous, dict) else 0
        if not isinstance(previous, dict) or not previous:
            counter_epoch, used_bytes = _counter_epoch(runtime_id, user.uuid, protocol), raw
        elif previous.get("reset_epoch") != reset_epoch:
            counter_epoch, used_bytes = _counter_epoch(runtime_id, user.uuid, protocol), 0
        elif previous.get("runtime_id") != runtime_id:
            counter_epoch, used_bytes = _counter_epoch(runtime_id, user.uuid, protocol), prior_used + raw
        elif raw < prior_raw:
            counter_epoch = _counter_epoch(
                runtime_id, user.uuid, protocol, str(previous.get("counter_epoch") or "reset")
            )
            used_bytes = prior_used + raw
        else:
            counter_epoch = str(previous.get("counter_epoch") or _counter_epoch(runtime_id, user.uuid, protocol))
            used_bytes = prior_used + raw - prior_raw
        baselines[key] = {
            "reset_epoch": reset_epoch,
            "runtime_id": runtime_id,
            "counter_epoch": counter_epoch,
            "raw_bytes": raw,
            "used_bytes": used_bytes,
        }
        result.append(TrafficSample(user.uuid, protocol, "direct", reset_epoch, counter_epoch, used_bytes))
    for user in state.users:
        local_total = sum(
            _counter(value.get("used_bytes"))
            for key, value in baselines.items()
            if isinstance(key, str)
            and key.startswith(f"{user.uuid}:")
            and isinstance(value, dict)
            and value.get("reset_epoch") == traffic_reset_epoch(state, user)
        )
        user.traffic_used_bytes = max(user.traffic_used_bytes, local_total)
    return result


def project_node_counters(
    state: AppState,
    counters: Iterable[tuple[str, str, int]],
    *,
    runtime_id: str,
) -> list[TrafficSample]:
    """Project current absolute samples without changing state or baselines."""
    baselines = state.install.get(_NODE_BASELINES, {})
    if not isinstance(baselines, dict):
        raise ValueError("managed-node traffic baselines are invalid")
    users = {user.uuid: user for user in state.users}
    result = []
    for user_id, protocol, raw in counters:
        user = users.get(user_id)
        if user is None or type(raw) is not int or raw < 0:
            continue
        reset_epoch = traffic_reset_epoch(state, user)
        previous = baselines.get(f"{user.uuid}:{protocol}", {})
        prior_used = _counter(previous.get("used_bytes")) if isinstance(previous, dict) else 0
        prior_raw = _counter(previous.get("raw_bytes")) if isinstance(previous, dict) else 0
        if not isinstance(previous, dict) or not previous:
            counter_epoch, used = _counter_epoch(runtime_id, user.uuid, protocol), raw
        elif previous.get("reset_epoch") != reset_epoch:
            counter_epoch, used = _counter_epoch(runtime_id, user.uuid, protocol), 0
        elif previous.get("runtime_id") != runtime_id:
            counter_epoch, used = _counter_epoch(runtime_id, user.uuid, protocol), prior_used + raw
        elif raw < prior_raw:
            counter_epoch = _counter_epoch(
                runtime_id, user.uuid, protocol, str(previous.get("counter_epoch") or "reset")
            )
            used = prior_used + raw
        else:
            counter_epoch = str(previous.get("counter_epoch") or _counter_epoch(runtime_id, user.uuid, protocol))
            used = prior_used + raw - prior_raw
        result.append(TrafficSample(user.uuid, protocol, "direct", reset_epoch, counter_epoch, used))
    return result


def collect_node_samples(state: AppState, *, protocols, runtime_id: str) -> list[TrafficSample]:
    """Collect a committed counter sample into the caller's state."""
    return record_node_counters(state, read_node_counters(state, protocols=protocols), runtime_id=runtime_id)


def _counter_epoch(runtime_id: str, user_id: str, protocol: str, previous: str = "") -> str:
    value = hashlib.sha256(f"{runtime_id}:{user_id}:{protocol}:{previous}".encode()).hexdigest()[:16]
    return value


__all__ = [
    "apply_traffic_samples",
    "collect_node_samples",
    "local_traffic_total",
    "read_node_counters",
    "record_node_counters",
    "record_local_traffic_delta",
    "recompute_user_traffic_totals",
    "reset_managed_node_traffic",
    "retire_node_traffic",
    "sync_local_traffic_from_credentials",
    "traffic_reset_epoch",
]
