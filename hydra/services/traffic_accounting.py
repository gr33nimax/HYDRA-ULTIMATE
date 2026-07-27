"""Protocol-neutral state updates for connection traffic snapshots."""
from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any

from hydra.core.source_relay import resolve_mapping
from hydra.core.state_models import AppState
from hydra.services.traffic_attribution import (
    DEFAULT_ATTRIBUTOR,
    ConnectionAttributor,
    TrafficEvidence,
)


def apply_connection_snapshot(
    state: AppState,
    connections: Sequence[dict[str, Any]],
    evidence: TrafficEvidence,
    *,
    attributor: ConnectionAttributor = DEFAULT_ATTRIBUTOR,
    now: Callable[[], float] = time.time,
) -> bool:
    """Apply monotonic deltas while retaining a short tombstone window."""
    timestamp = now()
    state.install["traffic_daemon_last_poll"] = timestamp
    active = state.install.setdefault("traffic_connection_counters", {})
    current_ids: set[str] = set()
    deltas: dict[tuple[str, str], int] = {}

    for connection in connections:
        connection_id = str(connection.get("id") or "")
        if not connection_id:
            continue
        current_ids.add(connection_id)
        identity = attributor.identify(connection, state, evidence)

        upload = max(0, int(connection.get("upload", 0)))
        download = max(0, int(connection.get("download", 0)))
        total = upload + download
        previous = active.get(connection_id, {})
        old_total = int(previous.get("total", 0))
        user = identity.user or str(previous.get("user") or "")
        protocol = identity.protocol
        if protocol == "unknown" and previous.get("protocol"):
            protocol = str(previous["protocol"])
        credited = int(
            previous.get(
                "credited_total",
                old_total if previous.get("user") else 0,
            ),
        )
        if total < old_total:
            # A reused id or reset runtime counter begins a new generation.
            credited = 0
        delta = (
            max(0, total - credited)
            if user and protocol != "unknown"
            else 0
        )
        metadata = connection.get("metadata", {})
        active[connection_id] = {
            "user": user,
            "protocol": protocol,
            "total": total,
            "upload": upload,
            "download": download,
            "credited_total": total if delta else credited,
            "missed_polls": 0,
            "seen_at": timestamp,
            # The source address is what a device looks like on the data path;
            # device limits and the device view both read it from here.
            "address": _source_address(metadata or {}, protocol, previous),
        }
        if delta:
            key = (user, protocol)
            deltas[key] = deltas.get(key, 0) + delta

    for connection_id in set(active) - current_ids:
        record = active[connection_id]
        record["missed_polls"] = int(record.get("missed_polls", 0)) + 1
        if record["missed_polls"] > 5:
            active.pop(connection_id, None)

    for (email, protocol), delta in deltas.items():
        user = next(
            (candidate for candidate in state.users if candidate.email == email),
            None,
        )
        if user is None:
            continue
        user.traffic_used_bytes += delta
        protocol_stats = user.credentials.setdefault(protocol, {})
        protocol_stats["traffic_used_bytes"] = (
            int(protocol_stats.get("traffic_used_bytes", 0)) + delta
        )
    return bool(deltas)


def _source_address(
    metadata: dict[str, Any],
    protocol: str,
    previous: dict[str, Any],
) -> str:
    """Recover a Caddy-proxied peer through the exact source relay mapping."""
    address = str(metadata.get("sourceIP", "") or "")
    previous_address = str(previous.get("address", "") or "")
    if address not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        return address or previous_address
    try:
        source_port = int(metadata.get("sourcePort", 0) or 0)
    except (TypeError, ValueError):
        source_port = 0
    mapped = (
        resolve_mapping(protocol, source_port)
        if protocol != "unknown" and source_port
        else None
    )
    if mapped:
        return mapped
    if previous_address and previous_address not in (
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
    ):
        return previous_address
    return address or previous_address


__all__ = ["apply_connection_snapshot"]
