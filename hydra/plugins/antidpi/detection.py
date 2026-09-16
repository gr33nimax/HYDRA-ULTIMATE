"""Decision core for the AntiScan evidence contract.

The detector mutates only the supplied dictionary.  Firewall enforcement,
notifications, locking, and persistence remain explicit caller decisions.

There is no score, no evidence family and no correlation window: an event is
either a proven protocol reject / decoy scan, or it does not exist.  Anything
outside the allowlist below is discarded before it can reach state, the
firewall or a notification.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass

from hydra.plugins.antidpi.model import (
    MAX_HISTORY_ENTRIES,
    active_bans,
    expire_bans,
    get_ban_duration,
    prune_runtime_state,
)

MAX_EVENT_TIME_SKEW = 5.0

# --- closed evidence allowlist -------------------------------------------

PROTOCOL_REJECT_KIND = "protocol_reject"
DECOY_SCAN_KIND = "decoy_scan"

# protocol -> reasons a protocol-owned parser may report, and the sources
# allowed to report them.  A protocol absent here can never enforce.
PROTOCOL_REJECT_RULES: dict[str, frozenset[str]] = {
    "snell": frozenset({"record_auth_failed"}),
}
PROTOCOL_REJECT_SOURCES = frozenset({"journal", "caddy-source-relay"})

DECOY_REASONS = frozenset({"scanner_path"})
DECOY_PROTOCOLS = frozenset({"https"})
DECOY_SOURCES = frozenset({"caddy-decoy"})

ATTRIBUTIONS = frozenset({"direct", "relay-exact"})


def evidence_problem(event: object) -> str:
    """Return why ``event`` is not enforcement evidence, or ``""`` if it is."""
    if not isinstance(event, dict):
        return "not a mapping"
    kind = str(event.get("kind", "")).strip()
    attribution = str(event.get("attribution", "")).strip()
    if attribution not in ATTRIBUTIONS:
        return "unproven attribution"
    if kind == PROTOCOL_REJECT_KIND:
        protocol = str(event.get("protocol", "")).strip().lower()
        allowed = PROTOCOL_REJECT_RULES.get(protocol)
        if allowed is None:
            return f"protocol {protocol or '?'} has no proven reject"
        if str(event.get("reason", "")).strip() not in allowed:
            return "reason is not a proven reject"
        if str(event.get("source", "")).strip() not in PROTOCOL_REJECT_SOURCES:
            return "source is not a proven reject stream"
        return ""
    if kind == DECOY_SCAN_KIND:
        if str(event.get("protocol", "")).strip().lower() not in DECOY_PROTOCOLS:
            return "decoy scan protocol mismatch"
        if str(event.get("reason", "")).strip() not in DECOY_REASONS:
            return "decoy scan reason mismatch"
        if str(event.get("source", "")).strip() not in DECOY_SOURCES:
            return "source is not a decoy surface"
        return ""
    return f"kind {kind or '?'} is not enforcement evidence"


def is_enforcement_evidence(event: object) -> bool:
    """Return whether one event may start an automatic ban."""
    return evidence_problem(event) == ""


def event_time(event: dict) -> float | None:
    """Return the original event time when plausible, else ``None``."""
    try:
        timestamp = float(event.get("event_time", 0) or 0)
    except (TypeError, ValueError):
        return None
    if timestamp <= 0 or timestamp > time.time() + MAX_EVENT_TIME_SKEW:
        return None
    return timestamp


@dataclass
class Observation:
    """Computed decision and the mutable evidence entry behind it."""

    address: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    event: dict
    timestamp: float
    enforced_at: float
    source: str
    signals: tuple[str, ...]
    entry: dict
    active_ban: bool
    should_ban: bool


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from untrusted persisted state, or ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return int(value.strip())
        except (TypeError, ValueError):
            return default
    return default


def _evidence_signal(event: dict) -> str:
    """Return the single human-readable signal name of one evidence event."""
    protocol = str(event.get("protocol", "unknown"))[:40]
    reason = str(event.get("reason", event.get("kind", "unknown")))[:60]
    return f"{protocol}:{reason}"


def _existing_ban(data: dict, address: str, timestamp: float) -> bool:
    try:
        return address in active_bans(data, now=timestamp)
    except (TypeError, ValueError):
        return False


def observe_state(
    data: dict,
    parsed_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    event: dict,
    *,
    timestamp: float,
    enforcement_time: float | None = None,
    max_score_entries: int,
) -> Observation:
    """Decide whether one proven evidence event must ban its address."""
    address = parsed_address.compressed
    enforced_at = timestamp if enforcement_time is None else enforcement_time
    source = str(event.get("source", "unknown"))[:80]
    entry = {
        "signals": [_evidence_signal(event)],
        "last_evidence_at": timestamp,
    }
    event_count = _as_int(data.get("events", 0)) + 1
    data["events"] = event_count
    data["last_event_at"] = timestamp
    data["last_event_source"] = source
    if event_count % 256 == 0:
        expire_bans(data, now=enforced_at)
        prune_runtime_state(
            data,
            now=enforced_at,
            max_entries=max_score_entries,
        )
    active_ban = _existing_ban(data, address, enforced_at)
    return Observation(
        address=address,
        ip=parsed_address,
        event=event,
        timestamp=timestamp,
        enforced_at=enforced_at,
        source=source,
        signals=(_evidence_signal(event),),
        entry=entry,
        active_ban=active_ban,
        should_ban=not active_ban,
    )


def record_automatic_ban(
    data: dict,
    observation: Observation,
    *,
    duration: int | None = None,
) -> dict:
    """Commit a successful firewall ban into persistent state."""
    address = observation.address
    ban_counts = data.setdefault("ban_counts", {})
    if not isinstance(ban_counts, dict):
        ban_counts = {}
        data["ban_counts"] = ban_counts
    offense_count = _as_int(ban_counts.get(address, 0)) + 1
    duration = get_ban_duration(offense_count) if duration is None else max(0, _as_int(duration))
    ban_counts[address] = offense_count
    event = observation.event
    metadata = {
        "at": observation.enforced_at,
        "signals": observation.entry["signals"],
        "source": observation.source,
        "protocol": str(event.get("protocol", "unknown"))[:40],
        "kind": str(event.get("kind", event.get("reason", "anomaly")))[:80],
        "reason": str(event.get("reason", ""))[:80],
        "attribution": str(event.get("attribution", ""))[:20],
        "duration": duration,
        "offense_count": offense_count,
    }
    banned = data.setdefault("banned", {})
    if not isinstance(banned, dict):
        banned = {}
        data["banned"] = banned
    banned[address] = metadata
    history = data.setdefault("history", [])
    if not isinstance(history, list):
        history = []
    history.append({"ip": address, **metadata, "status": "active"})
    data["history"] = history[-MAX_HISTORY_ENTRIES:]
    return metadata
