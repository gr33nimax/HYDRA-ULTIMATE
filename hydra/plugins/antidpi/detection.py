"""State transition model for one AntiDPI observation.

The detector mutates only the supplied dictionary.  Firewall enforcement,
notifications, locking, and persistence remain explicit caller decisions.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

from hydra.plugins.antidpi.correlation import (
    active_families,
    block_reason,
    event_weight,
    record_families,
    record_subnet_activity,
    required_score,
)
from hydra.plugins.antidpi.model import (
    ALERT_COOLDOWN,
    ALERT_THRESHOLD,
    AUTH_ALERT_THRESHOLD,
    BAN_THRESHOLD,
    MAX_HISTORY_ENTRIES,
    MAX_OBSERVED_SCORE,
    active_bans,
    ban_duration,
    decayed_score,
    expire_bans,
    get_ban_duration,
    prune_runtime_state,
    score_event,
)

MAX_EVENT_TIME_SKEW = 5.0


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
    evidence_can_ban: bool
    active_ban: bool
    should_alert: bool
    should_ban: bool
    families: tuple[str, ...] = ()
    required_score: float = float(BAN_THRESHOLD)
    block_reason: str = ""
    coordinated: dict = field(default_factory=dict)


def _kernel_context(entry: dict, event: dict, timestamp: float) -> None:
    """Record kernel scan context without ever raising attribution.

    Kernel SYN/NEW and UDP telemetry describes spoofable packets: the log
    proves a packet was seen, not that the sender owns the source address.
    Accumulating distinct ports therefore stays observability and can never
    upgrade an event into ban-eligible evidence.
    """
    if str(event.get("source", "")) != "kernel-firewall":
        return
    try:
        destination_port = int(event.get("destination_port", 0))
    except (TypeError, ValueError):
        destination_port = 0
    recent_ports = entry.get("kernel_ports", {})
    if not isinstance(recent_ports, dict):
        recent_ports = {}
    recent_ports = {
        str(port): seen_at
        for port, seen_at in recent_ports.items()
        if isinstance(seen_at, (int, float))
        and timestamp - float(seen_at) <= 60
    }
    if 1 <= destination_port <= 65535:
        recent_ports[str(destination_port)] = timestamp
    entry["kernel_ports"] = dict(list(recent_ports.items())[-64:])
    event["distinct_ports_60s"] = len(recent_ports)
    event["ban_eligible"] = False
    event["policy"] = "alert-only / unverified kernel source"


def _apply_attribution_policy(event: dict, signals: tuple[str, ...]) -> None:
    """Keep compatibility-class TLS failures out of enforcement.

    ``unknown_sni`` and ``handshake_failure`` alone describe old clients,
    latency probes, and DPI middleboxes, not an attacker.  The decision is a
    detector policy, so it lives here rather than in a caller facade.
    """
    if signals and set(signals) <= {"unknown_sni", "handshake_failure"}:
        event["ban_eligible"] = False
        event["policy"] = "alert-only / TLS compatibility or latency probe"


def _update_score(
    entry: dict,
    event: dict,
    timestamp: float,
) -> tuple[tuple[str, ...], bool]:
    _raw_score, signals = score_event(event)
    _apply_attribution_policy(event, signals)
    evidence_can_ban = event.get("ban_eligible") is not False
    source = str(event.get("source", "unknown"))[:80]
    previous_at = float(entry.get("updated", timestamp) or timestamp)
    out_of_order = timestamp < previous_at
    if (
        source not in {"kernel-firewall", "kernel-udp-probe"}
        and signals
        and evidence_can_ban
        and not out_of_order
    ):
        entry["last_non_kernel_evidence_at"] = timestamp
    if "port_sweep" in signals and evidence_can_ban and not out_of_order:
        entry["last_port_sweep_at"] = timestamp

    previous = float(entry.get("score", 0))
    previous_verified = float(entry.get("verified_score", 0))
    last_unknown_sni = float(entry.get("last_unknown_sni_at", 0) or 0)
    # Repeated evidence of one kind saturates: the tenth identical handshake
    # error carries far less information than the first.
    score = event_weight(
        entry if not out_of_order else {},
        signals,
        timestamp=timestamp,
    )
    if signals and set(signals) <= {"unknown_sni", "handshake_failure"}:
        if timestamp - last_unknown_sni < 0.5:
            score = 0.0
        else:
            entry["last_unknown_sni_at"] = timestamp
    if signals and evidence_can_ban and not out_of_order:
        record_families(entry, signals, timestamp=timestamp)

    updated = max(timestamp, previous_at)
    elapsed = max(0.0, timestamp - previous_at)
    contribution_age = max(0.0, updated - timestamp)
    score = decayed_score(score, contribution_age)
    entry["score"] = round(
        min(MAX_OBSERVED_SCORE, decayed_score(previous, elapsed) + score),
        4,
    )
    entry["verified_score"] = round(
        min(
            MAX_OBSERVED_SCORE,
            decayed_score(previous_verified, elapsed)
            + (score if evidence_can_ban else 0.0),
        ),
        4,
    )
    previous_signals = entry.get("signals", [])
    if not isinstance(previous_signals, list):
        previous_signals = [str(previous_signals)] if previous_signals else []
    entry["signals"] = list(
        dict.fromkeys([*previous_signals, *signals]),
    )[-16:]
    entry["updated"] = updated
    return signals, evidence_can_ban


def _record_event_counters(
    data: dict,
    *,
    source: str,
    signals: tuple[str, ...],
    timestamp: float,
) -> None:
    data["events"] = int(data.get("events", 0)) + 1
    source_counts = data.setdefault("source_counts", {})
    if not isinstance(source_counts, dict):
        source_counts = {}
        data["source_counts"] = source_counts
    source_counts[source] = int(source_counts.get(source, 0)) + 1
    signal_counts = data.setdefault("signal_counts", {})
    if not isinstance(signal_counts, dict):
        signal_counts = {}
        data["signal_counts"] = signal_counts
    for signal in signals:
        signal_counts[signal] = int(signal_counts.get(signal, 0)) + 1
    previous = float(data.get("last_event_at", 0) or 0)
    if timestamp >= previous:
        data["last_event_at"] = timestamp
        data["last_event_source"] = source


def _resolve_active_ban(data: dict, address: str, timestamp: float) -> bool:
    banned = data.setdefault("banned", {})
    if not isinstance(banned, dict):
        banned = {}
        data["banned"] = banned
    metadata = banned.get(address)
    if not isinstance(metadata, dict):
        return False
    try:
        active = (
            metadata.get("permanent") is True
            or timestamp < float(metadata.get("at", 0)) + ban_duration(metadata)
        )
    except (TypeError, ValueError):
        active = False
    if active:
        return True
    banned.pop(address, None)
    history = data.get("history", [])
    if not isinstance(history, list):
        return False
    for item in reversed(history):
        if (
            isinstance(item, dict)
            and item.get("ip") == address
            and item.get("status") == "active"
        ):
            item["status"] = "expired"
            item["expired_at"] = timestamp
            break
    return False


def _should_alert(
    entry: dict,
    event: dict,
    signals: tuple[str, ...],
    *,
    timestamp: float,
    active_ban: bool,
    evidence_can_ban: bool,
    score: float | None = None,
) -> bool:
    protocol_key = str(event.get("protocol", "L4"))[:40].lower()
    protocol_alerts = entry.get("protocol_alerts", {})
    if not isinstance(protocol_alerts, dict):
        protocol_alerts = {}
    protocol_alerts = {
        str(key): float(value)
        for key, value in protocol_alerts.items()
        if isinstance(value, (int, float))
        and timestamp - float(value) <= ALERT_COOLDOWN * 4
    }
    last_alert_at = float(protocol_alerts.get(protocol_key, 0) or 0)
    threshold = AUTH_ALERT_THRESHOLD if "auth_failure" in signals else ALERT_THRESHOLD
    should_alert = (
        not active_ban
        and bool(signals)
        and (entry["score"] if score is None else score) >= threshold
        and not (
            entry["verified_score"] >= BAN_THRESHOLD
            and evidence_can_ban
        )
        and timestamp - last_alert_at >= ALERT_COOLDOWN
    )
    if should_alert:
        entry["last_alert_at"] = timestamp
        protocol_alerts[protocol_key] = timestamp
        entry["protocol_alerts"] = protocol_alerts
    return should_alert


def observe_state(
    data: dict,
    parsed_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    event: dict,
    *,
    timestamp: float,
    enforcement_time: float | None = None,
    max_score_entries: int,
) -> Observation:
    """Apply one evidence event and return its side-effect decision."""
    address = parsed_address.compressed
    enforced_at = timestamp if enforcement_time is None else enforcement_time
    scores = data.setdefault("scores", {})
    if not isinstance(scores, dict):
        scores = {}
        data["scores"] = scores
    entry = scores.setdefault(
        address,
        {
            "score": 0,
            "signals": [],
            "updated": 0,
            "last_unknown_sni_at": 0,
        },
    )
    if not isinstance(entry, dict):
        entry = {}
        scores[address] = entry
    _kernel_context(entry, event, timestamp)
    signals, evidence_can_ban = _update_score(entry, event, timestamp)
    source = str(event.get("source", "unknown"))[:80]
    _record_event_counters(
        data,
        source=source,
        signals=signals,
        timestamp=timestamp,
    )
    event_count = int(data.get("events", 0))
    if event_count % 256 == 0:
        expire_bans(data, now=enforced_at)
    if len(scores) > max_score_entries or event_count % 256 == 0:
        prune_runtime_state(
            data,
            now=enforced_at,
            max_entries=max_score_entries,
        )
    active_ban = _resolve_active_ban(data, address, enforced_at)
    decision_observed = decayed_score(
        float(entry["score"]),
        max(0.0, enforced_at - float(entry.get("updated", timestamp))),
    )
    decision_verified = decayed_score(
        float(entry["verified_score"]),
        max(0.0, enforced_at - float(entry.get("updated", timestamp))),
    )
    should_alert = _should_alert(
        entry,
        event,
        signals,
        timestamp=enforced_at,
        active_ban=active_ban,
        evidence_can_ban=evidence_can_ban,
        score=decision_observed,
    )
    coordinated = (
        record_subnet_activity(data, address, timestamp=timestamp)
        if signals and evidence_can_ban
        else {}
    )
    families = active_families(entry, timestamp=enforced_at)
    threshold = required_score(
        families=families,
        signals=signals,
        offense_count=_offense_count(data, address),
    )
    should_ban = (
        not active_ban
        and decision_verified >= threshold
        and evidence_can_ban
    )
    return Observation(
        address=address,
        ip=parsed_address,
        event=event,
        timestamp=timestamp,
        enforced_at=enforced_at,
        source=source,
        signals=signals,
        entry=entry,
        evidence_can_ban=evidence_can_ban,
        active_ban=active_ban,
        should_alert=should_alert,
        should_ban=should_ban,
        families=families,
        required_score=threshold,
        block_reason=(
            ""
            if should_ban or active_ban
            else block_reason(
                score=float(entry["verified_score"]),
                required=threshold,
                families=families,
                evidence_can_ban=evidence_can_ban,
            )
        ),
        coordinated=coordinated,
    )


def _offense_count(data: dict, address: str) -> int:
    """Return how many times this address was banned before."""
    counts = data.get("ban_counts", {}) if isinstance(data, dict) else {}
    if not isinstance(counts, dict):
        return 0
    try:
        return max(0, int(counts.get(address, 0) or 0))
    except (TypeError, ValueError):
        return 0


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
    offense_count = int(ban_counts.get(address, 0)) + 1
    duration = (
        get_ban_duration(offense_count)
        if duration is None
        else max(0, int(duration))
    )
    ban_counts[address] = offense_count
    event = observation.event
    metadata = {
        "at": observation.enforced_at,
        "score": observation.entry["verified_score"],
        "signals": observation.entry["signals"],
        "source": observation.source,
        "protocol": str(event.get("protocol", "unknown"))[:40],
        "kind": str(event.get("kind", event.get("reason", "anomaly")))[:80],
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
