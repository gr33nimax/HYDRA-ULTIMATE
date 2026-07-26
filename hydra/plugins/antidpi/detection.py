"""State transition model for one AntiDPI observation.

The detector mutates only the supplied dictionary.  Firewall enforcement,
notifications, locking, and persistence remain explicit caller decisions.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from hydra.plugins.antidpi.model import (
    ALERT_COOLDOWN,
    ALERT_THRESHOLD,
    AUTH_ALERT_THRESHOLD,
    BAN_THRESHOLD,
    MAX_OBSERVED_SCORE,
    active_bans,
    ban_duration,
    decayed_score,
    expire_bans,
    get_ban_duration,
    prune_runtime_state,
    score_event,
)


@dataclass
class Observation:
    """Computed decision and the mutable evidence entry behind it."""

    address: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    event: dict
    timestamp: float
    source: str
    signals: tuple[str, ...]
    entry: dict
    evidence_can_ban: bool
    active_ban: bool
    should_alert: bool
    should_ban: bool


def _kernel_context(entry: dict, event: dict, timestamp: float) -> None:
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
    event["ban_eligible"] = len(recent_ports) >= 4
    if not event["ban_eligible"]:
        event["policy"] = "alert-only / single-port connection burst"


def _update_score(
    entry: dict,
    event: dict,
    timestamp: float,
) -> tuple[tuple[str, ...], bool]:
    score, signals = score_event(event)
    evidence_can_ban = event.get("ban_eligible") is not False
    source = str(event.get("source", "unknown"))[:80]
    if (
        source not in {"kernel-firewall", "kernel-udp-probe"}
        and signals
        and evidence_can_ban
    ):
        entry["last_non_kernel_evidence_at"] = timestamp
    if "port_sweep" in signals and evidence_can_ban:
        entry["last_port_sweep_at"] = timestamp

    previous = float(entry.get("score", 0))
    previous_verified = float(entry.get("verified_score", 0))
    previous_at = float(entry.get("updated", timestamp) or timestamp)
    last_unknown_sni = float(entry.get("last_unknown_sni_at", 0) or 0)
    if signals and set(signals) <= {"unknown_sni", "handshake_failure"}:
        if timestamp - last_unknown_sni < 0.5:
            score = 0.0
        else:
            entry["last_unknown_sni_at"] = timestamp

    elapsed = timestamp - previous_at
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
    entry["updated"] = timestamp
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
        and entry["score"] >= threshold
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
    max_score_entries: int,
) -> Observation:
    """Apply one evidence event and return its side-effect decision."""
    address = parsed_address.compressed
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
        expire_bans(data, now=timestamp)
    if len(scores) > max_score_entries or event_count % 256 == 0:
        prune_runtime_state(
            data,
            now=timestamp,
            max_entries=max_score_entries,
        )
    active_ban = _resolve_active_ban(data, address, timestamp)
    should_alert = _should_alert(
        entry,
        event,
        signals,
        timestamp=timestamp,
        active_ban=active_ban,
        evidence_can_ban=evidence_can_ban,
    )
    should_ban = (
        not active_ban
        and entry["verified_score"] >= BAN_THRESHOLD
        and evidence_can_ban
    )
    return Observation(
        address=address,
        ip=parsed_address,
        event=event,
        timestamp=timestamp,
        source=source,
        signals=signals,
        entry=entry,
        evidence_can_ban=evidence_can_ban,
        active_ban=active_ban,
        should_alert=should_alert,
        should_ban=should_ban,
    )


def record_automatic_ban(data: dict, observation: Observation) -> dict:
    """Commit a successful firewall ban into persistent state."""
    address = observation.address
    ban_counts = data.setdefault("ban_counts", {})
    if not isinstance(ban_counts, dict):
        ban_counts = {}
        data["ban_counts"] = ban_counts
    offense_count = int(ban_counts.get(address, 0)) + 1
    duration = get_ban_duration(offense_count)
    ban_counts[address] = offense_count
    event = observation.event
    metadata = {
        "at": observation.entry["updated"],
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
    data["history"] = history[-1000:]
    return metadata

