"""Evidence correlation for the AntiDPI detector.

The scorer answers "how much evidence is there"; this module answers "how much
*new information* does this event carry, and is it corroborated".

Three pure decisions live here:

* **Saturation.** The tenth identical handshake error is not ten times the
  evidence of the first. Repeats of one signal contribute a decaying share, so
  a broken client cannot grind its way to a ban while a real probe still can.
* **Corroboration.** A ban needs either a decisive signal or evidence from two
  different families. A single family (a mistyped password, one legacy client)
  has to reach a much higher bar before it blocks every port for an address.
* **Coordination.** Probing is routinely spread across one subnet so that no
  single address looks interesting. Aggregating per /24 and /48 makes that
  visible without letting an aggregate ban anyone by itself.

Nothing here touches files, sockets, or the firewall.
"""
from __future__ import annotations

import ipaddress

from hydra.plugins.antidpi.model import BAN_THRESHOLD, SIGNAL_WEIGHTS

SIGNAL_FAMILIES: dict[str, str] = {
    "malformed_tls": "tls_integrity",
    "non_tls_on_tls": "tls_integrity",
    "invalid_first_packet": "tls_integrity",
    "unknown_sni": "tls_negotiation",
    "handshake_failure": "tls_negotiation",
    "protocol_mismatch": "protocol",
    "low_volume_session": "protocol",
    "auth_failure": "auth",
    "port_scan": "scanning",
    "port_sweep": "scanning",
    "connection_burst": "scanning",
    "quic_retry_burst": "scanning",
    "udp_probe": "scanning",
    "active_decoy_probe": "decoy",
    "manual_ban": "manual",
}

# Signals that describe an action no ordinary client performs. They ban alone.
DECISIVE_SIGNALS = frozenset({"active_decoy_probe", "port_sweep"})

REPEAT_WINDOW = 900.0
REPEAT_DECAY = 0.5
MIN_REPEAT_FACTOR = 0.125
MAX_REPEAT_ENTRIES = 24

FAMILY_WINDOW = 900.0
SOLO_FAMILY_FACTOR = 1.5
OFFENDER_THRESHOLD_STEP = 1.0
MIN_BAN_THRESHOLD = 4.0

SUBNET_WINDOW = 600.0
SUBNET_MEMBERS = 4
SUBNET_ALERT_COOLDOWN = 900.0
MAX_SUBNET_ENTRIES = 512
IPV4_PREFIX = 24
IPV6_PREFIX = 48


def signal_family(signal: object) -> str:
    """Return the evidence family of one signal, or its own name."""
    key = str(signal or "").strip()
    return SIGNAL_FAMILIES.get(key, key)


def event_weight(
    entry: dict,
    signals: tuple[str, ...],
    *,
    timestamp: float,
) -> float:
    """Return the saturated weight of one event and update its repeat ledger."""
    hits = entry.get("signal_hits")
    if not isinstance(hits, dict):
        hits = {}
    total = 0.0
    for signal in signals:
        base = SIGNAL_WEIGHTS.get(signal, 0)
        if not base:
            continue
        seen = _recent_repeats(hits.get(signal), timestamp)
        total += base * max(MIN_REPEAT_FACTOR, REPEAT_DECAY**seen)
        hits[signal] = {"count": seen + 1, "at": timestamp}
    entry["signal_hits"] = _prune_repeats(hits, timestamp)
    return round(total, 4)


def _recent_repeats(record: object, timestamp: float) -> int:
    if not isinstance(record, dict):
        return 0
    try:
        last = float(record.get("at", 0) or 0)
        count = int(record.get("count", 0) or 0)
    except (TypeError, ValueError):
        return 0
    if timestamp - last > REPEAT_WINDOW:
        return 0
    return max(0, count)


def _prune_repeats(hits: dict, timestamp: float) -> dict:
    fresh = {
        str(signal): record
        for signal, record in hits.items()
        if isinstance(record, dict)
        and timestamp - float(record.get("at", 0) or 0) <= REPEAT_WINDOW
    }
    if len(fresh) <= MAX_REPEAT_ENTRIES:
        return fresh
    ordered = sorted(
        fresh.items(),
        key=lambda item: float(item[1].get("at", 0) or 0),
        reverse=True,
    )
    return dict(ordered[:MAX_REPEAT_ENTRIES])


def record_families(
    entry: dict,
    signals: tuple[str, ...],
    *,
    timestamp: float,
) -> None:
    """Remember which evidence families produced ban-eligible signals."""
    families = entry.get("families")
    if not isinstance(families, dict):
        families = {}
    for signal in signals:
        family = signal_family(signal)
        if family:
            families[family] = timestamp
    entry["families"] = {
        name: seen
        for name, seen in families.items()
        if isinstance(seen, (int, float))
        and timestamp - float(seen) <= FAMILY_WINDOW
    }


def active_families(entry: dict, *, timestamp: float) -> tuple[str, ...]:
    """Return families whose ban-eligible evidence is still fresh."""
    families = entry.get("families") if isinstance(entry, dict) else None
    if not isinstance(families, dict):
        return ()
    return tuple(
        sorted(
            name
            for name, seen in families.items()
            if isinstance(seen, (int, float))
            and timestamp - float(seen) <= FAMILY_WINDOW
        ),
    )


def ban_threshold(offense_count: object) -> float:
    """Return the base threshold, lowered for addresses banned before."""
    try:
        offenses = max(0, int(offense_count or 0))
    except (TypeError, ValueError):
        offenses = 0
    return max(
        MIN_BAN_THRESHOLD,
        float(BAN_THRESHOLD) - OFFENDER_THRESHOLD_STEP * offenses,
    )


def required_score(
    *,
    families: tuple[str, ...],
    signals: object,
    offense_count: object = 0,
) -> float:
    """Return how much verified evidence this address needs for a ban.

    A decisive signal is sufficient evidence by itself, so it lowers the bar to
    its own weight: reaching the decoy page or sweeping four ports must not
    additionally depend on unrelated companion signals.
    """
    base = ban_threshold(offense_count)
    seen = set(signals or ())
    decisive = seen & DECISIVE_SIGNALS
    if decisive:
        weight = max(SIGNAL_WEIGHTS.get(signal, 0) for signal in decisive)
        return float(min(base, weight))
    if len(families) >= 2:
        return base
    return round(base * SOLO_FAMILY_FACTOR, 4)


def block_reason(
    *,
    score: float,
    required: float,
    families: tuple[str, ...],
    evidence_can_ban: bool,
) -> str:
    """Explain why an address with evidence is not banned yet."""
    if not evidence_can_ban:
        return "unverified_source"
    if score >= required:
        return ""
    if len(families) < 2 and score >= ban_threshold(0):
        return "single_family"
    return "below_threshold"


def subnet_of(address: object) -> str:
    """Return the aggregation prefix of one address, or an empty string."""
    try:
        parsed = ipaddress.ip_address(str(address).strip("[]"))
    except ValueError:
        return ""
    prefix = IPV4_PREFIX if parsed.version == 4 else IPV6_PREFIX
    return str(ipaddress.ip_network(f"{parsed.compressed}/{prefix}", strict=False))


def record_subnet_activity(
    data: dict,
    address: str,
    *,
    timestamp: float,
) -> dict:
    """Aggregate ban-eligible evidence per subnet and report coordination."""
    prefix = subnet_of(address)
    if not prefix:
        return {}
    subnets = data.setdefault("subnets", {})
    if not isinstance(subnets, dict):
        subnets = {}
        data["subnets"] = subnets
    record = subnets.get(prefix)
    if not isinstance(record, dict):
        record = {}
    members = record.get("members")
    if not isinstance(members, dict):
        members = {}
    members = {
        str(member): seen
        for member, seen in members.items()
        if isinstance(seen, (int, float))
        and timestamp - float(seen) <= SUBNET_WINDOW
    }
    members[str(address)] = timestamp
    record["members"] = members
    record["updated"] = timestamp
    subnets[prefix] = record
    data["subnets"] = _prune_subnets(subnets, timestamp)
    return _coordination(record, prefix, timestamp)


def _coordination(record: dict, prefix: str, timestamp: float) -> dict:
    members = record.get("members", {})
    count = len(members) if isinstance(members, dict) else 0
    if count < SUBNET_MEMBERS:
        return {}
    try:
        alerted_at = float(record.get("alerted_at", 0) or 0)
    except (TypeError, ValueError):
        alerted_at = 0.0
    fresh = timestamp - alerted_at >= SUBNET_ALERT_COOLDOWN
    if fresh:
        record["alerted_at"] = timestamp
    return {
        "prefix": prefix,
        "members": count,
        "first_report": fresh,
        "addresses": sorted(members)[:8],
    }


def _prune_subnets(subnets: dict, timestamp: float) -> dict:
    fresh = {
        prefix: record
        for prefix, record in subnets.items()
        if isinstance(record, dict)
        and timestamp - float(record.get("updated", 0) or 0) <= SUBNET_WINDOW
    }
    if len(fresh) <= MAX_SUBNET_ENTRIES:
        return fresh
    ordered = sorted(
        fresh.items(),
        key=lambda item: float(item[1].get("updated", 0) or 0),
        reverse=True,
    )
    return dict(ordered[:MAX_SUBNET_ENTRIES])


def coordinated_subnets(data: dict, *, now: float) -> list[dict]:
    """Return currently coordinated subnets for operator views."""
    subnets = data.get("subnets", {}) if isinstance(data, dict) else {}
    if not isinstance(subnets, dict):
        return []
    rows = []
    for prefix, record in subnets.items():
        if not isinstance(record, dict):
            continue
        members = record.get("members", {})
        if not isinstance(members, dict):
            continue
        active = [
            member
            for member, seen in members.items()
            if isinstance(seen, (int, float))
            and now - float(seen) <= SUBNET_WINDOW
        ]
        if len(active) < SUBNET_MEMBERS:
            continue
        rows.append(
            {
                "prefix": str(prefix),
                "members": len(active),
                "addresses": sorted(active)[:8],
                "updated": float(record.get("updated", 0) or 0),
            },
        )
    rows.sort(key=lambda row: (row["members"], row["updated"]), reverse=True)
    return rows


__all__ = [
    "DECISIVE_SIGNALS",
    "SIGNAL_FAMILIES",
    "active_families",
    "ban_threshold",
    "block_reason",
    "coordinated_subnets",
    "event_weight",
    "record_families",
    "record_subnet_activity",
    "required_score",
    "signal_family",
    "subnet_of",
]
