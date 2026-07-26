"""Pure AntiDPI scoring, retention, and ban-state helpers.

This module deliberately knows nothing about files, subprocesses, systemd,
ipset, Telegram, or the plugin registry.  Callers provide the current time and
persist the mutated dictionaries through an explicit state store.
"""
from __future__ import annotations

import ipaddress
import time
from collections.abc import Iterable

SIGNAL_WEIGHTS = {
    "malformed_tls": 4,
    "non_tls_on_tls": 3,
    "unknown_sni": 2,
    "handshake_failure": 2,
    "protocol_mismatch": 3,
    "quic_retry_burst": 2,
    "connection_burst": 2,
    "invalid_first_packet": 3,
    "active_decoy_probe": 8,
    "auth_failure": 3,
    "port_scan": 2,
    "port_sweep": 6,
    "udp_probe": 4,
    "low_volume_session": 3,
}

SCORE_HALF_LIFE = 300.0
BAN_THRESHOLD = 8
ALERT_THRESHOLD = 6
AUTH_ALERT_THRESHOLD = 3
BAN_DURATIONS = (600, 3600, 86400, 604800)
LEGACY_BAN_DURATION = 86400
ALERT_COOLDOWN = 300.0
MAX_OBSERVED_SCORE = BAN_THRESHOLD * 2
BAN_NOTIFICATION_COOLDOWN = 5.0
SCORE_RETENTION = 86400.0
MAX_SCORE_ENTRIES = 20000
DEFAULT_TRUSTED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)

_WHITELIST_CACHE: tuple[
    tuple[str, ...],
    list[ipaddress.IPv4Network | ipaddress.IPv6Network],
] = ((), [])


def get_whitelisted_networks(
    raw_list: list[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse configured networks once while preserving object identity."""
    global _WHITELIST_CACHE
    current_raw = tuple(raw_list)
    if _WHITELIST_CACHE[0] == current_raw:
        return _WHITELIST_CACHE[1]
    parsed = []
    for raw in raw_list:
        try:
            parsed.append(ipaddress.ip_network(str(raw), strict=False))
        except ValueError:
            continue
    _WHITELIST_CACHE = (current_raw, parsed)
    return parsed


def is_whitelisted(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    configured: object,
    host_addresses: Iterable[str] = (),
) -> bool:
    """Return whether an address is local, trusted, or explicitly configured."""
    if address.is_loopback or address.is_link_local:
        return True
    if address.compressed in set(host_addresses):
        return True
    raw_networks = configured if isinstance(configured, list) else []
    networks = (*DEFAULT_TRUSTED_NETWORKS, *get_whitelisted_networks(raw_networks))
    return any(address in network for network in networks)


def get_ban_duration(offense_count: int) -> int:
    """Return ban duration in seconds based on progressive offense count."""
    index = min(max(0, offense_count - 1), len(BAN_DURATIONS) - 1)
    return BAN_DURATIONS[index]


def format_score(value: object, *, threshold: float = BAN_THRESHOLD) -> str:
    """Render detector precision without visually crossing the ban threshold."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        score = 0.0
    return f"{score:.2f}/{threshold:.2f}"


def track_notification(data: dict, delivered: bool, *, now: float) -> None:
    """Persist delivery telemetry without storing notification credentials."""
    stats = data.setdefault("notification_stats", {})
    if not isinstance(stats, dict):
        stats = {}
        data["notification_stats"] = stats
    stats["attempted"] = int(stats.get("attempted", 0)) + 1
    stats["last_attempt_at"] = now
    key = "delivered" if delivered else "failed"
    stats[key] = int(stats.get(key, 0)) + 1
    stats[f"last_{key}_at"] = now


def ban_duration(metadata: object) -> int:
    """Return persisted duration, preserving the old 24-hour ban format."""
    if not isinstance(metadata, dict):
        return 0
    try:
        return max(0, int(metadata.get("duration", LEGACY_BAN_DURATION)))
    except (TypeError, ValueError):
        return 0


def active_bans(data: dict, *, now: float | None = None) -> dict:
    """Return only bans whose persisted timeout has not expired."""
    banned = data.get("banned", {}) if isinstance(data, dict) else {}
    if not isinstance(banned, dict):
        return {}
    timestamp = time.time() if now is None else now
    result = {}
    for address, metadata in banned.items():
        if not isinstance(metadata, dict):
            continue
        if metadata.get("permanent") is True:
            result[address] = metadata
            continue
        try:
            expires_at = float(metadata.get("at", 0)) + ban_duration(metadata)
        except (TypeError, ValueError):
            continue
        if timestamp < expires_at:
            result[address] = metadata
    return result


def expire_bans(data: dict, *, now: float | None = None) -> bool:
    """Remove elapsed bans and reconcile their latest history records."""
    banned = data.get("banned", {}) if isinstance(data, dict) else {}
    if not isinstance(banned, dict):
        data["banned"] = {}
        return True
    timestamp = time.time() if now is None else now
    changed = False
    for address, metadata in list(banned.items()):
        if not isinstance(metadata, dict):
            banned.pop(address, None)
            changed = True
            continue
        if metadata.get("permanent") is True:
            continue
        try:
            elapsed = timestamp >= float(metadata.get("at", 0)) + ban_duration(metadata)
        except (TypeError, ValueError):
            elapsed = True
        if elapsed:
            banned.pop(address, None)
            changed = True
    active = set(active_bans(data, now=timestamp))
    history = data.get("history", [])
    if isinstance(history, list):
        for item in reversed(history):
            if not isinstance(item, dict):
                continue
            if item.get("status") == "active" and item.get("ip") not in active:
                item["status"] = "expired"
                item["expired_at"] = timestamp
                changed = True
    return changed


def prune_runtime_state(
    data: dict,
    *,
    now: float | None = None,
    max_entries: int = MAX_SCORE_ENTRIES,
) -> None:
    """Bound per-address evidence while retaining active bans and recent scores."""
    scores = data.get("scores", {})
    if not isinstance(scores, dict):
        data["scores"] = {}
        return
    timestamp = time.time() if now is None else now
    active = set(active_bans(data, now=timestamp))
    retained = {}
    for address, metadata in scores.items():
        if not isinstance(metadata, dict):
            continue
        try:
            updated = float(metadata.get("updated", 0))
        except (TypeError, ValueError):
            continue
        if address in active or timestamp - updated <= SCORE_RETENTION:
            retained[address] = metadata
    if len(retained) > max_entries:
        protected = {
            address: retained[address]
            for address in active
            if address in retained
        }
        candidates = sorted(
            (
                (address, metadata)
                for address, metadata in retained.items()
                if address not in protected
            ),
            key=lambda item: float(item[1].get("updated", 0)),
            reverse=True,
        )
        available = max(0, max_entries - len(protected))
        retained = {**protected, **dict(candidates[:available])}
    data["scores"] = retained


def decayed_score(
    score: float,
    elapsed: float,
    half_life: float = SCORE_HALF_LIFE,
) -> float:
    """Decay evidence exponentially so old probes cannot cause a late ban."""
    if elapsed <= 0:
        return max(0.0, float(score))
    if half_life <= 0:
        return 0.0
    return max(0.0, float(score) * 0.5 ** (elapsed / half_life))


def score_event(event: dict) -> tuple[int, tuple[str, ...]]:
    """Return ``(score, signals)`` for one normalized L4 event."""
    if not isinstance(event, dict):
        return 0, ()
    signals: list[str] = []
    kind = str(event.get("kind", event.get("reason", ""))).lower()
    mapping = {
        "malformed_tls": ("malformed_tls",),
        "bad_client_hello": ("malformed_tls",),
        "non_tls": ("non_tls_on_tls",),
        "unknown_sni": ("unknown_sni",),
        "handshake_error": ("handshake_failure",),
        "handshake_failure": ("handshake_failure",),
        "protocol_mismatch": ("protocol_mismatch",),
        "invalid_first_packet": ("invalid_first_packet",),
        "active_decoy_probe": ("active_decoy_probe",),
        "auth_failure": ("auth_failure",),
        "port_scan": ("port_scan",),
        "udp_probe": ("udp_probe",),
        "low_volume_session": ("low_volume_session",),
    }
    signals.extend(mapping.get(kind, ()))
    protocol = str(event.get("protocol", "")).lower()
    if protocol in {"tls", "https", "quic"} and event.get("handshake_ok") is False:
        signals.append("handshake_failure")
    if event.get("sni_known") is False and "unknown_sni" not in signals:
        signals.append("unknown_sni")
    try:
        if int(event.get("distinct_ports_60s", 0)) >= 4:
            signals.append("port_sweep")
        if int(event.get("connections_10s", 0)) >= 12:
            signals.append("connection_burst")
        if protocol == "quic" and int(event.get("retries_10s", 0)) >= 6:
            signals.append("quic_retry_burst")
    except (TypeError, ValueError):
        pass
    unique = tuple(dict.fromkeys(signals))
    return sum(SIGNAL_WEIGHTS.get(signal, 0) for signal in unique), unique


def record_unban(data: dict, address: str, *, now: float) -> None:
    """Remove active evidence and close the newest matching history record."""
    banned = data.get("banned", {})
    if isinstance(banned, dict):
        banned.pop(address, None)
    scores = data.get("scores", {})
    if isinstance(scores, dict):
        scores.pop(address, None)
    history = data.get("history", [])
    if not isinstance(history, list):
        return
    for item in reversed(history):
        if (
            isinstance(item, dict)
            and item.get("ip") == address
            and item.get("status") == "active"
        ):
            item["status"] = "unbanned"
            item["unbanned_at"] = now
            break


def record_manual_ban(
    data: dict,
    address: str,
    *,
    source: str,
    timestamp: float,
    current: dict | None,
) -> dict:
    """Promote or create a permanent administrator-owned ban."""
    ban_counts = data.setdefault("ban_counts", {})
    if not isinstance(ban_counts, dict):
        ban_counts = {}
        data["ban_counts"] = ban_counts
    offense_count = (
        int(current.get("offense_count", 1) or 1)
        if isinstance(current, dict)
        else int(ban_counts.get(address, 0) or 0) + 1
    )
    scores = data.get("scores", {})
    if not isinstance(scores, dict):
        scores = {}
    entry = scores.get(address, {})
    if not isinstance(entry, dict):
        entry = {}
    raw_signals = entry.get("signals", [])
    if not isinstance(raw_signals, list):
        raw_signals = [str(raw_signals)] if raw_signals else []
    signals = list(dict.fromkeys([*raw_signals, "manual_ban"]))[-16:]
    metadata = {
        "at": timestamp,
        "score": float(
            entry.get("verified_score", entry.get("score", 0)) or 0,
        ),
        "signals": signals,
        "source": str(source)[:80],
        "protocol": "manual",
        "kind": "manual_ban",
        "duration": 0,
        "permanent": True,
        "offense_count": offense_count,
    }
    banned = data.setdefault("banned", {})
    if not isinstance(banned, dict):
        banned = {}
        data["banned"] = banned
    banned[address] = metadata
    ban_counts[address] = offense_count
    history = data.setdefault("history", [])
    if not isinstance(history, list):
        history = []
    promoted = False
    if isinstance(current, dict):
        for item in reversed(history):
            if (
                isinstance(item, dict)
                and item.get("ip") == address
                and item.get("status") == "active"
            ):
                item.clear()
                item.update({"ip": address, **metadata, "status": "active"})
                promoted = True
                break
    if not promoted:
        history.append({"ip": address, **metadata, "status": "active"})
    data["history"] = history[-1000:]
    return metadata
