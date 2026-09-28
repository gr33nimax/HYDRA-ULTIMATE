"""Pure AntiDPI scoring, retention, and ban-state helpers.

This module deliberately knows nothing about files, subprocesses, systemd,
ipset, Telegram, or the plugin registry.  Callers provide the current time and
persist the mutated dictionaries through an explicit state store.
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Iterable

# Progressive ban ladder.  Enforcement no longer consults a score: one proven
# protocol reject or decoy scan starts the ladder at its first step.
BAN_DURATIONS = (600, 3600, 86400, 604800)
LEGACY_BAN_DURATION = 86400
BAN_NOTIFICATION_COOLDOWN = 5.0

# Retention for legacy runtime state written by earlier AntiDPI versions.  The
# current runtime never reads those entries for a decision; the retention
# window only lets old data age out instead of being migrated destructively.
SCORE_RETENTION = 86400.0
MAX_SCORE_ENTRIES = 20000
MAX_HISTORY_ENTRIES = 1000
DEFAULT_TRUSTED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from untrusted state, or ``default``."""
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


def _as_float(value: object, default: float = 0.0) -> float:
    """Return a float from untrusted state, or ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return float(value.strip())
        except (TypeError, ValueError):
            return default
    return default


def _is_permanent(metadata: object) -> bool:
    """Return True only for the JSON boolean ``true`` of an admin-owned ban."""
    if not isinstance(metadata, dict):
        return False
    return isinstance(metadata.get("permanent"), bool) and metadata["permanent"]


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


def track_notification(data: dict, delivered: bool, *, now: float) -> None:
    """Persist delivery telemetry without storing notification credentials."""
    stats = data.setdefault("notification_stats", {})
    if not isinstance(stats, dict):
        stats = {}
        data["notification_stats"] = stats
    stats["attempted"] = _as_int(stats.get("attempted", 0)) + 1
    stats["last_attempt_at"] = now
    key = "delivered" if delivered else "failed"
    stats[key] = _as_int(stats.get(key, 0)) + 1
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
        if _is_permanent(metadata):
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
        if _is_permanent(metadata):
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


def prune_ban_counts(data: dict, *, now: float | None = None) -> None:
    """Bound escalation memory to addresses with a live ban or ban history.

    ``ban_counts`` drives progressive ban durations, so it used to grow for
    every address ever banned and never shrank.  Escalation memory now lives
    exactly as long as the history record that explains it.
    """
    counts = data.get("ban_counts", {}) if isinstance(data, dict) else {}
    if not isinstance(counts, dict):
        data["ban_counts"] = {}
        return
    if not counts:
        return
    timestamp = time.time() if now is None else now
    known = set(active_bans(data, now=timestamp))
    history = data.get("history", [])
    if isinstance(history, list):
        known.update(str(item.get("ip")) for item in history if isinstance(item, dict) and item.get("ip"))
    data["ban_counts"] = {address: value for address, value in counts.items() if address in known}


def record_ban_failure(data: dict, address: str, *, now: float) -> None:
    """Persist firewall enforcement failures observed by the detector service.

    The detector runs in its own systemd unit, so an in-memory ``last_error``
    is invisible to operators.  Persisting the failure lets the TUI and the
    Telegram dashboards show that evidence crossed the threshold while the
    firewall refused the ban.
    """
    stats = data.setdefault("ban_failures", {})
    if not isinstance(stats, dict):
        stats = {}
        data["ban_failures"] = stats
    stats["count"] = _as_int(stats.get("count", 0)) + 1
    stats["last_at"] = now
    stats["last_ip"] = str(address)[:64]


def prune_runtime_state(
    data: dict,
    *,
    now: float | None = None,
    max_entries: int = MAX_SCORE_ENTRIES,
) -> None:
    """Bound per-address evidence while retaining active bans and recent scores."""
    prune_ban_counts(data, now=now)
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
        protected = {address: retained[address] for address in active if address in retained}
        candidates = sorted(
            ((address, metadata) for address, metadata in retained.items() if address not in protected),
            key=lambda item: _as_float(item[1].get("updated", 0)),
            reverse=True,
        )
        available = max(0, max_entries - len(protected))
        retained = {**protected, **dict(candidates[:available])}
    data["scores"] = retained


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
        if isinstance(item, dict) and item.get("ip") == address and item.get("status") == "active":
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
        max(1, _as_int(current.get("offense_count", 1), default=1))
        if isinstance(current, dict)
        else _as_int(ban_counts.get(address, 0)) + 1
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
        "score": _as_float(
            entry.get("verified_score", entry.get("score", 0)),
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
            if isinstance(item, dict) and item.get("ip") == address and item.get("status") == "active":
                item.clear()
                item.update({"ip": address, **metadata, "status": "active"})
                promoted = True
                break
    if not promoted:
        history.append({"ip": address, **metadata, "status": "active"})
    data["history"] = history[-MAX_HISTORY_ENTRIES:]
    return metadata
