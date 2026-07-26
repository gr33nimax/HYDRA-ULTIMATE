"""Bounded read projections over persisted AntiDPI evidence.

Dashboards used to receive a deep copy of the whole runtime state, including
up to ``MAX_SCORE_ENTRIES`` per-address score entries, on every refresh.  This
module derives exactly what an operator view needs: active bans, recent
history, aggregate counters, and the sub-threshold watchlist.
"""
from __future__ import annotations

import copy
import time

from hydra.plugins.antidpi.correlation import (
    active_families,
    block_reason,
    coordinated_subnets,
    required_score,
    signal_family,
)
from hydra.plugins.antidpi.labels import (
    ban_view,
    block_reason_label,
    counter_rows,
    family_summary,
    signal_label,
    signal_summary,
    source_label,
)
from hydra.plugins.antidpi.model import (
    WATCHLIST_MIN_SCORE,
    active_bans,
    decayed_score,
)

HISTORY_LIMIT = 200
WATCHLIST_LIMIT = 25
COUNTER_LIMIT = 6
_DERIVED_KEYS = ("banned", "scores", "history")


def watchlist(
    data: dict,
    *,
    now: float | None = None,
    limit: int = WATCHLIST_LIMIT,
    minimum: float = WATCHLIST_MIN_SCORE,
) -> list[dict]:
    """Return decayed evidence for addresses that are observed but not banned.

    The detector already tracks sub-threshold evidence; without this
    projection an operator only ever sees an address after it is banned.
    """
    scores = data.get("scores", {}) if isinstance(data, dict) else {}
    if not isinstance(scores, dict):
        return []
    timestamp = time.time() if now is None else now
    banned = set(active_bans(data, now=timestamp))
    counts = data.get("ban_counts", {}) if isinstance(data, dict) else {}
    counts = counts if isinstance(counts, dict) else {}
    rows = []
    for address, entry in scores.items():
        if address in banned or not isinstance(entry, dict):
            continue
        try:
            offenses = max(0, int(counts.get(address, 0) or 0))
        except (TypeError, ValueError):
            offenses = 0
        row = _watchlist_row(
            str(address),
            entry,
            timestamp,
            float(minimum),
            offenses,
        )
        if row is not None:
            rows.append(row)
    rows.sort(key=lambda row: (row["score"], row["updated"]), reverse=True)
    return rows[:max(0, int(limit))]


def _watchlist_row(
    address: str,
    entry: dict,
    timestamp: float,
    minimum: float,
    offense_count: int = 0,
) -> dict | None:
    try:
        updated = float(entry.get("updated", 0) or 0)
        raw_score = float(entry.get("score", 0) or 0)
        raw_verified = float(entry.get("verified_score", 0) or 0)
    except (TypeError, ValueError):
        return None
    elapsed = max(0.0, timestamp - updated)
    score = decayed_score(raw_score, elapsed)
    if score < minimum:
        return None
    signals = entry.get("signals", [])
    visible = (
        [str(value) for value in signals][-8:]
        if isinstance(signals, list)
        else []
    )
    verified = decayed_score(raw_verified, elapsed)
    families = _display_families(entry, visible, verified, timestamp)
    threshold = required_score(
        families=families,
        signals=visible,
        offense_count=offense_count,
    )
    reason = block_reason(
        score=verified,
        required=threshold,
        families=families,
        evidence_can_ban=verified > 0,
    )
    return {
        "ip": address,
        "score": round(score, 2),
        "verified_score": round(verified, 2),
        "threshold": float(threshold),
        "signals": visible,
        "reason": signal_summary(visible, limit=2),
        "signal_labels": signal_summary(visible, limit=8),
        "families": list(families),
        "evidence": family_summary(families),
        "block_reason": reason,
        "block_label": block_reason_label(reason),
        "offense_count": offense_count,
        "updated": updated,
    }


def _display_families(
    entry: dict,
    signals: list[str],
    verified: float,
    timestamp: float,
) -> tuple[str, ...]:
    """Return evidence families, reconstructing them for pre-upgrade entries.

    The decision path never guesses: an entry without a recorded ledger is
    treated as uncorroborated until fresh evidence arrives. Operator views may
    still show what the stored signals imply, so an upgraded install does not
    display an empty evidence column for addresses it is already tracking.
    """
    families = active_families(entry, timestamp=timestamp)
    if families or not isinstance(entry, dict):
        return families
    if entry.get("families") is not None or verified <= 0:
        return ()
    return tuple(sorted({signal_family(signal) for signal in signals if signal}))


def ban_rows(data: dict, *, now: float) -> list[dict]:
    """Return active bans, newest first, with adapter-ready labels."""
    banned = data.get("banned", {}) if isinstance(data, dict) else {}
    if not isinstance(banned, dict):
        return []
    rows = [
        ban_view(address, metadata, now=now)
        for address, metadata in active_bans(data, now=now).items()
    ]
    rows.sort(key=lambda row: row["at"], reverse=True)
    return rows


def counters(data: dict, *, limit: int = COUNTER_LIMIT) -> dict:
    """Return ranked, translated signal and source counters."""
    source = data if isinstance(data, dict) else {}
    return {
        "signals": counter_rows(
            source.get("signal_counts"),
            signal_label,
            limit=limit,
        ),
        "sources": counter_rows(
            source.get("source_counts"),
            source_label,
            limit=limit,
        ),
    }


def management_projection(
    data: dict,
    *,
    now: float,
    history_limit: int = HISTORY_LIMIT,
    watchlist_limit: int = WATCHLIST_LIMIT,
) -> dict:
    """Return the bounded operator view of one persisted runtime state."""
    source = data if isinstance(data, dict) else {}
    projection = {
        key: copy.deepcopy(value)
        for key, value in source.items()
        if key not in _DERIVED_KEYS
    }
    projection["now"] = float(now)
    projection["last_event_source_label"] = source_label(
        source.get("last_event_source"),
    )
    projection["banned"] = copy.deepcopy(active_bans(source, now=now))
    projection["ban_rows"] = ban_rows(source, now=now)
    history = source.get("history", [])
    projection["history"] = (
        copy.deepcopy(history[-max(0, int(history_limit)):])
        if isinstance(history, list)
        else []
    )
    scores = source.get("scores", {})
    projection["tracked_addresses"] = (
        len(scores) if isinstance(scores, dict) else 0
    )
    projection["watchlist"] = watchlist(
        source,
        now=now,
        limit=watchlist_limit,
    )
    projection["counters"] = counters(source)
    projection["coordinated"] = coordinated_subnets(source, now=now)
    projection.pop("subnets", None)
    return projection


__all__ = [
    "COUNTER_LIMIT",
    "HISTORY_LIMIT",
    "WATCHLIST_LIMIT",
    "ban_rows",
    "counters",
    "management_projection",
    "watchlist",
]
