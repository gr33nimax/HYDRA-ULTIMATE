"""Bounded read projections over persisted AntiScan state.

The contraction removed scoring, evidence families and correlation windows, so
an operator view only ever shows what the runtime actually did: active bans,
recent ban history and aggregate source counters.  Legacy ``scores`` written by
earlier AntiDPI versions stay hidden instead of being presented as evidence.
"""

from __future__ import annotations

import copy
import time

from hydra.plugins.antidpi.labels import (
    ban_view,
    counter_rows,
    signal_label,
    source_label,
)
from hydra.plugins.antidpi.model import active_bans

HISTORY_LIMIT = 200
COUNTER_LIMIT = 6
# Derived or legacy state that must never reach an operator view.  ``scores``
# and ``subnets`` are written by earlier AntiDPI versions and are not evidence
# under the contracted contract.
_DERIVED_KEYS = ("banned", "scores", "history", "subnets")


def _as_float(value: object, default: float = 0.0) -> float:
    """Return a float from caller input, or ``default``."""
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


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from caller input, or ``default``."""
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


def address_details(data: dict, address: str, *, now: float) -> dict:
    """Return the exact evidence projection for one address."""
    source = data if isinstance(data, dict) else {}
    result: dict = {"ip": address, "now": _as_float(now, time.time())}
    metadata = active_bans(source, now=now).get(address)
    if isinstance(metadata, dict):
        result["ban"] = ban_view(address, metadata, now=now)
    history = source.get("history", [])
    matches = [
        copy.deepcopy(item)
        for item in (history if isinstance(history, list) else [])
        if isinstance(item, dict) and item.get("ip") == address
    ]
    if matches:
        result["history"] = matches[-20:]
    result["tracked"] = bool(result.get("ban") or matches)
    return result


def ban_rows(data: dict, *, now: float) -> list[dict]:
    """Return active bans, newest first, with adapter-ready labels."""
    banned = data.get("banned", {}) if isinstance(data, dict) else {}
    if not isinstance(banned, dict):
        return []
    rows = [ban_view(address, metadata, now=now) for address, metadata in active_bans(data, now=now).items()]
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
    watchlist_limit: int = 0,
) -> dict:
    """Return the bounded operator view of one persisted runtime state."""
    del watchlist_limit  # legacy call sites; the watchlist no longer exists
    source = data if isinstance(data, dict) else {}
    projection = {key: copy.deepcopy(value) for key, value in source.items() if key not in _DERIVED_KEYS}
    projection["now"] = _as_float(now, time.time())
    projection["last_event_source_label"] = source_label(
        source.get("last_event_source"),
    )
    projection["banned"] = copy.deepcopy(active_bans(source, now=now))
    projection["ban_rows"] = ban_rows(source, now=now)
    history = source.get("history", [])
    projection["history"] = (
        copy.deepcopy(history[-max(0, _as_int(history_limit, HISTORY_LIMIT)) :]) if isinstance(history, list) else []
    )
    projection["counters"] = counters(source)
    return projection


__all__ = [
    "COUNTER_LIMIT",
    "HISTORY_LIMIT",
    "address_details",
    "ban_rows",
    "counters",
    "management_projection",
]
