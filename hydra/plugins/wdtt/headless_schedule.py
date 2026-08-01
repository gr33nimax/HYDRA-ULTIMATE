"""Persisted qWDTT headless refresh schedule."""
from __future__ import annotations

from hydra.plugins.context import PluginStateAccess


REFRESH_INTERVAL = 86_400
MIN_REFRESH_INTERVAL = 3_600
MAX_REFRESH_INTERVAL = 86_400
REFRESH_INTERVAL_KEY = "headless_refresh_interval_seconds"


def refresh_interval(state: PluginStateAccess | None) -> int:
    protocol = state.protocols.get("wdtt") if state is not None else None
    value = (
        protocol.config.get(REFRESH_INTERVAL_KEY, REFRESH_INTERVAL)
        if protocol is not None
        else REFRESH_INTERVAL
    )
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return REFRESH_INTERVAL
    if not MIN_REFRESH_INTERVAL <= seconds <= MAX_REFRESH_INTERVAL:
        return REFRESH_INTERVAL
    return seconds


def set_refresh_interval(
    state: PluginStateAccess,
    seconds: int,
) -> bool:
    if isinstance(seconds, bool):
        raise ValueError(
            "headless refresh interval must be between 1 and 24 hours",
        )
    try:
        normalized = int(seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "headless refresh interval must be between 1 and 24 hours",
        ) from exc
    if not MIN_REFRESH_INTERVAL <= normalized <= MAX_REFRESH_INTERVAL:
        raise ValueError(
            "headless refresh interval must be between 1 and 24 hours",
        )
    protocol = state.protocols.get("wdtt")
    if protocol is None:
        raise ValueError("qWDTT protocol state is missing")
    previous = refresh_interval(state)
    if previous == normalized and REFRESH_INTERVAL_KEY in protocol.config:
        return False
    protocol.config[REFRESH_INTERVAL_KEY] = normalized
    return True


__all__ = [
    "MAX_REFRESH_INTERVAL",
    "MIN_REFRESH_INTERVAL",
    "REFRESH_INTERVAL",
    "REFRESH_INTERVAL_KEY",
    "refresh_interval",
    "set_refresh_interval",
]
