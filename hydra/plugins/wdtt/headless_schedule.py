"""Persisted qWDTT headless refresh schedule."""
from __future__ import annotations

from hydra.plugins.context import PluginStateAccess


REFRESH_INTERVAL = 86_400
MIN_REFRESH_INTERVAL = 3_600
MAX_REFRESH_INTERVAL = 86_400
REFRESH_INTERVAL_KEY = "qwdtt_refresh_interval_seconds"
AUTO_MANAGEMENT_FLAG = "sync_headless_creator_vk_qwdtt_enabled"


def refresh_interval(state: PluginStateAccess | None) -> int:
    value = REFRESH_INTERVAL
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
    raise RuntimeError(
        "VK creator schedule moved to ApplicationService.headless_creator",
    )


__all__ = [
    "AUTO_MANAGEMENT_FLAG",
    "MAX_REFRESH_INTERVAL",
    "MIN_REFRESH_INTERVAL",
    "REFRESH_INTERVAL",
    "REFRESH_INTERVAL_KEY",
    "refresh_interval",
    "set_refresh_interval",
]
