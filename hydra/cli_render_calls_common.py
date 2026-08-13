"""Shared scalar helpers for Calls telemetry rendering."""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone


def bytes_value(value: object) -> str:
    amount = float(value or 0)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return "0.0 B"


def bitrate(value: object) -> str:
    amount = float(value or 0)
    units = ("bit/s", "Kbit/s", "Mbit/s", "Gbit/s")
    for unit in units:
        if abs(amount) < 1000 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1000
    return "0.0 bit/s"


def percent(value: object) -> str:
    return f"{float(value or 0) * 100:.1f}%"


def gauge(report: Mapping[str, object], metric: str, statistic: str) -> float:
    gauges = report.get("gauges")
    gauge_map = gauges if isinstance(gauges, Mapping) else {}
    value = gauge_map.get(metric)
    value_map = value if isinstance(value, Mapping) else {}
    return float(value_map.get(statistic, 0) or 0)


def counter(report: Mapping[str, object], metric: str) -> float:
    counters = report.get("counters")
    counter_map = counters if isinstance(counters, Mapping) else {}
    return float(counter_map.get(metric, 0) or 0)


def has_gauge(report: Mapping[str, object], metric: str) -> bool:
    gauges = report.get("gauges")
    return isinstance(gauges, Mapping) and metric in gauges


def short_id(value: object) -> str:
    text = str(value or "-")
    return text if len(text) <= 12 else text[-12:]


def timestamp(value: object) -> str:
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ",
        )
    except (OSError, TypeError, ValueError):
        return "unknown-time"


__all__ = [
    "bitrate",
    "bytes_value",
    "counter",
    "gauge",
    "has_gauge",
    "percent",
    "short_id",
    "timestamp",
]
