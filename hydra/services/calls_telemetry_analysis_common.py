"""Shared scalar and distribution helpers for Calls telemetry analysis."""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

def _metric_summary(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    series: dict[str, list[float]] = {}
    for record in records:
        metrics = _mapping(record.get("metrics"))
        for key, value in metrics.items():
            if type(value) in {int, float, bool}:
                series.setdefault(str(key), []).append(float(value))
    counters: dict[str, float] = {}
    gauges: dict[str, dict[str, float]] = {}
    for key, values in sorted(series.items()):
        if key.endswith("_total"):
            counters[key] = round(_monotonic_series_delta(values), 3)
        else:
            gauges[key] = _distribution(values)
    return {"records": len(records), "counters": counters, "gauges": gauges}


def _observed_groups(
    records: Sequence[Mapping[str, object]],
    groups: Mapping[str, Sequence[str]],
) -> dict[str, bool]:
    names = {
        str(name)
        for record in records
        for name in _mapping(record.get("metrics"))
    }
    return {
        group: all(required in names for required in required_names)
        for group, required_names in groups.items()
    }


def _monotonic_series_delta(values: Sequence[float]) -> float:
    total = 0.0
    previous: float | None = None
    for current in values:
        if previous is not None:
            total += current - previous if current >= previous else current
        previous = current
    return total


def _distribution(values: Sequence[float]) -> dict[str, float]:
    cleaned = sorted(value for value in values if math.isfinite(value))
    return {
        "min": round(min(cleaned, default=0.0), 3),
        "p50": round(_percentile(cleaned, 50), 3),
        "p95": round(_percentile(cleaned, 95), 3),
        "p99": round(_percentile(cleaned, 99), 3),
        "max": round(max(cleaned, default=0.0), 3),
    }


def _percentile(values: Sequence[float], percentile: int) -> float:
    if not values:
        return 0.0
    index = max(0, math.ceil(percentile / 100 * len(values)) - 1)
    return values[index]


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _integer(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _number(value: object) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else 0.0
    except (TypeError, ValueError):
        return 0.0


__all__ = [
    "_distribution",
    "_integer",
    "_mapping",
    "_metric_summary",
    "_monotonic_series_delta",
    "_number",
    "_observed_groups",
]
