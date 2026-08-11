"""Resource aggregation for the Calls telemetry report."""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence


def build_resource_report(
    samples: Sequence[Mapping[str, object]],
    host_cpu: Sequence[float],
    process_cpu: Sequence[float],
    host_memory: Sequence[float],
    process_rss: Sequence[int],
    udp: Mapping[str, int],
    kernel: Mapping[str, object],
) -> dict[str, object]:
    return {
        "host_cpu_percent": _distribution(host_cpu),
        "hydracore_cpu_percent": _distribution(process_cpu),
        "host_memory_percent": _distribution(host_memory),
        "hydracore_rss_bytes": _distribution(process_rss),
        "udp": dict(udp),
        "kernel": dict(kernel),
        "service_restarts": _counter_delta(samples, "runtime", "restarts"),
        "hydracore_threads": _distribution(_values(samples, "runtime", "threads")),
        "hydracore_open_fds": _distribution(_values(samples, "runtime", "open_fds")),
        "hydracore_swap_bytes": _distribution(_values(samples, "runtime", "swap_bytes")),
        "hydracore_major_faults": _counter_delta(samples, "runtime", "major_faults"),
    }


def _counter_delta(
    samples: Sequence[Mapping[str, object]],
    section: str,
    key: str,
) -> int:
    total = 0
    previous: int | None = None
    for sample in samples:
        current = _integer(_mapping(sample.get(section)).get(key))
        if previous is not None:
            total += current - previous if current >= previous else current
        previous = current
    return total


def _values(
    samples: Sequence[Mapping[str, object]],
    section: str,
    key: str,
) -> list[float]:
    return [
        _number(_mapping(sample.get(section)).get(key))
        for sample in samples
    ]


def _distribution(values: Sequence[float | int]) -> dict[str, float]:
    cleaned = sorted(float(value) for value in values if math.isfinite(float(value)))
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


__all__ = ["build_resource_report"]
