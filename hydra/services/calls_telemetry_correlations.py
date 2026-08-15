"""Exploratory correlations for Calls telemetry; coefficients do not imply causation."""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence


def throughput_correlations(
    samples: Sequence[Mapping[str, object]],
) -> dict[str, dict[str, float | int]]:
    """Relate interval goodput to resource, queue and protocol indicators."""
    pairs: dict[str, list[tuple[float, float]]] = {
        "hydracore_cpu_percent": [],
        "host_cpu_percent": [],
        "active_connections": [],
        "listener_rx_queue_bytes": [],
        "kcp_wait_snd": [],
        "kcp_rtt_ms": [],
        "kcp_output_queue_depth": [],
        "lane_admission_window_segments": [],
        "worker_write_latency_ms": [],
        "network_loss_ratio": [],
    }
    previous: Mapping[str, object] | None = None
    for sample in samples:
        if previous is None:
            previous = sample
            continue
        elapsed = _number(sample.get("timestamp")) - _number(previous.get("timestamp"))
        if elapsed <= 0:
            previous = sample
            continue
        calls = _mapping(sample.get("calls"))
        interval = _mapping(calls.get("interval"))
        goodput = (
            _number(interval.get("upload_bytes"))
            + _number(interval.get("download_bytes"))
        ) * 8 / elapsed
        _add(pairs, "hydracore_cpu_percent", goodput, _process_cpu(previous, sample, elapsed))
        _add(pairs, "host_cpu_percent", goodput, _mapping(sample.get("host")).get("cpu_percent"))
        _add(pairs, "active_connections", goodput, calls.get("active_connections"))
        _add(
            pairs,
            "listener_rx_queue_bytes",
            goodput,
            _mapping(sample.get("udp")).get("listener_rx_queue_bytes"),
        )
        latest = _mapping(_mapping(sample.get("native")).get("latest"))
        server = _mapping(latest.get("server"))
        _add(pairs, "kcp_wait_snd", goodput, server.get("kcp_wait_snd"))
        _add(pairs, "kcp_rtt_ms", goodput, server.get("kcp_rtt_ms"))
        _add(
            pairs,
            "kcp_output_queue_depth",
            goodput,
            server.get("kcp_output_queue_depth"),
        )
        _add(
            pairs,
            "lane_admission_window_segments",
            goodput,
            server.get("lane_admission_window_segments"),
        )
        _add(
            pairs,
            "worker_write_latency_ms",
            goodput,
            server.get("worker_write_latency_ms"),
        )
        clients = _mapping(latest.get("clients"))
        losses = [
            _number(_mapping(metrics).get("network_loss_ratio"))
            for metrics in clients.values()
            if type(_mapping(metrics).get("network_loss_ratio")) in {int, float}
        ]
        if losses:
            _add(pairs, "network_loss_ratio", goodput, sum(losses) / len(losses))
        previous = sample
    return {
        name: {"pearson_r": round(_pearson(values), 4), "samples": len(values)}
        for name, values in pairs.items()
        if len(values) >= 3
    }


def _process_cpu(
    previous: Mapping[str, object],
    current: Mapping[str, object],
    elapsed: float,
) -> float | None:
    before = _mapping(previous.get("runtime"))
    after = _mapping(current.get("runtime"))
    before_ticks = _number(before.get("cpu_ticks"))
    after_ticks = _number(after.get("cpu_ticks"))
    ticks_per_second = max(1.0, _number(after.get("clock_ticks_per_second")))
    if after_ticks < before_ticks:
        return None
    return (after_ticks - before_ticks) / ticks_per_second * 100 / elapsed


def _add(
    pairs: dict[str, list[tuple[float, float]]],
    name: str,
    goodput: float,
    raw: object,
) -> None:
    if type(raw) not in {int, float}:
        return
    value = float(raw)
    if math.isfinite(value):
        pairs[name].append((goodput, value))


def _pearson(values: Sequence[tuple[float, float]]) -> float:
    left = [pair[0] for pair in values]
    right = [pair[1] for pair in values]
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    numerator = sum(
        (x - left_mean) * (y - right_mean)
        for x, y in values
    )
    denominator = math.sqrt(
        sum((x - left_mean) ** 2 for x in left)
        * sum((y - right_mean) ** 2 for y in right)
    )
    return numerator / denominator if denominator else 0.0


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _number(value: object) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else 0.0
    except (TypeError, ValueError):
        return 0.0


__all__ = ["throughput_correlations"]
