"""Protocol-specific analysis for Hydracore Calls telemetry records."""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence


SERVER_REQUIRED = {
    "auth": ("auth_success_total", "auth_failure_total"),
    "dtls": ("dtls_handshake_success_total", "dtls_handshake_failure_total", "dtls_handshake_latency_ms"),
    "handshake": (
        "handshake_pending", "handshake_rejected_total", "handshake_timeout_total",
        "handshake_latency_ms",
    ),
    "kcp": (
        "kcp_wait_snd", "kcp_out_segments_total", "kcp_retrans_segments_total",
        "kcp_rtt_ms", "kcp_rto_ms", "kcp_send_blocked_seconds_total",
    ),
    "outer": (
        "outer_packets_in_total", "outer_packets_out_total", "outer_bytes_in_total",
        "outer_bytes_out_total", "outer_auth_failures_total", "outer_wrap_failures_total",
    ),
    "peer": ("peer_read_queue_depth", "peer_read_queue_drops_total"),
    "relay": (
        "relay_tcp_active", "relay_udp_active", "relay_bytes_total",
        "relay_queue_depth", "relay_queue_drops_total", "relay_connect_failure_total",
    ),
    "runtime": ("runtime_goroutines", "runtime_heap_bytes", "runtime_gc_pause_seconds_total"),
    "session": ("session_active", "session_created_total", "session_closed_total"),
    "worker": (
        "worker_active", "worker_attach_success_total", "worker_attach_failure_total",
        "worker_send_queue_depth", "worker_send_queue_drops_total",
        "worker_no_available_drops_total", "worker_liveness_expired_total",
    ),
}
CLIENT_REQUIRED = {
    "vk": (
        "vk_auth_success_total", "vk_auth_failure_total", "vk_auth_latency_ms",
        "vk_auth_anonym_token_latency_ms", "vk_call_preview_latency_ms",
        "vk_anonym_call_token_latency_ms", "vk_anonym_login_latency_ms",
        "vk_join_conversation_latency_ms",
    ),
    "turn": (
        "turn_allocate_success_total", "turn_allocate_failure_total",
        "turn_allocate_latency_ms", "turn_endpoints_tried_total",
    ),
    "dtls": ("dtls_handshake_success_total", "dtls_handshake_failure_total", "dtls_handshake_latency_ms"),
    "inner_auth": ("inner_auth_success_total", "inner_auth_failure_total", "inner_auth_latency_ms"),
    "worker": (
        "worker_desired", "worker_active", "worker_reconnect_total",
        "worker_reconnect_backoff_ms", "worker_send_queue_depth",
        "worker_send_queue_drops_total", "worker_liveness_expired_total",
    ),
    "kcp": (
        "kcp_wait_snd", "kcp_out_segments_total", "kcp_retrans_segments_total",
        "kcp_rtt_ms", "kcp_rto_ms", "kcp_send_blocked_seconds_total",
    ),
    "network": (
        "network_loss_ratio", "network_jitter_ms", "network_handover_total",
        "network_change_total",
    ),
    "outer": (
        "outer_packets_in_total", "outer_packets_out_total", "outer_bytes_in_total",
        "outer_bytes_out_total", "outer_auth_failures_total",
    ),
    "runtime": ("runtime_cpu_percent", "runtime_rss_bytes", "runtime_thermal_state"),
}


def analyze_native(
    records: Sequence[Mapping[str, object]],
    tester_ids: Sequence[str],
) -> dict[str, object]:
    native = [record for record in records if record.get("kind") == "native"]
    server = [record for record in native if record.get("native_scope") == "server"]
    clients: dict[str, list[Mapping[str, object]]] = {}
    events: dict[str, int] = {}
    for record in native:
        event = str(record.get("event", ""))
        if event:
            events[event] = events.get(event, 0) + 1
        if record.get("native_scope") == "client":
            tester_id = str(record.get("tester_id", "")) or "unattributed"
            clients.setdefault(tester_id, []).append(record)
    server_groups = _observed_groups(server, SERVER_REQUIRED)
    client_groups = {
        tester_id: _observed_groups(clients.get(tester_id, ()), CLIENT_REQUIRED)
        for tester_id in tester_ids
    }
    full_clients = all(
        all(groups.values())
        for groups in client_groups.values()
    ) if tester_ids else False
    full_server = all(server_groups.values())
    diagnostic_level = (
        "full"
        if full_server and full_clients
        else "partial"
        if native
        else "server_observation_only"
    )
    return {
        "available": bool(native),
        "diagnostic_level": diagnostic_level,
        "records": len(native),
        "server_records": len(server),
        "client_records": sum(len(value) for value in clients.values()),
        "server_groups": server_groups,
        "client_groups": client_groups,
        "missing_testers": [
            tester_id for tester_id in tester_ids if not clients.get(tester_id)
        ],
        "server": _metric_summary(server),
        "clients": {
            tester_id: _metric_summary(value)
            for tester_id, value in sorted(clients.items())
        },
        "events": events,
    }


def analyze_kernel(samples: Sequence[Mapping[str, object]]) -> dict[str, object]:
    return {
        "softnet_drops": _nested_counter_delta(samples, ("kernel", "softnet"), "dropped"),
        "softnet_time_squeeze": _nested_counter_delta(
            samples,
            ("kernel", "softnet"),
            "time_squeeze",
        ),
        "interface_rx_drops": _nested_counter_delta(
            samples,
            ("kernel", "interfaces"),
            "rx_drops",
        ),
        "interface_tx_drops": _nested_counter_delta(
            samples,
            ("kernel", "interfaces"),
            "tx_drops",
        ),
        "interface_rx_errors": _nested_counter_delta(
            samples,
            ("kernel", "interfaces"),
            "rx_errors",
        ),
        "interface_tx_errors": _nested_counter_delta(
            samples,
            ("kernel", "interfaces"),
            "tx_errors",
        ),
        "cpu_psi_some_avg10": _distribution(
            _nested_values(samples, ("kernel", "pressure", "cpu", "some"), "avg10"),
        ),
        "memory_psi_some_avg10": _distribution(
            _nested_values(samples, ("kernel", "pressure", "memory", "some"), "avg10"),
        ),
        "io_psi_some_avg10": _distribution(
            _nested_values(samples, ("kernel", "pressure", "io", "some"), "avg10"),
        ),
        "conntrack_peak_ratio": _conntrack_peak(samples),
        "minimum_telemetry_disk_free_bytes": min(
            _nested_values(samples, ("kernel", "telemetry_disk"), "free_bytes"),
            default=0.0,
        ),
    }


def phase_reports(
    samples: Sequence[Mapping[str, object]],
    records: Sequence[Mapping[str, object]],
    *,
    started_at: float,
    observed_until: float,
) -> list[dict[str, object]]:
    marks = sorted(
        (record for record in records if record.get("kind") == "mark"),
        key=lambda record: _number(record.get("timestamp")),
    )
    boundaries = [(started_at, "unmarked")]
    boundaries.extend(
        (_number(mark.get("timestamp")), str(mark.get("label", "")))
        for mark in marks
    )
    reports: list[dict[str, object]] = []
    for index, (begin, label) in enumerate(boundaries):
        end = boundaries[index + 1][0] if index + 1 < len(boundaries) else observed_until
        selected = [
            sample
            for sample in samples
            if begin <= _number(sample.get("timestamp")) < end
        ]
        rates = _sample_rates(selected)
        reports.append({
            "label": label,
            "started_at": begin,
            "ended_at": end,
            "duration_seconds": max(0.0, end - begin),
            "samples": len(selected),
            "throughput_bps": _distribution(rates),
            "peak_connections": max(
                (
                    _integer(_mapping(sample.get("calls")).get("active_connections"))
                    for sample in selected
                ),
                default=0,
            ),
        })
    return reports


def protocol_findings(
    native: Mapping[str, object],
    kernel: Mapping[str, object],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if native.get("diagnostic_level") != "full":
        findings.append(_finding(
            "critical",
            "native_coverage_incomplete",
            "Native client/server metrics do not cover every diagnostic stage.",
            "Use an instrumented Hydracore build for all testers before drawing a protocol-level conclusion.",
        ))
    server = _mapping(native.get("server"))
    counters = _combined_counters(native)
    gauges = _mapping(server.get("gauges"))
    if _sum_matching(counters, ("queue_drops", "no_worker", "peer_queue")):
        findings.append(_finding(
            "critical",
            "internal_queue_loss",
            "Hydracore dropped records because an internal worker or peer queue was full.",
            "Profile the single UDP unwrap path and worker queues; compare larger queues against latency and RSS.",
        ))
    retrans = _sum_matching(counters, ("kcp_retrans", "kcp_fast_retrans", "kcp_lost"))
    out_segments = _sum_matching(counters, ("kcp_out_segments",))
    if retrans and (not out_segments or retrans / max(1, out_segments) >= 0.1):
        findings.append(_finding(
            "warning",
            "kcp_retransmission_pressure",
            "KCP retransmission/loss counters are high relative to transmitted segments.",
            "Compare by tester, room and worker; tune KCP/window only after separating RTT from packet loss.",
        ))
    wait_p95 = _number(_mapping(gauges.get("kcp_wait_snd")).get("p95"))
    wait_p95 = max(wait_p95, _client_gauge_peak(native, "kcp_wait_snd"))
    if wait_p95 >= 1536:
        findings.append(_finding(
            "warning",
            "kcp_send_window_saturated",
            "KCP pending-send depth spent time near the current 2048-segment backpressure cap.",
            "Measure RTT and retransmissions, then test a larger adaptive window or congestion-control strategy.",
        ))
    if _sum_matching(counters, ("dtls_handshake_failure", "turn_failure", "vk_auth_failure")):
        findings.append(_finding(
            "warning",
            "worker_setup_failures",
            "VK authentication, TURN allocation or DTLS worker setup failed during the run.",
            "Use stage latency/failure distributions to isolate VK control plane, TURN endpoint or DTLS.",
        ))
    if any(
        _integer(kernel.get(key))
        for key in (
            "softnet_drops",
            "interface_rx_drops",
            "interface_tx_drops",
            "interface_rx_errors",
            "interface_tx_errors",
        )
    ):
        findings.append(_finding(
            "critical",
            "kernel_network_loss",
            "The kernel or network interface dropped packets during the experiment.",
            "Remove host/NIC loss before attributing retransmissions to VK TURN or the tunnel protocol.",
        ))
    return findings


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
        if key.endswith(("_total", "_bytes", "_packets", "_segments")):
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


def _sample_rates(samples: Sequence[Mapping[str, object]]) -> list[float]:
    rates: list[float] = []
    previous_at = 0.0
    previous_total = 0
    for sample in samples:
        timestamp = _number(sample.get("timestamp"))
        calls = _mapping(sample.get("calls"))
        interval = _mapping(calls.get("interval"))
        interval_bytes = _integer(interval.get("upload_bytes")) + _integer(
            interval.get("download_bytes"),
        )
        if interval_bytes and previous_at:
            rates.append(interval_bytes * 8 / max(0.001, timestamp - previous_at))
        elif previous_at:
            total = _integer(calls.get("upload_bytes")) + _integer(calls.get("download_bytes"))
            rates.append(max(0, total - previous_total) * 8 / max(0.001, timestamp - previous_at))
        previous_at = timestamp
        previous_total = _integer(calls.get("upload_bytes")) + _integer(calls.get("download_bytes"))
    return rates


def _nested_counter_delta(
    samples: Sequence[Mapping[str, object]],
    path: Sequence[str],
    key: str,
) -> int:
    values = _nested_values(samples, path, key)
    return int(_monotonic_series_delta(values))


def _nested_values(
    samples: Sequence[Mapping[str, object]],
    path: Sequence[str],
    key: str,
) -> list[float]:
    values: list[float] = []
    for sample in samples:
        current: object = sample
        for part in path:
            current = _mapping(current).get(part)
        value = _mapping(current).get(key)
        if type(value) in {int, float}:
            values.append(float(value))
    return values


def _conntrack_peak(samples: Sequence[Mapping[str, object]]) -> float:
    ratios = []
    for sample in samples:
        metrics = _mapping(_mapping(sample.get("kernel")).get("conntrack"))
        maximum = _integer(metrics.get("max"))
        if maximum:
            ratios.append(_integer(metrics.get("count")) / maximum)
    return round(max(ratios, default=0.0), 6)


def _sum_matching(values: Mapping[str, object], fragments: Sequence[str]) -> float:
    return sum(
        _number(value)
        for key, value in values.items()
        if any(fragment in str(key) for fragment in fragments)
    )


def _combined_counters(native: Mapping[str, object]) -> dict[str, float]:
    combined: dict[str, float] = {}
    summaries = [_mapping(native.get("server"))]
    summaries.extend(
        _mapping(summary)
        for summary in _mapping(native.get("clients")).values()
    )
    for summary in summaries:
        for key, value in _mapping(summary.get("counters")).items():
            name = str(key)
            combined[name] = combined.get(name, 0.0) + _number(value)
    return combined


def _client_gauge_peak(native: Mapping[str, object], key: str) -> float:
    return max(
        (
            _number(
                _mapping(
                    _mapping(_mapping(summary).get("gauges")).get(key),
                ).get("p95"),
            )
            for summary in _mapping(native.get("clients")).values()
        ),
        default=0.0,
    )


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


def _finding(severity: str, code: str, message: str, next_step: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "message": message, "next_step": next_step}


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


__all__ = ["analyze_kernel", "analyze_native", "phase_reports", "protocol_findings"]
