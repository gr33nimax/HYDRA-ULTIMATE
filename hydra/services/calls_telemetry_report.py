"""Pure aggregation for privacy-preserving Hydra VK Tunnel telemetry."""
from __future__ import annotations

import math
import time
from collections.abc import Mapping, Sequence

from hydra.services.calls_telemetry_correlations import throughput_correlations
from hydra.services.calls_telemetry_findings import extended_native_findings
from hydra.services.calls_telemetry_protocol_analysis import (
    analyze_kernel,
    analyze_native,
    phase_reports,
    protocol_findings,
)
from hydra.services.calls_telemetry_resource_report import build_resource_report


def build_calls_telemetry_report(
    session: Mapping[str, object],
    records: Sequence[Mapping[str, object]],
    *,
    now: float | None = None,
) -> dict[str, object]:
    """Build comparable rates, percentiles and actionable observations."""
    ordered = _ordered_samples(records)
    started_at = _number(session.get("started_at"))
    stopped_at = _number(session.get("stopped_at"))
    current = time.time() if now is None else now
    observed_until = stopped_at or current
    interval = max(1, _integer(session.get("sample_interval_seconds")))
    expected = max(0, math.floor(max(0.0, observed_until - started_at) / interval))
    sample_count = _integer(session.get("sample_count")) or len(ordered)
    coverage = min(1.0, sample_count / expected) if expected else 0.0
    last = ordered[-1] if ordered else {}

    calls_samples = [_mapping(sample.get("calls")) for sample in ordered]
    rates = _cumulative_rates(ordered, started_at, "calls")
    last_calls = _mapping(last.get("calls"))
    upload = _integer(last_calls.get("upload_bytes"))
    download = _integer(last_calls.get("download_bytes"))
    total = upload + download
    duration = max(
        0.0,
        (_number(last.get("timestamp")) - started_at) if ordered else 0.0,
    )

    active = [_integer(item.get("active_connections")) for item in calls_samples]
    attributed = sum(_integer(item.get("attributed_connections")) for item in calls_samples)
    tester_attributed = sum(
        _integer(item.get("tester_attributed_connections"))
        for item in calls_samples
    )
    active_sum = sum(active)
    attribution_ratio = attributed / active_sum if active_sum else 1.0
    tester_connection_ratio = tester_attributed / active_sum if active_sum else 1.0
    host_cpu = _counter_percentages(ordered, "host", "cpu_idle", "cpu_total")
    process_cpu = _process_cpu_percentages(ordered)
    host_memory = [
        _number(_mapping(sample.get("host")).get("memory_percent"))
        for sample in ordered
    ]
    process_rss = [
        _integer(_mapping(sample.get("runtime")).get("rss_bytes"))
        for sample in ordered
    ]
    udp = _udp_deltas(ordered)
    complete_analysis_set = len(ordered) >= sample_count
    gaps = _sample_gaps(ordered, interval) if complete_analysis_set else []
    testers = _tester_reports(session, ordered, started_at)
    tester_bytes = sum(_integer(tester.get("total_bytes")) for tester in testers)
    tester_traffic_ratio = tester_bytes / total if total else 1.0
    events = {
        str(key): _integer(value)
        for key, value in _mapping(session.get("events")).items()
    }
    native = analyze_native(
        records,
        [str(value) for value in session.get("tester_ids", [])],
    )
    native["analyzed_records"] = native["records"]
    native["records"] = _integer(session.get("native_record_count")) or native["records"]
    server_counters = _mapping(_mapping(native.get("server")).get("counters"))
    wire_breakdown = _native_wire_breakdown(server_counters)
    native["wire_breakdown"] = wire_breakdown
    wire_bytes = _number(wire_breakdown.get("outer_bytes"))
    native["goodput_wire_efficiency_ratio"] = (
        round(total / wire_bytes, 6) if wire_bytes else None
    )
    kernel = analyze_kernel(ordered)
    findings = _findings(
        coverage=coverage,
        attribution_ratio=attribution_ratio,
        tester_traffic_ratio=tester_traffic_ratio,
        host_cpu_p95=_percentile(host_cpu, 95),
        process_cpu_p95=_percentile(process_cpu, 95),
        memory_p95=_percentile(host_memory, 95),
        udp=udp,
        events=events,
    )
    findings.extend(protocol_findings(native, kernel))
    findings.extend(extended_native_findings(native))
    if not findings:
        findings.append(_finding(
            "info",
            "no_obvious_bottleneck_detected",
            "The collected server and native indicators show no obvious bottleneck.",
            "Compare marked workload phases and repeat the run to verify reproducibility.",
        ))
    phases = phase_reports(
        ordered,
        records,
        started_at=started_at,
        observed_until=observed_until,
    )

    return {
        "ok": True,
        "session_id": str(session.get("session_id", "")),
        "active": not bool(stopped_at),
        "window": {
            "started_at": started_at,
            "stopped_at": stopped_at or None,
            "elapsed_seconds": round(max(0.0, observed_until - started_at), 3),
            "sample_interval_seconds": interval,
            "samples": sample_count,
            "analyzed_samples": len(ordered),
            "expected_samples": expected,
            "coverage_ratio": round(coverage, 4),
            "data_duration_seconds": round(duration, 3),
            "gap_count": len(gaps),
            "max_gap_seconds": round(max(gaps, default=0.0), 3),
            "gaps_analyzed": complete_analysis_set,
        },
        "configuration": _public_configuration(session),
        "calls": {
            "upload_bytes": upload,
            "download_bytes": download,
            "total_bytes": total,
            "average_bps": round(total * 8 / duration, 3) if duration else 0.0,
            "throughput_bps": _distribution(rates),
            "active_connections": _distribution(active),
            "attribution_ratio": round(attribution_ratio, 4),
            "tester_connection_ratio": round(tester_connection_ratio, 4),
            "tester_traffic_ratio": round(tester_traffic_ratio, 4),
            "other_user_bytes": _integer(last_calls.get("other_user_upload_bytes"))
            + _integer(last_calls.get("other_user_download_bytes")),
            "unattributed_bytes": _integer(last_calls.get("unattributed_upload_bytes"))
            + _integer(last_calls.get("unattributed_download_bytes")),
            "connections_opened": _integer(last_calls.get("connections_opened")),
            "connections_closed": _integer(last_calls.get("connections_closed")),
            "short_connections": _integer(last_calls.get("short_connections")),
            "zero_byte_connections": _integer(
                last_calls.get("zero_byte_connections"),
            ),
            "counter_resets": _integer(last_calls.get("counter_resets")),
            "no_progress": dict(_mapping(last_calls.get("no_progress"))),
        },
        "testers": testers,
        "phases": phases,
        "correlations": throughput_correlations(ordered),
        "native": native,
        "resources": build_resource_report(
            ordered, host_cpu, process_cpu, host_memory, process_rss, udp, kernel,
        ),
        "events": events,
        "findings": findings,
        "limitations": ([
            "Exact RTT, loss, VK/TURN stage latency and internal queue diagnosis require native Hydracore records from every tester.",
        ] if native.get("diagnostic_level") != "full" else []) + [
            "UDP kernel counters are host-wide; listener queue drops are Calls-specific.",
            "Connections shorter than the traffic-daemon polling interval may be absent.",
        ],
    }


def _native_wire_breakdown(
    counters: Mapping[str, object],
) -> dict[str, float]:
    def combined(left: str, right: str) -> float:
        return _number(counters.get(left)) + _number(counters.get(right))

    return {
        "outer_bytes": round(combined("outer_bytes_in_total", "outer_bytes_out_total"), 3),
        "outer_payload_bytes": round(
            combined("outer_payload_bytes_in_total", "outer_payload_bytes_out_total"),
            3,
        ),
        "outer_overhead_bytes": round(
            combined("outer_overhead_bytes_in_total", "outer_overhead_bytes_out_total"),
            3,
        ),
        "kcp_output_bytes": round(_number(counters.get("kcp_out_bytes_total")), 3),
        "kcp_retransmit_bytes": round(
            _number(counters.get("kcp_retrans_bytes_total")),
            3,
        ),
        "kcp_fast_retransmit_estimate_bytes": (
            round(_number(counters.get("kcp_fast_retrans_estimate_bytes_total")), 3)
            if "kcp_fast_retrans_estimate_bytes_total" in counters else None
        ),
        "kcp_rto_retransmit_estimate_bytes": (
            round(_number(counters.get("kcp_rto_retrans_estimate_bytes_total")), 3)
            if "kcp_rto_retrans_estimate_bytes_total" in counters else None
        ),
        "relay_goodput_bytes": round(_number(counters.get("relay_bytes_total")), 3),
    }


def _ordered_samples(
    samples: Sequence[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    by_sequence: dict[int, Mapping[str, object]] = {}
    for sample in samples:
        if sample.get("kind", "sample") != "sample":
            continue
        sequence = _integer(sample.get("sequence"))
        if sequence > 0:
            by_sequence[sequence] = sample
    return sorted(
        by_sequence.values(),
        key=lambda item: (_number(item.get("timestamp")), _integer(item.get("sequence"))),
    )


def _cumulative_rates(
    samples: Sequence[Mapping[str, object]],
    started_at: float,
    key: str,
) -> list[float]:
    rates: list[float] = []
    previous_at = started_at
    previous_total = 0
    for sample in samples:
        current_at = _number(sample.get("timestamp"))
        current = _mapping(sample.get(key))
        total = _integer(current.get("upload_bytes")) + _integer(
            current.get("download_bytes"),
        )
        elapsed = current_at - previous_at
        if elapsed > 0:
            delta = total - previous_total if total >= previous_total else total
            rates.append(max(0.0, delta * 8 / elapsed))
        previous_at = current_at
        previous_total = total
    return rates


def _tester_reports(
    session: Mapping[str, object],
    samples: Sequence[Mapping[str, object]],
    started_at: float,
) -> list[dict[str, object]]:
    tester_ids = [str(value) for value in session.get("tester_ids", [])]
    reports: list[dict[str, object]] = []
    for tester_id in tester_ids:
        projected: list[dict[str, object]] = []
        active: list[int] = []
        for sample in samples:
            testers = _mapping(_mapping(sample.get("calls")).get("testers"))
            metrics = _mapping(testers.get(tester_id))
            projected.append({"timestamp": sample.get("timestamp"), "tester": metrics})
            active.append(_integer(metrics.get("active_connections")))
        rates = _cumulative_rates(projected, started_at, "tester")
        last_testers = (
            _mapping(_mapping(samples[-1].get("calls")).get("testers"))
            if samples
            else {}
        )
        last_metrics = _mapping(last_testers.get(tester_id))
        upload = _integer(last_metrics.get("upload_bytes"))
        download = _integer(last_metrics.get("download_bytes"))
        reports.append({
            "tester_id": tester_id,
            "upload_bytes": upload,
            "download_bytes": download,
            "total_bytes": upload + download,
            "throughput_bps": _distribution(rates),
            "active_connections": _distribution(active),
            "connections_opened": _integer(last_metrics.get("connections_opened")),
            "connections_closed": _integer(last_metrics.get("connections_closed")),
            "short_connections": _integer(last_metrics.get("short_connections")),
            "zero_byte_connections": _integer(
                last_metrics.get("zero_byte_connections"),
            ),
        })
    return reports


def _counter_percentages(
    samples: Sequence[Mapping[str, object]],
    section: str,
    idle_key: str,
    total_key: str,
) -> list[float]:
    values: list[float] = []
    previous: tuple[float, float] | None = None
    for sample in samples:
        metrics = _mapping(sample.get(section))
        current = (_number(metrics.get(idle_key)), _number(metrics.get(total_key)))
        if previous is not None:
            idle_delta = current[0] - previous[0]
            total_delta = current[1] - previous[1]
            if total_delta > 0:
                values.append(max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)))
        previous = current
    return values


def _process_cpu_percentages(
    samples: Sequence[Mapping[str, object]],
) -> list[float]:
    values: list[float] = []
    previous: tuple[float, int] | None = None
    for sample in samples:
        timestamp = _number(sample.get("timestamp"))
        runtime = _mapping(sample.get("runtime"))
        ticks = _integer(runtime.get("cpu_ticks"))
        ticks_per_second = max(1, _integer(runtime.get("clock_ticks_per_second")))
        if previous is not None and timestamp > previous[0] and ticks >= previous[1]:
            values.append((ticks - previous[1]) / ticks_per_second * 100 / (timestamp - previous[0]))
        previous = (timestamp, ticks)
    return values


def _udp_deltas(samples: Sequence[Mapping[str, object]]) -> dict[str, int]:
    keys = (
        "in_datagrams",
        "out_datagrams",
        "in_errors",
        "no_ports",
        "receive_buffer_errors",
        "send_buffer_errors",
        "listener_drops",
    )
    return {key: _counter_delta(samples, "udp", key) for key in keys} | {
        "max_listener_rx_queue_bytes": max(
            (
                _integer(_mapping(sample.get("udp")).get("listener_rx_queue_bytes"))
                for sample in samples
            ),
            default=0,
        ),
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


def _sample_gaps(
    samples: Sequence[Mapping[str, object]],
    interval: int,
) -> list[float]:
    timestamps = [_number(sample.get("timestamp")) for sample in samples]
    return [
        current - previous
        for previous, current in zip(timestamps, timestamps[1:])
        if current - previous > interval * 2.5
    ]


def _findings(
    *,
    coverage: float,
    attribution_ratio: float,
    tester_traffic_ratio: float,
    host_cpu_p95: float,
    process_cpu_p95: float,
    memory_p95: float,
    udp: Mapping[str, int],
    events: Mapping[str, int],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if coverage < 0.9:
        findings.append(_finding(
            "warning",
            "low_sample_coverage",
            "Less than 90% of scheduled samples were collected.",
            "Inspect hydra-traffic-daemon and Clash API availability before comparing throughput.",
        ))
    if attribution_ratio < 0.95:
        findings.append(_finding(
            "warning",
            "incomplete_user_attribution",
            "Some Calls connections were not attributed to an authenticated tester.",
            "Verify that Hydracore exports metadata.user for the call inbound.",
        ))
    if tester_traffic_ratio < 0.95:
        findings.append(_finding(
            "warning",
            "experiment_traffic_contamination",
            "Selected testers generated less than 95% of observed Calls traffic.",
            "Pause other Calls users or analyze tester-only totals before comparing protocol changes.",
        ))
    if udp.get("receive_buffer_errors", 0) or udp.get("listener_drops", 0):
        findings.append(_finding(
            "critical",
            "udp_receive_drops",
            "The kernel reported UDP receive-buffer or Calls-listener drops.",
            "Correlate drop timestamps with throughput, then inspect socket buffers and CPU scheduling.",
        ))
    if host_cpu_p95 >= 85 or process_cpu_p95 >= 85:
        findings.append(_finding(
            "warning",
            "cpu_pressure",
            "CPU usage reached a sustained high percentile during the session.",
            "Profile Hydracore at peak concurrency before changing worker counts or transport code.",
        ))
    if memory_p95 >= 90:
        findings.append(_finding(
            "warning",
            "memory_pressure",
            "Host memory usage stayed close to capacity.",
            "Repeat the test without co-located workloads and compare throughput and RSS.",
        ))
    if events.get("clash_api_unavailable", 0) or events.get("clash_api_disabled", 0):
        findings.append(_finding(
            "warning",
            "telemetry_source_unavailable",
            "The traffic source was unavailable during the experiment.",
            "Fix Clash API stability before treating connection and throughput percentiles as complete.",
        ))
    return findings


def _finding(severity: str, code: str, message: str, next_step: str) -> dict[str, str]:
    return {
        "severity": severity,
        "code": code,
        "message": message,
        "next_step": next_step,
    }


def _public_configuration(session: Mapping[str, object]) -> dict[str, object]:
    metadata = _mapping(session.get("metadata"))
    return {
        "hydra_version": str(metadata.get("hydra_version", "")),
        "state_schema": _integer(metadata.get("state_schema")),
        "kernel_provider": str(metadata.get("kernel_provider", "")),
        "calls": dict(_mapping(metadata.get("calls"))),
        "tester_count": len(session.get("tester_ids", [])),
    }


def _distribution(values: Sequence[float | int]) -> dict[str, float]:
    cleaned = [float(value) for value in values if math.isfinite(float(value))]
    return {
        "min": round(min(cleaned, default=0.0), 3),
        "p50": round(_percentile(cleaned, 50), 3),
        "p95": round(_percentile(cleaned, 95), 3),
        "p99": round(_percentile(cleaned, 99), 3),
        "max": round(max(cleaned, default=0.0), 3),
    }


def _percentile(values: Sequence[float | int], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    index = max(0, math.ceil(percentile / 100 * len(ordered)) - 1)
    return ordered[index]


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


__all__ = ["build_calls_telemetry_report"]
