"""Protocol-specific analysis for Hydracore Calls telemetry records."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.services.calls_telemetry_analysis_common import (
    _distribution,
    _integer,
    _mapping,
    _monotonic_series_delta,
    _number,
)
from hydra.services.calls_telemetry_native_analysis import analyze_native
from hydra.services.calls_telemetry_native_contract import (
    CLIENT_REQUIRED,
    CLIENT_SESSION_REQUIRED,
    CLIENT_WORKER_REQUIRED,
    SERVER_PROCESS_REQUIRED,
    SERVER_REQUIRED,
    SERVER_SESSION_REQUIRED,
    SERVER_WORKER_REQUIRED,
)

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
    findings = _continuity_findings(native)
    server = _mapping(native.get("server"))
    counters = _combined_counters(native)
    gauges = _mapping(server.get("gauges"))
    if _sum_matching(counters, ("queue_drops", "no_worker", "peer_queue")):
        findings.append(_finding(
            "critical",
            "internal_queue_loss",
            "Hydracore dropped packets in a UDP-ingress, peer-read or worker-send queue.",
            "Compare the individual queue counters and occupancy percentiles before changing their capacities.",
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
    server_paths = [
        report
        for report in native.get("server_sessions", [])
        if isinstance(report, Mapping)
    ]
    client_paths = [
        report
        for report in native.get("client_sessions", [])
        if isinstance(report, Mapping)
    ]
    downstream_pressure = any(
        _number(report.get("kcp_retransmission_ratio")) >= 0.1
        for report in server_paths
    ) or any(
        _number(
            _mapping(_mapping(report.get("gauges")).get("network_loss_ratio")).get("p95"),
        ) >= 0.05
        for report in client_paths
    )
    uplink_pressure = any(
        _number(report.get("kcp_retransmission_ratio")) >= 0.1
        for report in client_paths
    ) or any(
        _number(
            _mapping(_mapping(report.get("gauges")).get("network_loss_ratio")).get("p95"),
        ) >= 0.05
        for report in server_paths
    )
    if downstream_pressure and not uplink_pressure:
        findings.append(_finding(
            "critical",
            "downstream_transport_bottleneck",
            "Server-to-client KCP retransmission or client receive loss dominates the reverse direction.",
            "Compare client workers by TURN ordinal, wire rate and loss; "
            "then A/B downstream pacing, congestion control and KCP windows.",
        ))
    elif uplink_pressure and not downstream_pressure:
        findings.append(_finding(
            "critical",
            "uplink_transport_bottleneck",
            "Client-to-server KCP retransmission or server receive loss dominates the reverse direction.",
            "Compare server worker ingress and client TURN paths before tuning client-side pacing and send windows.",
        ))
    wait_p95 = _number(_mapping(gauges.get("kcp_wait_snd")).get("p95"))
    wait_p95 = max(
        wait_p95,
        _entity_gauge_peak(native, "server_sessions", "kcp_wait_snd"),
    )
    wait_p95 = max(wait_p95, _client_gauge_peak(native, "kcp_wait_snd"))
    if wait_p95 >= 1536:
        findings.append(_finding(
            "warning",
            "kcp_send_window_saturated",
            "KCP pending-send depth spent time near the current 2048-segment backpressure cap.",
            "Measure RTT and retransmissions, then test a larger adaptive window or congestion-control strategy.",
        ))
    stale_sessions = [
        report
        for report in native.get("server_sessions", [])
        if isinstance(report, Mapping)
        and _number(
            _mapping(_mapping(report.get("gauges")).get("worker_active")).get("max"),
        ) == 0
        and _number(
            _mapping(_mapping(report.get("gauges")).get("session_idle_seconds")).get("max"),
        ) >= 30
    ]
    if stale_sessions:
        findings.append(_finding(
            "warning",
            "stale_server_sessions",
            "The server retained one or more sessions with no live worker for at least 30 seconds.",
            "Use session IDs to verify idle reaping and exclude stale "
            "sessions from transport comparisons.",
        ))
    if _sum_matching(counters, ("dtls_handshake_failure", "turn_failure", "vk_auth_failure")):
        findings.append(_finding(
            "warning",
            "worker_setup_failures",
            "VK authentication, TURN allocation or DTLS worker setup failed during the run.",
            "Use stage latency/failure distributions to isolate VK control plane, TURN endpoint or DTLS.",
        ))
    if _worker_path_imbalance(native):
        findings.append(_finding(
            "warning",
            "worker_path_imbalance",
            "Parallel VK/TURN workers carried materially different wire rates.",
            "Compare TURN ordinal, loss, queue drops and reconnects per worker; deprioritize persistently weak paths.",
        ))
    if any(
        _integer(kernel.get(key))
        for key in (
            "softnet_drops",
            "interface_rx_drops",
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
    elif _integer(kernel.get("interface_tx_drops")):
        findings.append(_finding(
            "warning",
            "host_interface_tx_drops",
            "A host-wide network interface TX-drop counter increased during the experiment.",
            "Correlate it with the Calls listener and native UDP-ingress counters before attributing it to this tunnel.",
        ))
    return findings


def _continuity_findings(native: Mapping[str, object]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if native.get("diagnostic_level") != "full":
        findings.append(_finding(
            "critical",
            "native_coverage_incomplete",
            "Native client/server metrics do not cover every diagnostic stage.",
            "Use an instrumented Hydracore build for all testers before drawing a protocol-level conclusion.",
        ))
    continuity = _mapping(native.get("continuity"))
    if _sum_matching(
        continuity,
        (
            "control_drops",
            "server_record_drops",
            "client_record_drops",
            "lease_expirations",
            "missing_sequences",
        ),
    ):
        findings.append(_finding(
            "critical",
            "native_telemetry_discontinuity",
            "Native control or snapshot records were lost during the measurement window.",
            "Use per-tester continuity counters before comparing rates; "
            "repeat phases whose client sequence has gaps.",
        ))
    if _integer(continuity.get("sequence_resets")) or _integer(
        continuity.get("server_generations"),
    ) > 1:
        findings.append(_finding(
            "warning",
            "native_source_restarted",
            "The Calls inbound telemetry producer changed generation or reset its sequence during the run.",
            "Correlate the generation boundary with configuration apply, service logs and transport recovery time.",
        ))
    return findings


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


def _entity_gauge_peak(
    native: Mapping[str, object],
    entity: str,
    key: str,
) -> float:
    records = native.get(entity, [])
    if not isinstance(records, Sequence):
        return 0.0
    return max(
        (
            _number(
                _mapping(_mapping(record.get("gauges")).get(key)).get("p95"),
            )
            for record in records
            if isinstance(record, Mapping)
        ),
        default=0.0,
    )


def _worker_path_imbalance(native: Mapping[str, object]) -> bool:
    reports = native.get("client_workers", [])
    if not isinstance(reports, Sequence):
        return False
    rates_by_tester: dict[str, list[float]] = {}
    for report in reports:
        if not isinstance(report, Mapping):
            continue
        rate = _number(report.get("wire_bps"))
        if rate > 0:
            tester_id = str(report.get("tester_id", "")) or "unattributed"
            rates_by_tester.setdefault(tester_id, []).append(rate)
    return any(
        len(rates) >= 2
        and max(rates) >= 1_000_000
        and max(rates) / max(1, min(rates)) >= 2
        for rates in rates_by_tester.values()
    )


def _finding(severity: str, code: str, message: str, next_step: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "message": message, "next_step": next_step}


__all__ = ["analyze_kernel", "analyze_native", "phase_reports", "protocol_findings"]
