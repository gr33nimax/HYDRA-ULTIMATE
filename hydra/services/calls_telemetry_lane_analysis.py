"""Findings for the four independent VK parasite KCP lanes."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.services.calls_telemetry_analysis_common import _mapping, _number
from hydra.services.calls_telemetry_transport_diagnostics import recovery_findings


def lane_findings(native: Mapping[str, object]) -> list[dict[str, str]]:
    return [
        *_wire_v7_findings(native),
        *recovery_findings(native),
        *_worker_findings(native),
        *_pipeline_findings(native),
    ]


def _wire_v7_findings(native: Mapping[str, object]) -> list[dict[str, str]]:
    workers = _current_workers(native)
    sessions = [
        *current_reports(native, "server_sessions"),
        *current_reports(native, "client_sessions"),
    ]
    if not any(
        "lane_pacing_bytes_per_second" in _mapping(report.get("gauges"))
        for report in workers
    ):
        return []
    findings: list[dict[str, str]] = []
    carrying = [report for report in workers if _number(report.get("wire_bps")) > 0]
    retry_ratios = [
        _number(report.get("kcp_retransmission_ratio"))
        for report in carrying
        if report.get("kcp_retransmission_ratio") is not None
    ]
    capacity_ceiling = any(_is_capacity_ceiling(group) for group in _wire_v7_groups(native))
    if capacity_ceiling:
        findings.append(_finding(
            "info",
            "physical_capacity_ceiling",
            "All four demand-limited VK lanes delivered close to their paced "
            "rates without material retransmission.",
            "Treat the measured aggregate as the current four-call physical "
            "capacity ceiling; further growth needs a different media/path model.",
        ))
    minimum_pacing = min(
        (
            _gauge(report, "lane_pacing_bytes_per_second", "p50")
            for report in carrying
            if _gauge(report, "lane_pacing_bytes_per_second", "p50") > 0
        ),
        default=0.0,
    )
    demand_limited = any(not _application_limited(report) for report in carrying)
    if demand_limited and (
        minimum_pacing and minimum_pacing <= 40_000
        and max(retry_ratios, default=0.0) >= 0.10
    ):
        findings.append(_finding(
            "critical",
            "congestion_pacing_collapse",
            "The wire-v9 lane controller backed a demand-limited lane down "
            "close to its minimum under retransmission pressure.",
            "Compare pacing versus delivered rate, minRTT inflation and output "
            "queue growth; replace the degraded path before raising its limit.",
        ))
    events = _mapping(native.get("events"))
    reset_requests = _counter_total(workers, "lane_reset_request_total")
    reset_commits = _counter_total(workers, "lane_reset_commit_total")
    failed_probe = any(
        _gauge(report, "lane_probe_result", "p95") == 0
        and _counter_total([report], "lane_reset_request_total") > 0
        for report in workers
    )
    if _number(events.get("lane_reset_failed")) or (
        reset_requests > reset_commits and failed_probe
    ):
        findings.append(_finding(
            "critical",
            "lane_reset_failed",
            "A generation reset did not reach commit and a successful "
            "bidirectional KCP probe within the observation window.",
            "Inspect RESET retry/ACK/commit counters, stale-generation drops "
            "and TURN reconnect latency for the affected lane.",
        ))
    replacements = _counter_total(sessions, "session_replacement_total")
    if _number(events.get("session_replacement")) or replacements:
        findings.append(_finding(
            "critical",
            "full_session_replacement",
            "Hydracore replaced the complete logical VK session after aggregate "
            "no-progress or multi-lane quarantine.",
            "Confirm that a new native session appeared within ten seconds and "
            "traffic resumed without restarting the application.",
        ))
    return findings


def _wire_v7_groups(
    native: Mapping[str, object],
) -> list[list[Mapping[str, object]]]:
    complete: list[list[Mapping[str, object]]] = []
    for entity in ("server_workers", "client_workers"):
        grouped: dict[tuple[str, str], list[Mapping[str, object]]] = {}
        for report in current_reports(native, entity):
            key = (
                str(report.get("tester_id", "")),
                str(report.get("native_session_id", "")),
            )
            grouped.setdefault(key, []).append(report)
        for reports in grouped.values():
            lane_ids = {
                int(worker_id)
                for report in reports
                if isinstance(worker_id := report.get("worker_id"), (int, float))
            }
            if lane_ids == set(range(4)):
                complete.append(reports)
    return complete


def _is_capacity_ceiling(reports: Sequence[Mapping[str, object]]) -> bool:
    carrying = [report for report in reports if _number(report.get("wire_bps")) > 0]
    pacing = sum(
        _gauge(report, "lane_pacing_bytes_per_second", "p95")
        for report in carrying
    )
    delivered = sum(
        _gauge(report, "lane_delivered_bytes_per_second", "p95")
        for report in carrying
    )
    retry_ratios = [
        _number(report.get("kcp_retransmission_ratio"))
        for report in carrying
        if report.get("kcp_retransmission_ratio") is not None
    ]
    return bool(
        len(carrying) == 4
        and pacing > 0
        and delivered >= 0.8 * pacing
        and max(retry_ratios, default=0.0) < 0.15
        and not any(_application_limited(report) for report in carrying)
    )


def _application_limited(report: Mapping[str, object]) -> bool:
    return _gauge(report, "lane_application_limited", "p50") >= 0.5


def lane_pipeline_summary(native: Mapping[str, object]) -> dict[str, object]:
    """Summarize the debug.23 KCP-to-TURN pipeline without double counting."""
    workers = _current_workers(native)
    sessions = [
        *current_reports(native, "server_sessions"),
        *current_reports(native, "client_sessions"),
    ]
    gauge_names = (
        "kcp_output_queue_depth",
        "kcp_output_queue_capacity",
        "lane_admission_window_segments",
        "worker_write_latency_ms",
    )
    counter_names = (
        "kcp_update_backpressure_total",
        "kcp_mutex_blocked_seconds_total",
    )
    available = any(
        any(name in _mapping(report.get("gauges")) for name in gauge_names)
        or any(name in _mapping(report.get("counters")) for name in counter_names)
        for report in workers
    ) or any(
        "flow_reorder_abort_total" in _mapping(report.get("counters"))
        for report in sessions
    )
    output_depth = max(
        (_gauge(report, "kcp_output_queue_depth", "p95") for report in workers),
        default=0.0,
    )
    output_capacity = max(
        (_gauge(report, "kcp_output_queue_capacity", "max") for report in workers),
        default=0.0,
    )
    admission_p50 = [
        _gauge(report, "lane_admission_window_segments", "p50")
        for report in workers
        if "lane_admission_window_segments" in _mapping(report.get("gauges"))
    ]
    admission_p95 = [
        _gauge(report, "lane_admission_window_segments", "p95")
        for report in workers
        if "lane_admission_window_segments" in _mapping(report.get("gauges"))
    ]
    return {
        "available": available,
        "output_queue_depth_p95": round(output_depth, 3),
        "output_queue_capacity": round(output_capacity, 3),
        "output_queue_utilization_ratio": (
            round(output_depth / output_capacity, 6) if output_capacity else None
        ),
        "admission_window_p50_min": round(min(admission_p50, default=0.0), 3),
        "admission_window_p95_max": round(max(admission_p95, default=0.0), 3),
        "worker_write_latency_p95_ms": round(max(
            (_gauge(report, "worker_write_latency_ms", "p95") for report in workers),
            default=0.0,
        ), 3),
        "update_backpressure_total": round(_counter_total(
            workers,
            "kcp_update_backpressure_total",
        ), 3),
        "mutex_blocked_seconds_total": round(_counter_total(
            workers,
            "kcp_mutex_blocked_seconds_total",
        ), 6),
        "flow_reorder_abort_total": round(_counter_total(
            sessions,
            "flow_reorder_abort_total",
        ), 3),
    }


def _pipeline_findings(native: Mapping[str, object]) -> list[dict[str, str]]:
    raw = native.get("lane_pipeline")
    pipeline = (
        raw if isinstance(raw, Mapping) and raw.get("available")
        else lane_pipeline_summary(native)
    )
    if not pipeline.get("available"):
        return []
    findings: list[dict[str, str]] = []
    utilization = _number(pipeline.get("output_queue_utilization_ratio"))
    update_backpressure = _number(pipeline.get("update_backpressure_total"))
    if update_backpressure or utilization >= 0.75:
        findings.append(_finding(
            "critical" if update_backpressure else "warning",
            "kcp_output_staging_backpressure",
            "The staged KCP output queue filled far enough to delay or pause "
            "KCP updates on at least one VK lane.",
            "Compare output queue occupancy with physical write latency and "
            "ACK progress; fix the writer or path before increasing KCP windows.",
        ))
    mutex_blocked = _number(pipeline.get("mutex_blocked_seconds_total"))
    if mutex_blocked >= 0.05:
        findings.append(_finding(
            "warning",
            "kcp_mutex_contention",
            "KCP input or update work accumulated measurable waits on a lane mutex.",
            "Correlate mutex-blocked time with output staging and CPU pressure; "
            "profile the remaining work performed while the lane lock is held.",
        ))
    write_latency = _number(pipeline.get("worker_write_latency_p95_ms"))
    if write_latency >= 20:
        findings.append(_finding(
            "warning",
            "worker_physical_write_latency",
            "Physical TURN/DTLS writes reached at least twice the 10 ms KCP update interval.",
            "Split by side and lane, then compare TURN endpoint, socket pressure "
            "and scheduler latency before changing KCP retransmission settings.",
        ))
    if _number(pipeline.get("flow_reorder_abort_total")):
        findings.append(_finding(
            "warning",
            "ordered_flow_reorder_abort",
            "Hydracore isolated one or more ordered flows after an unrecoverable sequence gap.",
            "Correlate each abort with its lane reconnect and loss boundary; "
            "verify that unrelated flows and the logical tunnel remained alive.",
        ))
    return findings


def _worker_findings(native: Mapping[str, object]) -> list[dict[str, str]]:
    workers = _current_workers(native)
    findings: list[dict[str, str]] = []
    for report in workers:
        counters = _mapping(report.get("counters"))
        out_segments = _number(counters.get("kcp_out_segments_total"))
        ack_ratio = report.get("kcp_ack_progress_ratio")
        rtt_coverage = report.get("kcp_rtt_sample_coverage_ratio")
        if out_segments >= 100 and ack_ratio and rtt_coverage == 0:
            findings.append(_finding(
                "critical",
                "lane_rtt_sampling_missing",
                "KCP made ACK progress but produced no timestamp-matched RTT "
                "samples.",
                "Verify that both client and VPS run Hydracore debug.22 "
                "before interpreting RTO or path latency.",
            ))
            break
        if (
            out_segments >= 100
            and isinstance(ack_ratio, (int, float))
            and ack_ratio < 0.5
        ):
            findings.append(_finding(
                "warning",
                "lane_ack_progress_deficit",
                "A VK lane acknowledged fewer than half of its observed KCP "
                "output segments.",
                "Compare ACK progress, in-flight depth, RTO share and TURN "
                "loss on that lane before changing its window.",
            ))
            break

    active_by_session: dict[tuple[str, str, str], set[int]] = {}
    for side, entity in (("server", "server_workers"), ("client", "client_workers")):
        records = native.get(entity, [])
        if not isinstance(records, Sequence):
            continue
        for report in records:
            if not isinstance(report, Mapping) or not _is_current(report):
                continue
            worker_id = report.get("worker_id")
            if type(worker_id) is not int or not bool(report.get("active")):
                continue
            key = (
                side,
                str(report.get("tester_id", "")),
                str(report.get("native_session_id", "")),
            )
            active_by_session.setdefault(key, set()).add(worker_id)
    incomplete = [
        key for key, lane_ids in active_by_session.items()
        if lane_ids != set(range(4))
    ]
    if incomplete:
        findings.append(_finding(
            "critical",
            "four_lane_session_incomplete",
            "An active VK parasite session did not have all four independent KCP lanes.",
            "Compare worker attach/reconnect events by tester and lane; do "
            "not tune KCP until lanes 0..3 stay active.",
        ))

    carrying = [
        report for report in workers
        if _number(report.get("wire_bps")) > 0
    ]
    ratios = [
        _number(report.get("kcp_retransmission_ratio"))
        for report in carrying
        if report.get("kcp_retransmission_ratio") is not None
    ]
    if ratios and max(ratios) >= 0.1 and max(ratios) >= 2.5 * max(0.01, min(ratios)):
        findings.append(_finding(
            "warning",
            "lane_kcp_imbalance",
            "One independent KCP lane retransmitted materially more than the other VK calls.",
            "Compare that lane's TURN ordinal, RTT, WaitSnd and output "
            "queue; quarantine or reduce only the degraded lane.",
        ))

    rtts = [
        _gauge(report, "kcp_rtt_ms", "p95")
        for report in carrying
        if _gauge(report, "kcp_rtt_ms", "p95") > 0
    ]
    if len(rtts) >= 2 and max(rtts) >= min(rtts) + 150:
        findings.append(_finding(
            "warning",
            "lane_rtt_imbalance",
            "The four VK/TURN lanes had materially different KCP RTT.",
            "Prefer low-RTT lanes for new frames and keep the slow lane as "
            "reduced-capacity or standby.",
        ))
    admission_rates = [
        _gauge(report, "lane_admission_bytes_per_second", "p95")
        for report in carrying
        if _gauge(report, "lane_admission_bytes_per_second", "p95") > 0
    ]
    if (
        admission_rates
        and min(admission_rates) <= 110_000
        and ratios
        and max(ratios) >= 0.1
    ):
        findings.append(_finding(
            "warning",
            "lane_admission_backoff",
            "The pre-KCP controller reduced at least one lane close to its "
            "minimum rate under retry pressure.",
            "Compare that lane's TURN ordinal, physical loss and KCP retries; "
            "replace the path instead of increasing its KCP window.",
        ))
    return findings


def current_reports(
    native: Mapping[str, object],
    entity: str,
) -> list[Mapping[str, object]]:
    records = native.get(entity, [])
    if not isinstance(records, Sequence):
        return []
    return [record for record in records if isinstance(record, Mapping) and _is_current(record)]


def entity_gauge_peak(
    native: Mapping[str, object],
    entity: str,
    key: str,
) -> float:
    return max(
        (_gauge(report, key, "p95") for report in current_reports(native, entity)),
        default=0.0,
    )


def client_gauge_peak(native: Mapping[str, object], key: str) -> float:
    if "server_processes" in native:
        return entity_gauge_peak(native, "client_sessions", key)
    return max(
        (
            _number(
                _mapping(_mapping(_mapping(summary).get("gauges")).get(key)).get("p95"),
            )
            for summary in _mapping(native.get("clients")).values()
        ),
        default=0.0,
    )


def server_process_gauge_peak(
    native: Mapping[str, object],
    key: str,
) -> float:
    if "server_processes" in native:
        return entity_gauge_peak(native, "server_processes", key)
    return _number(
        _mapping(_mapping(_mapping(native.get("server")).get("gauges")).get(key)).get("p95"),
    )


def _current_workers(native: Mapping[str, object]) -> list[Mapping[str, object]]:
    workers: list[Mapping[str, object]] = []
    for entity in ("server_workers", "client_workers"):
        records = native.get(entity, [])
        if not isinstance(records, Sequence):
            continue
        workers.extend(
            report for report in records
            if isinstance(report, Mapping) and _is_current(report)
        )
    return workers


def _is_current(report: Mapping[str, object]) -> bool:
    return "current" not in report or bool(report.get("current"))


def _gauge(report: Mapping[str, object], name: str, field: str) -> float:
    return _number(_mapping(_mapping(report.get("gauges")).get(name)).get(field))


def _counter_total(
    reports: Sequence[Mapping[str, object]],
    name: str,
) -> float:
    return sum(
        _number(_mapping(report.get("counters")).get(name))
        for report in reports
    )


def _finding(
    severity: str,
    code: str,
    message: str,
    next_step: str,
) -> dict[str, str]:
    return {
        "severity": severity,
        "code": code,
        "message": message,
        "next_step": next_step,
    }


__all__ = [
    "client_gauge_peak",
    "current_reports",
    "entity_gauge_peak",
    "lane_findings",
    "lane_pipeline_summary",
    "server_process_gauge_peak",
]
