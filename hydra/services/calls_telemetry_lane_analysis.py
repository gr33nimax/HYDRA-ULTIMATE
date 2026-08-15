"""Findings for the four independent VK parasite KCP lanes."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.services.calls_telemetry_analysis_common import _mapping, _number


def lane_findings(native: Mapping[str, object]) -> list[dict[str, str]]:
    return [
        *_recovery_findings(native),
        *_worker_findings(native),
    ]


def _recovery_findings(native: Mapping[str, object]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    events = _mapping(native.get("events"))

    recovery = _mapping(native.get("lane_recovery"))
    attempts = _number(recovery.get("attempts"))
    unresolved = _number(recovery.get("unresolved"))
    matched = _number(recovery.get("matched_recoveries"))
    failed = _number(recovery.get("failed"))
    escalated = _number(recovery.get("escalated"))
    if attempts and unresolved:
        findings.append(_finding(
            "critical",
            "lane_recovery_incomplete",
            "A session-wide VK lane recovery started but no matching worker "
            "reattached before the telemetry window ended.",
            "Correlate the affected lane with TURN allocation, DTLS and "
            "worker-attach events; the other three lanes must remain active.",
        ))
    if failed:
        findings.append(_finding(
            "critical",
            "lane_recovery_failed",
            "Hydracore could not restore a stalled VK lane before its "
            "bounded recovery deadline.",
            "Correlate the failed lane with TURN allocation, DTLS and worker "
            "attach events; verify that session replacement restored traffic.",
        ))
    if escalated:
        findings.append(_finding(
            "warning",
            "lane_recovery_escalated",
            "A stalled VK lane escalated to a complete logical-session "
            "replacement instead of remaining unresolved.",
            "Measure the replacement interruption and verify that all four "
            "lanes resumed without restarting the client application.",
        ))
    if attempts and matched:
        findings.append(_finding(
            "warning",
            "lane_recovery_succeeded",
            "Hydracore recovered a saturated VK lane without recycling the "
            "other three calls.",
            "Use recovery p95 and per-lane WaitSnd/loss to decide whether the "
            "path needs earlier replacement or only lower send pressure.",
        ))
    if _number(events.get("lane_send_stalled")) and not attempts:
        findings.append(_finding(
            "critical",
            "lane_send_stall_terminal",
            "A KCP send stall had no observed matching lane-recovery attempt.",
            "Check telemetry continuity and whether all four physical workers "
            "were already absent when the logical session closed.",
        ))
    if _number(events.get("lane_reorder_timeout")):
        findings.append(_finding(
            "critical",
            "lane_reorder_timeout_recovery",
            "Hydracore closed a logical session because a per-flow lane "
            "sequence gap did not recover.",
            "Inspect the missing flow's lane loss and reconnect boundary, "
            "then verify that the replacement session resumed without an "
            "application restart.",
        ))
    if _number(events.get("lane_udp_reorder_timeout")):
        findings.append(_finding(
            "warning",
            "lane_udp_reorder_timeout",
            "One striped UDP/QUIC flow had a sequence gap that outlived the "
            "bounded cleanup window.",
            "Compare physical loss and reconnects on the four lanes; the gap "
            "was isolated to that flow and did not close the logical tunnel.",
        ))
    if _number(events.get("network_rebind_lane_failed")):
        findings.append(_finding(
            "warning",
            "network_rebind_lane_failed",
            "A staged Android network handover could not replace one VK/TURN "
            "lane in time.",
            "Inspect that lane's VK authentication, TURN allocation and DTLS "
            "events; the remaining lanes were intentionally kept alive.",
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
    "server_process_gauge_peak",
]
