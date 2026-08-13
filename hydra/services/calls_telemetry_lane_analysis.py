"""Findings for the four independent VK parasite KCP lanes."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.services.calls_telemetry_analysis_common import _mapping, _number


def lane_findings(native: Mapping[str, object]) -> list[dict[str, str]]:
    workers = _current_workers(native)
    findings: list[dict[str, str]] = []

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
        if lane_ids != {0, 1, 2, 3}
    ]
    if incomplete:
        findings.append(_finding(
            "critical",
            "four_lane_session_incomplete",
            "An active VK parasite session did not have all four independent KCP lanes.",
            "Compare worker attach/reconnect events by tester and lane; do not tune KCP until lanes 0..3 stay active.",
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
            "Compare that lane's TURN ordinal, RTT, WaitSnd and output queue; quarantine or reduce only the degraded lane.",
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
            "Prefer low-RTT lanes for new frames and keep the slow lane as reduced-capacity or standby.",
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
