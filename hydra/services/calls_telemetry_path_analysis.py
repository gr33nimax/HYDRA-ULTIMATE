"""Findings for the four-call adaptive VK path controller."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.services.calls_telemetry_analysis_common import _mapping, _number


def multipath_findings(
    native: Mapping[str, object],
    retransmission_pressure: bool,
    server_paths: Sequence[Mapping[str, object]],
    client_paths: Sequence[Mapping[str, object]],
) -> list[dict[str, str]]:
    adaptive = any(
        _gauge(report, "multipath_profile", "max") >= 0.5
        for report in (*server_paths, *client_paths)
    )
    if retransmission_pressure and not adaptive:
        return [_finding(
            "warning",
            "legacy_multipath_reordering",
            "The run used packet-striped legacy multipath while KCP "
            "retransmissions were high.",
            "Repeat the same marked workload with the adaptive profile; "
            "compare goodput, stalls, retransmissions and WaitSnd.",
        )]
    if not adaptive:
        return []

    findings: list[dict[str, str]] = []
    workers = _current_workers(native)
    carrying = [
        report
        for report in workers
        if _recent_counter(report, "worker_path_attempt_segments_total") >= 8
        or _latest(report, "worker_path_inflight_segments") > 0
    ]
    feedback_missing = any(
        _latest(report, "worker_path_feedback_capable") < 0.5
        or (
            _recent_counter(report, "worker_path_feedback_acked_packets_total")
            + _recent_counter(report, "worker_path_feedback_lost_packets_total")
        ) == 0
        or _latest(report, "worker_path_feedback_age_ms") >= 2_000
        for report in carrying
    )
    if feedback_missing:
        findings.append(_finding(
            "critical",
            "adaptive_path_feedback_missing",
            "A traffic-carrying VK path did not return fresh physical-packet "
            "feedback.",
            "Verify that VPS and client both run the paired debug Hydracore; "
            "then compare feedback age and packet counters per one of the "
            "four workers.",
        ))

    physical_loss = max(
        (_latest(report, "worker_path_loss_ratio") for report in carrying),
        default=0.0,
    )
    backoffs = sum(
        _recent_counter(report, "worker_path_backoff_total")
        for report in carrying
    )
    if physical_loss >= 0.1 or backoffs > 0:
        findings.append(_finding(
            "warning",
            "adaptive_physical_path_loss",
            "The adaptive controller observed physical packet loss or a "
            "feedback timeout on at least one VK/TURN call.",
            "Compare path loss, feedback age, delivered rate and window/flight "
            "by TURN ordinal; the controller will reduce only the affected call.",
        ))

    retry_pressure = max(
        (_retry_ratio(report) for report in carrying),
        default=0.0,
    )
    if retry_pressure >= 0.1 and physical_loss < 0.1:
        findings.append(_finding(
            "warning",
            "adaptive_kcp_retry_without_path_loss",
            "KCP retries remained high without matching physical loss on the "
            "four VK paths.",
            "Inspect shared KCP ordering, ACK/control delivery and WaitSnd; do "
            "not penalize an individual TURN path from this counter.",
        ))
    return findings


def current_reports(
    native: Mapping[str, object],
    entity: str,
) -> list[Mapping[str, object]]:
    records = native.get(entity, [])
    if not isinstance(records, Sequence):
        return []
    return [
        record
        for record in records
        if isinstance(record, Mapping)
        and ("current" not in record or bool(record.get("current")))
    ]


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
                _mapping(
                    _mapping(_mapping(summary).get("gauges")).get(key),
                ).get("p95"),
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
        _mapping(
            _mapping(_mapping(native.get("server")).get("gauges")).get(key),
        ).get("p95"),
    )


def _current_workers(
    native: Mapping[str, object],
) -> list[Mapping[str, object]]:
    workers: list[Mapping[str, object]] = []
    for entity in ("server_workers", "client_workers"):
        records = native.get(entity, [])
        if not isinstance(records, Sequence):
            continue
        workers.extend(
            report
            for report in records
            if isinstance(report, Mapping)
            and ("current" not in report or bool(report.get("current")))
        )
    return workers


def _retry_ratio(report: Mapping[str, object]) -> float:
    attempts = _recent_counter(report, "worker_path_attempt_segments_total")
    retransmissions = _recent_counter(
        report,
        "worker_path_retrans_segments_total",
    )
    if attempts > 0:
        return retransmissions / attempts
    exact = report.get("worker_path_retransmission_ratio")
    if isinstance(exact, (int, float)) and not isinstance(exact, bool):
        return float(exact)
    return _gauge(report, "worker_path_retry_ratio", "p95")


def _gauge(report: Mapping[str, object], name: str, field: str) -> float:
    return _number(_mapping(_mapping(report.get("gauges")).get(name)).get(field))


def _latest(report: Mapping[str, object], name: str) -> float:
    latest = _mapping(report.get("latest"))
    if name in latest:
        return _number(latest.get(name))
    return _gauge(report, name, "max")


def _counter(report: Mapping[str, object], name: str) -> float:
    return _number(_mapping(report.get("counters")).get(name))


def _recent_counter(report: Mapping[str, object], name: str) -> float:
    recent = _mapping(report.get("recent_counters"))
    if recent:
        return _number(recent.get(name))
    return _counter(report, name)


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
    "multipath_findings",
    "server_process_gauge_peak",
]
