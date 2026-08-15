"""Hydracore transport recovery and retransmission diagnostics."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.services.calls_telemetry_analysis_common import (
    _distribution,
    _number,
)


def lane_recovery_summary(
    records: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    events = sorted(
        (
            record
            for record in records
            if record.get("native_kind") == "event"
            and record.get("event") in {
                "lane_send_stalled",
                "lane_send_recovery",
                "lane_send_recovered",
                "lane_send_recovery_failed",
                "lane_send_recovery_escalated",
            }
        ),
        key=lambda record: _number(record.get("timestamp")),
    )
    pending: dict[tuple[str, str, str, int | None], list[float]] = {}
    durations: list[float] = []
    stalls = 0
    attempts = 0
    recovered = 0
    failed = 0
    escalated = 0
    for record in events:
        event = str(record.get("event", ""))
        if event == "lane_send_stalled":
            stalls += 1
            continue
        worker = record.get("worker_id")
        key = (
            str(record.get("native_scope", "")),
            str(record.get("tester_id", "")),
            str(record.get("native_session_id", "")),
            int(worker) if type(worker) is int else None,
        )
        timestamp = _number(record.get("timestamp"))
        if event == "lane_send_recovery":
            attempts += 1
            pending.setdefault(key, []).append(timestamp)
        elif event == "lane_send_recovered":
            recovered += 1
            starts = pending.get(key)
            if starts:
                durations.append(max(0.0, timestamp - starts.pop(0)))
        elif event in {"lane_send_recovery_failed", "lane_send_recovery_escalated"}:
            if event == "lane_send_recovery_failed":
                failed += 1
            else:
                escalated += 1
            starts = pending.get(key)
            if starts:
                starts.pop(0)
    unresolved = sum(len(starts) for starts in pending.values())
    matched = len(durations)
    return {
        "stalls": stalls,
        "attempts": attempts,
        "recovered": recovered,
        "failed": failed,
        "escalated": escalated,
        "matched_recoveries": matched,
        "orphan_recovered": max(0, recovered - matched),
        "unresolved": unresolved,
        "success_ratio": round(matched / attempts, 6) if attempts else None,
        "duration_seconds": _distribution(durations),
    }


def retransmission_findings(
    native: Mapping[str, object],
    counters: Mapping[str, object],
    *,
    pressure: bool,
) -> list[dict[str, str]]:
    if not pressure:
        return []
    findings = [_finding(
        "warning",
        "kcp_retransmission_pressure",
        "KCP retransmission/loss counters are high relative to transmitted segments.",
        "Compare by tester, room and worker; tune KCP/window only after separating RTT from packet loss.",
    )]
    fast_retrans = _number(
        counters.get("kcp_fast_retrans_estimate_segments_total"),
    )
    rto_retrans = _number(
        counters.get("kcp_rto_retrans_estimate_segments_total"),
    )
    classified = fast_retrans + rto_retrans
    if classified and rto_retrans / classified >= 0.6:
        findings.append(_finding(
            "warning",
            "kcp_rto_retransmission_dominant",
            "Estimated KCP timeout retransmissions dominate fast-resend retransmissions.",
            "Treat physical path loss, RTT inflation or a blocked TURN writer "
            "as the primary vector; compare RTO share with outer loss and "
            "output-queue delay per lane.",
        ))
    elif classified and fast_retrans / classified >= 0.6:
        findings.append(_finding(
            "warning",
            "kcp_fast_retransmission_dominant",
            "Estimated KCP fast-resend retransmissions dominate timeout retransmissions.",
            "Inspect burst loss and ACK progression per lane before changing "
            "fast-resend; verify against outer loss because this reason split "
            "is explicitly an estimate.",
        ))
    return findings


def retransmission_report(
    counters: Mapping[str, object],
) -> dict[str, float | None]:
    out_segments = _number(counters.get("kcp_out_segments_total"))
    retrans = _number(counters.get("kcp_retrans_segments_total"))
    fast_name = "kcp_fast_retrans_estimate_segments_total"
    rto_name = "kcp_rto_retrans_estimate_segments_total"
    fast_available = fast_name in counters
    rto_available = rto_name in counters
    fast = _number(counters.get(fast_name))
    rto = _number(counters.get(rto_name))
    ack_progress_name = "kcp_ack_progress_segments_total"
    rtt_samples_name = "kcp_rtt_samples_total"
    ack_progress = _number(counters.get(ack_progress_name))
    rtt_samples = _number(counters.get(rtt_samples_name))
    return {
        "kcp_retransmission_ratio": (
            round(retrans / out_segments, 6) if out_segments else None
        ),
        "kcp_fast_retransmission_ratio": (
            round(fast / out_segments, 6)
            if out_segments and fast_available else None
        ),
        "kcp_rto_retransmission_ratio": (
            round(rto / out_segments, 6)
            if out_segments and rto_available else None
        ),
        "kcp_fast_retransmission_share": (
            round(fast / retrans, 6) if retrans and fast_available else None
        ),
        "kcp_rto_retransmission_share": (
            round(rto / retrans, 6) if retrans and rto_available else None
        ),
        "kcp_ack_progress_ratio": (
            round(ack_progress / out_segments, 6)
            if out_segments and ack_progress_name in counters else None
        ),
        "kcp_rtt_sample_coverage_ratio": (
            round(rtt_samples / ack_progress, 6)
            if ack_progress and rtt_samples_name in counters else None
        ),
    }


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
    "lane_recovery_summary",
    "retransmission_findings",
    "retransmission_report",
]
