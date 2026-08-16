"""Native Hydracore diagnostics rendering for Calls telemetry."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.cli_format import scalar, table
from hydra.cli_render_calls_common import (
    bitrate as _bitrate,
    bytes_value as _bytes,
    counter as _counter,
    gauge as _gauge,
    percent as _percent,
    short_id as _short_id,
)


def _retrans_reason(report: Mapping[str, object]) -> str:
    fast = report.get("kcp_fast_retransmission_ratio")
    rto = report.get("kcp_rto_retransmission_ratio")
    if fast is None and rto is None:
        return "-"
    return f"{_percent(fast)}/{_percent(rto)}"


def append_native_diagnostics(
    lines: list[str],
    native: Mapping[str, object],
    *,
    detailed: bool,
) -> None:
    coverage = native.get("tester_coverage")
    coverage_map = coverage if isinstance(coverage, Mapping) else {}
    missing = native.get("missing_entities")
    missing_items = [str(value) for value in missing] if isinstance(missing, Sequence) else []
    missing_groups = native.get("missing_groups")
    group_items = (
        [str(value) for value in missing_groups]
        if isinstance(missing_groups, Sequence)
        else []
    )
    continuity = native.get("continuity")
    continuity_map = continuity if isinstance(continuity, Mapping) else {}
    lines.extend([
        "",
        "Native diagnostics",
        (
            f"  Coverage: {scalar(native.get('diagnostic_level', 'unavailable'))}"
            f"  |  records {scalar(native.get('records', 0))}"
            f"  |  testers {scalar(len(coverage_map))}"
        ),
        (
            "  Continuity: "
            f"gaps={scalar(continuity_map.get('gap_count', 0))}, "
            f"missing_seq={scalar(continuity_map.get('missing_sequences', 0))}, "
            f"seq_reset={scalar(continuity_map.get('sequence_resets', 0))}, "
            f"generations={scalar(continuity_map.get('server_generations', 0))}, "
            f"control_drop={scalar(continuity_map.get('control_drops', 0))}, "
            f"client_drop={scalar(continuity_map.get('client_record_drops', 0))}, "
            f"server_drop={scalar(continuity_map.get('server_record_drops', 0))}, "
            f"lease_expiry={scalar(continuity_map.get('lease_expirations', 0))}"
        ),
    ])
    server = native.get("server")
    server_map = server if isinstance(server, Mapping) else {}
    server_counters = server_map.get("counters")
    counter_map = server_counters if isinstance(server_counters, Mapping) else {}
    lines.append(
        "  UDP ingress: "
        f"queue p95={_gauge(server_map, 'udp_ingress_queue_depth', 'p95'):.0f}/"
        f"{_gauge(server_map, 'udp_ingress_queue_capacity', 'max'):.0f}, "
        f"drops={scalar(counter_map.get('udp_ingress_queue_drops_total', 0))}, "
        f"workers={_gauge(server_map, 'udp_ingress_workers', 'max'):.0f}, "
        f"socket rcv/snd={_bytes(_gauge(server_map, 'udp_socket_receive_buffer_bytes', 'max'))}/"
        f"{_bytes(_gauge(server_map, 'udp_socket_send_buffer_bytes', 'max'))}"
    )
    peer_capacity = _gauge(server_map, "peer_read_queue_capacity", "max")
    if peer_capacity:
        lines.append(
            "  Peer ingress: "
            f"queue p95={_gauge(server_map, 'peer_read_queue_depth', 'p95'):.0f}/"
            f"{peer_capacity:.0f}, "
            f"drops={scalar(counter_map.get('peer_read_queue_drops_total', 0))}"
        )
    _append_lane_pipeline(lines, native)
    _append_wire_and_recovery(lines, native)
    missing_all = [*missing_items, *group_items]
    if missing_all:
        shown = missing_all if detailed else missing_all[:8]
        lines.append("  Missing: " + ", ".join(shown))
        if len(shown) < len(missing_all):
            lines.append(f"    ... and {len(missing_all) - len(shown)} more; run telemetry report")
    _append_native_sessions(lines, native, detailed=detailed)
    _append_native_workers(lines, native, detailed=detailed)
    if detailed:
        _append_lane_internals(lines, native)


def _append_lane_pipeline(
    lines: list[str],
    native: Mapping[str, object],
) -> None:
    raw = native.get("lane_pipeline")
    pipeline = raw if isinstance(raw, Mapping) else {}
    if not pipeline.get("available"):
        return
    utilization = pipeline.get("output_queue_utilization_ratio")
    utilization_text = _percent(utilization) if utilization is not None else "-"
    lines.append(
        "  KCP pipeline: "
        f"output p95={scalar(pipeline.get('output_queue_depth_p95', 0))}/"
        f"{scalar(pipeline.get('output_queue_capacity', 0))} ({utilization_text}), "
        f"admission p50/p95={scalar(pipeline.get('admission_window_p50_min', 0))}/"
        f"{scalar(pipeline.get('admission_window_p95_max', 0))} seg, "
        f"write p95={scalar(pipeline.get('worker_write_latency_p95_ms', 0))} ms, "
        f"update_pause={scalar(pipeline.get('update_backpressure_total', 0))}, "
        f"mutex_wait={scalar(pipeline.get('mutex_blocked_seconds_total', 0))} s, "
        f"flow_abort={scalar(pipeline.get('flow_reorder_abort_total', 0))}"
    )


def _append_wire_and_recovery(
    lines: list[str],
    native: Mapping[str, object],
) -> None:
    wire = native.get("wire_breakdown")
    wire_map = wire if isinstance(wire, Mapping) else {}
    if wire_map:
        fast_bytes = wire_map.get("kcp_fast_retransmit_estimate_bytes")
        rto_bytes = wire_map.get("kcp_rto_retransmit_estimate_bytes")
        reason_bytes = (
            " (fast/RTO est="
            f"{_bytes(fast_bytes)}/{_bytes(rto_bytes)})"
            if fast_bytes is not None or rto_bytes is not None
            else ""
        )
        lines.append(
            "  Wire: "
            f"outer={_bytes(wire_map.get('outer_bytes'))}, "
            f"payload={_bytes(wire_map.get('outer_payload_bytes'))}, "
            f"wrapper={_bytes(wire_map.get('outer_overhead_bytes'))}, "
            f"KCP retx={_bytes(wire_map.get('kcp_retransmit_bytes'))}"
            f"{reason_bytes}, "
            f"goodput={_bytes(wire_map.get('relay_goodput_bytes'))}"
        )
        if any(
            wire_map.get(name) is not None
            for name in (
                "kcp_ack_segments",
                "kcp_ack_progress_segments",
                "kcp_rtt_samples",
            )
        ):
            lines.append(
                "  KCP ACK: "
                f"observed={scalar(wire_map.get('kcp_ack_segments', 0))}, "
                f"progress={scalar(wire_map.get('kcp_ack_progress_segments', 0))}, "
                f"RTT samples={scalar(wire_map.get('kcp_rtt_samples', 0))}"
            )
    recovery = native.get("lane_recovery")
    recovery_map = recovery if isinstance(recovery, Mapping) else {}
    if recovery_map and (
        recovery_map.get("stalls") or recovery_map.get("attempts")
        or recovery_map.get("recovered")
    ):
        duration = recovery_map.get("duration_seconds")
        duration_map = duration if isinstance(duration, Mapping) else {}
        lines.append(
            "  Lane recovery: "
            f"stalls={scalar(recovery_map.get('stalls', 0))}, "
            f"started={scalar(recovery_map.get('attempts', 0))}, "
            f"recovered={scalar(recovery_map.get('matched_recoveries', 0))}, "
            f"failed={scalar(recovery_map.get('failed', 0))}, "
            f"escalated={scalar(recovery_map.get('escalated', 0))}, "
            f"unresolved={scalar(recovery_map.get('unresolved', 0))}, "
            f"p95={scalar(round(float(duration_map.get('p95', 0) or 0), 3))} s"
        )


def _append_native_sessions(
    lines: list[str],
    native: Mapping[str, object],
    *,
    detailed: bool,
) -> None:
    rows = []
    first_report: Mapping[str, object] | None = None
    hidden = 0
    for side, key in (("server", "server_sessions"), ("client", "client_sessions")):
        raw_reports = native.get(key)
        if not isinstance(raw_reports, Sequence):
            continue
        for report in raw_reports:
            if not isinstance(report, Mapping):
                continue
            if not detailed and not report.get("current"):
                hidden += 1
                continue
            if first_report is None:
                first_report = report
            rows.append((
                side,
                report.get("tester_id", "-"),
                _short_id(report.get("native_session_id")),
                _bitrate(report.get("wire_bps")),
                _percent(report.get("kcp_retransmission_ratio")),
                _retrans_reason(report),
                scalar(round(_gauge(report, "kcp_wait_snd", "p95"), 1)),
                f"{_gauge(report, 'kcp_rtt_ms', 'p95'):.0f} ms",
                _percent(_gauge(report, "network_loss_ratio", "p95")),
            ))
    if rows:
        if first_report is not None:
            lines.extend([
                "",
                (
                    "Transport config: four independent KCP lanes (wire v8), "
                    f"lanes={_gauge(first_report, 'lane_count', 'max'):.0f}, "
                    f"MTU={_gauge(first_report, 'kcp_mtu_bytes', 'max'):.0f}, "
                    f"aggregate-window={_gauge(first_report, 'kcp_send_window_segments', 'max'):.0f}, "
                    f"aggregate-pending={_gauge(first_report, 'kcp_max_pending_segments', 'max'):.0f}, "
                    f"update={_gauge(first_report, 'kcp_update_interval_ms', 'max'):.0f} ms, "
                    f"fast-resend={_gauge(first_report, 'kcp_fast_resend', 'max'):.0f}, "
                    f"congestion={_gauge(first_report, 'kcp_congestion_control', 'max'):.0f}, "
                    f"RTP PT={_gauge(first_report, 'outer_rtp_payload_type', 'max'):.0f}"
                ),
            ])
        lines.extend([
            "Transport sessions",
            *table(
                (
                    "Side", "Tester", "Session", "Wire avg", "KCP retx",
                    "Fast/RTO", "Wait p95", "RTT p95", "Loss p95",
                ),
                rows,
            ),
        ])
    if hidden:
        lines.append(f"  Historical/inactive sessions hidden: {hidden}; run telemetry report")


def _append_native_workers(
    lines: list[str],
    native: Mapping[str, object],
    *,
    detailed: bool,
) -> None:
    candidates: list[tuple[float, tuple[object, ...]]] = []
    hidden = 0
    for side, key in (("server", "server_workers"), ("client", "client_workers")):
        raw_reports = native.get(key)
        if not isinstance(raw_reports, Sequence):
            continue
        for report in raw_reports:
            if not isinstance(report, Mapping):
                continue
            if not detailed and not report.get("current"):
                hidden += 1
                continue
            drops = _counter(report, "worker_send_queue_drops_total") + _counter(
                report,
                "peer_read_queue_drops_total",
            )
            reconnects = _counter(report, "worker_reconnect_total")
            loss = _gauge(report, "network_loss_ratio", "p95")
            exact_retry = report.get("kcp_retransmission_ratio")
            retry_pressure = (
                float(exact_retry)
                if isinstance(exact_retry, (int, float))
                and not isinstance(exact_retry, bool)
                else 0.0
            )
            lane_rtt = _gauge(report, "kcp_rtt_ms", "p95")
            wait_snd = _gauge(report, "kcp_wait_snd", "p95")
            flow_count = _gauge(report, "lane_flow_count", "max")
            queue_delay = _gauge(report, "worker_output_queue_delay_ms", "p95")
            queue_late = _counter(report, "worker_output_queue_late_total")
            active = bool(report.get("active"))
            score = (
                drops * 1000 + reconnects * 100
                + max(loss, retry_pressure) * 100 + queue_late + wait_snd
                + (0 if active else 1)
            )
            row: list[object] = [side, report.get("tester_id", "-")]
            if detailed:
                row.append(_short_id(report.get("native_session_id")))
            common = (scalar(report.get("worker_id", "-")), "yes" if active else "no")
            row.extend(_worker_row(
                report,
                common,
                detailed=detailed,
                flow_count=flow_count,
                retry_pressure=retry_pressure,
                wait_snd=wait_snd,
                lane_rtt=lane_rtt,
                loss=loss,
                queue_delay=queue_delay,
                queue_late=queue_late,
                drops=drops,
                reconnects=reconnects,
            ))
            candidates.append((score, tuple(row)))
    if not candidates:
        return
    candidates.sort(key=lambda item: item[0], reverse=True)
    shown = candidates if detailed else candidates[:16]
    headers = ["Side", "Tester"]
    if detailed:
        headers.append("Session")
        headers.extend((
            "Lane", "Active", "Wire avg", "Flows", "KCP retx", "Fast/RTO", "Wait p95",
            "ACK/flight", "RTT/var", "Net loss", "Queue/late", "Drops",
            "Reconnect", "TURN #",
        ))
    else:
        headers.extend((
            "Lane", "Active", "Wire avg", "Flows", "KCP retx", "Fast/RTO", "Wait p95",
            "RTT p95", "Drops", "TURN #",
        ))
    lines.extend([
        "",
        "KCP lanes" + ("" if detailed else f" (top {len(shown)} of {len(candidates)})"),
        *table(tuple(headers), [row for _, row in shown]),
    ])
    if hidden:
        lines.append(f"  Historical/inactive workers hidden: {hidden}; run telemetry report")


def _worker_row(
    report: Mapping[str, object],
    common: tuple[object, object],
    *,
    detailed: bool,
    flow_count: float,
    retry_pressure: float,
    wait_snd: float,
    lane_rtt: float,
    loss: float,
    queue_delay: float,
    queue_late: float,
    drops: float,
    reconnects: float,
) -> tuple[object, ...]:
    base = (
        *common,
        _bitrate(report.get("wire_bps")),
        scalar(round(flow_count, 1)),
        _percent(retry_pressure),
        _retrans_reason(report),
        scalar(round(wait_snd, 1)),
        f"{lane_rtt:.0f} ms",
    )
    turn = scalar(round(_gauge(report, "turn_selected_endpoint_ordinal", "p95"), 1))
    if not detailed:
        return (*base, scalar(round(drops, 1)), turn)
    ack_ratio = report.get("kcp_ack_progress_ratio")
    ack = _percent(float(ack_ratio)) if isinstance(ack_ratio, (int, float)) else "-"
    inflight = _gauge(report, "kcp_inflight_segments", "p95")
    rtt_var = _gauge(report, "kcp_rttvar_ms", "p95")
    return (
        *base[:-1],
        f"{ack}/{scalar(round(inflight, 1))}",
        f"{lane_rtt:.0f}/{rtt_var:.0f} ms",
        _percent(loss),
        f"{queue_delay:.0f} ms/{scalar(round(queue_late, 1))}",
        scalar(round(drops, 1)),
        scalar(round(reconnects, 1)),
        turn,
    )


def _append_lane_internals(
    lines: list[str],
    native: Mapping[str, object],
) -> None:
    rows: list[tuple[object, ...]] = []
    metric_names = {
        "lane_admission_window_segments",
        "lane_generation",
        "lane_state",
        "lane_pacing_bytes_per_second",
        "lane_delivered_bytes_per_second",
        "lane_inflight_limit_segments",
        "lane_ack_age_seconds",
        "lane_reset_request_total",
        "lane_reset_ack_total",
        "lane_reset_commit_total",
        "lane_stale_generation_drops_total",
        "lane_probe_result",
        "kcp_output_queue_depth",
        "kcp_output_queue_capacity",
        "kcp_update_backpressure_total",
        "kcp_mutex_blocked_seconds_total",
        "worker_write_latency_ms",
    }
    for side, key in (("server", "server_workers"), ("client", "client_workers")):
        reports = native.get(key)
        if not isinstance(reports, Sequence):
            continue
        for report in reports:
            if not isinstance(report, Mapping):
                continue
            gauges = report.get("gauges")
            gauge_map = gauges if isinstance(gauges, Mapping) else {}
            counters = report.get("counters")
            counter_map = counters if isinstance(counters, Mapping) else {}
            if not metric_names.intersection((*gauge_map, *counter_map)):
                continue
            rows.append((
                side,
                report.get("tester_id", "-"),
                _short_id(report.get("native_session_id")),
                scalar(report.get("worker_id", "-")),
                (
                    f"{_gauge(report, 'lane_generation', 'max'):.0f}/"
                    f"{_gauge(report, 'lane_state', 'max'):.0f}"
                ),
                (
                    f"{_bitrate(_gauge(report, 'lane_pacing_bytes_per_second', 'p50') * 8)}/"
                    f"{_bitrate(_gauge(report, 'lane_delivered_bytes_per_second', 'p50') * 8)}"
                ),
                f"{_gauge(report, 'lane_inflight_limit_segments', 'p95'):.0f}",
                f"{_gauge(report, 'lane_ack_age_seconds', 'p95'):.2f} s",
                (
                    f"{_counter(report, 'lane_reset_request_total'):.0f}/"
                    f"{_counter(report, 'lane_reset_ack_total'):.0f}/"
                    f"{_counter(report, 'lane_reset_commit_total'):.0f}"
                ),
                (
                    f"{_gauge(report, 'lane_probe_result', 'max'):.0f}/"
                    f"{_counter(report, 'lane_stale_generation_drops_total'):.0f}"
                ),
                (
                    f"{_gauge(report, 'lane_admission_window_segments', 'p50'):.0f}/"
                    f"{_gauge(report, 'lane_admission_window_segments', 'p95'):.0f}"
                ),
                (
                    f"{_gauge(report, 'kcp_output_queue_depth', 'p95'):.0f}/"
                    f"{_gauge(report, 'kcp_output_queue_capacity', 'max'):.0f}"
                ),
                scalar(round(_counter(report, "kcp_update_backpressure_total"), 3)),
                f"{_counter(report, 'kcp_mutex_blocked_seconds_total'):.3f} s",
                f"{_gauge(report, 'worker_write_latency_ms', 'p95'):.1f} ms",
            ))
    if not rows:
        return
    lines.extend([
        "",
        "Lane internals",
        *table(
            (
                "Side", "Tester", "Session", "Lane", "Gen/state",
                "Pace/deliver", "Inflight", "ACK age", "Reset r/a/c",
                "Probe/stale", "Admission p50/p95",
                "Output p95/cap", "Update pause", "Mutex wait", "Write p95",
            ),
            rows,
        ),
    ])


__all__ = ["append_native_diagnostics"]
