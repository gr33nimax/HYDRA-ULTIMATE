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
    _append_wire_and_recovery(lines, native)
    missing_all = [*missing_items, *group_items]
    if missing_all:
        shown = missing_all if detailed else missing_all[:8]
        lines.append("  Missing: " + ", ".join(shown))
        if len(shown) < len(missing_all):
            lines.append(f"    ... and {len(missing_all) - len(shown)} more; run telemetry report")
    _append_native_sessions(lines, native, detailed=detailed)
    _append_native_workers(lines, native, detailed=detailed)


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
                    "Transport config: four independent KCP lanes (wire v6), "
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
            "RTT p95", "Net loss", "Queue/late", "Drops", "Reconnect", "TURN #",
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
    return (
        *base,
        _percent(loss),
        f"{queue_delay:.0f} ms/{scalar(round(queue_late, 1))}",
        scalar(round(drops, 1)),
        scalar(round(reconnects, 1)),
        turn,
    )


__all__ = ["append_native_diagnostics"]
