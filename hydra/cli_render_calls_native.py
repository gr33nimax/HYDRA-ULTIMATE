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
    _append_wire(lines, native)
    missing_all = [*missing_items, *group_items]
    if missing_all:
        shown = missing_all if detailed else missing_all[:8]
        lines.append("  Missing: " + ", ".join(shown))
        if len(shown) < len(missing_all):
            lines.append(f"    ... and {len(missing_all) - len(shown)} more; run telemetry report")
    _append_native_sessions(lines, native, detailed=detailed)
    _append_native_workers(lines, native, detailed=detailed)


def _append_wire(
    lines: list[str],
    native: Mapping[str, object],
) -> None:
    wire = native.get("wire_breakdown")
    wire_map = wire if isinstance(wire, Mapping) else {}
    if wire_map:
        lines.append(
            "  Wire: "
            f"outer={_bytes(wire_map.get('outer_bytes'))}, "
            f"payload={_bytes(wire_map.get('outer_payload_bytes'))}, "
            f"wrapper={_bytes(wire_map.get('outer_overhead_bytes'))}, "
            f"retx={_bytes(wire_map.get('quic_retransmit_bytes'))}, "
            f"goodput={_bytes(wire_map.get('relay_goodput_bytes'))}"
        )
        datagrams_sent = wire_map.get("quic_datagrams_sent")
        if datagrams_sent is not None:
            lines.append(
                "  QUIC datagrams: "
                f"sent={scalar(datagrams_sent)}, "
                f"dropped={scalar(wire_map.get('quic_datagrams_dropped', 0))}, "
                f"packets lost={scalar(wire_map.get('quic_packets_lost', 0))}"
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
                scalar(round(_gauge(report, "quic_streams_active", "max"), 1)),
                f"{_gauge(report, 'quic_rtt_ms', 'p95'):.0f} ms",
                _bytes(_gauge(report, "quic_congestion_window_bytes", "p95")),
                _percent(_gauge(report, "network_loss_ratio", "p95")),
            ))
    if rows:
        if first_report is not None:
            lines.extend([
                "",
                (
                    "Transport config: QUIC over DTLS over TURN, "
                    f"paths={_gauge(first_report, 'quic_conn_count', 'max'):.0f}, "
                    f"path replacements={_counter(first_report, 'path_replacements_total'):.0f}, "
                    f"RTP PT={_gauge(first_report, 'outer_rtp_payload_type', 'max'):.0f}"
                ),
            ])
        lines.extend([
            "Transport sessions",
            *table(
                (
                    "Side", "Tester", "Session", "Wire avg", "Streams",
                    "RTT p95", "CWND p95", "Loss p95",
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
            lost = _counter(report, "quic_packets_lost_total")
            quic_rtt = _gauge(report, "quic_rtt_ms", "p95")
            cwnd = _gauge(report, "quic_congestion_window_bytes", "p95")
            streams = _gauge(report, "quic_streams_active", "max")
            queue_delay = _gauge(report, "worker_output_queue_delay_ms", "p95")
            queue_late = _counter(report, "worker_output_queue_late_total")
            active = bool(report.get("active"))
            score = (
                drops * 1000 + reconnects * 100
                + loss * 100 + queue_late + lost
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
                streams=streams,
                lost=lost,
                cwnd=cwnd,
                quic_rtt=quic_rtt,
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
            "Path", "Active", "Wire avg", "Streams", "Lost", "CWND p95",
            "RTT/var", "Net loss", "Queue/late", "Drops", "Reconnect", "TURN #",
        ))
    else:
        headers.extend((
            "Path", "Active", "Wire avg", "Streams", "Lost", "CWND p95",
            "RTT p95", "Drops", "TURN #",
        ))
    lines.extend([
        "",
        "QUIC paths" + ("" if detailed else f" (top {len(shown)} of {len(candidates)})"),
        *table(tuple(headers), [row for _, row in shown]),
    ])
    if hidden:
        lines.append(f"  Historical/inactive workers hidden: {hidden}; run telemetry report")


def _worker_row(
    report: Mapping[str, object],
    common: tuple[object, object],
    *,
    detailed: bool,
    streams: float,
    lost: float,
    cwnd: float,
    quic_rtt: float,
    loss: float,
    queue_delay: float,
    queue_late: float,
    drops: float,
    reconnects: float,
) -> tuple[object, ...]:
    base = (
        *common,
        _bitrate(report.get("wire_bps")),
        scalar(round(streams, 1)),
        scalar(round(lost, 1)),
        _bytes(cwnd),
        f"{quic_rtt:.0f} ms",
    )
    turn = scalar(round(_gauge(report, "turn_selected_endpoint_ordinal", "p95"), 1))
    if not detailed:
        return (*base, scalar(round(drops, 1)), turn)
    rtt_var = _gauge(report, "quic_rtt_var_ms", "p95")
    return (
        *base[:-1],
        f"{quic_rtt:.0f}/{rtt_var:.0f} ms",
        _percent(loss),
        f"{queue_delay:.0f} ms/{scalar(round(queue_late, 1))}",
        scalar(round(drops, 1)),
        scalar(round(reconnects, 1)),
        turn,
    )


__all__ = ["append_native_diagnostics"]
