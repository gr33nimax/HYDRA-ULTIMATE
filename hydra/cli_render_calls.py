"""Human-oriented rendering for Hydra VK Tunnel telemetry."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.cli_format import scalar, table
from hydra.cli_render_calls_common import (
    bitrate as _bitrate,
    bytes_value as _bytes,
    counter as _counter,
    gauge as _gauge,
    has_gauge as _has_gauge,
    percent as _percent,
    short_id as _short_id,
    timestamp as _timestamp,
)


def render_calls_telemetry(payload: Mapping[str, object]) -> list[str]:
    window = payload.get("window")
    window_map = window if isinstance(window, Mapping) else payload
    lines = [
        f"  Session: {scalar(payload.get('session_id') or 'none')}",
        f"  State: {'active' if payload.get('active') else 'complete'}",
        (
            f"  Samples: {scalar(window_map.get('samples', 0))}/"
            f"{scalar(window_map.get('expected_samples', 0))}"
            f"  |  coverage {_percent(window_map.get('coverage_ratio'))}"
        ),
    ]
    _append_session_details(lines, payload, window_map)
    calls = payload.get("calls")
    if isinstance(calls, Mapping):
        _append_calls(lines, calls)
    testers = payload.get("testers")
    if isinstance(testers, Sequence) and testers:
        _append_testers(lines, testers)
    native = payload.get("native")
    if isinstance(native, Mapping):
        _append_native_diagnostics(
            lines,
            native,
            detailed="analysis_input" in payload,
        )
    _append_findings_and_paths(lines, payload)
    records = payload.get("records")
    if isinstance(records, Sequence) and records:
        lines.extend(["", "Timeline"])
        for record in records:
            if isinstance(record, Mapping):
                lines.append("  " + render_calls_telemetry_record(record, color=False))
    return lines


def _append_session_details(
    lines: list[str],
    payload: Mapping[str, object],
    window: Mapping[str, object],
) -> None:
    elapsed = window.get("elapsed_seconds", payload.get("elapsed_seconds"))
    if elapsed is not None:
        lines.append(f"  Elapsed: {scalar(round(float(elapsed or 0), 1))} s")
    if payload.get("max_data_bytes"):
        lines.append(
            f"  Storage: {_bytes(payload.get('data_bytes'))} / "
            f"{_bytes(payload.get('max_data_bytes'))}",
        )
        raw_bytes = payload.get("raw_data_bytes")
        if raw_bytes and float(raw_bytes) > float(payload.get("data_bytes", 0) or 0):
            lines.append(
                f"  Raw retained: {_bytes(raw_bytes)}"
                f"  |  saved {_percent(1 - float(payload.get('compression_ratio', 1) or 1))}"
                f"  |  segments {scalar(payload.get('timeline_segments', 0))}",
            )
    native = payload.get("native")
    native_map = native if isinstance(native, Mapping) else {}
    native_level = native_map.get("diagnostic_level")
    if native_level:
        if "continuity" not in native_map:
            lines.append(f"  Native coverage: {scalar(native_level)}")
    elif "native_available" in payload:
        lines.append(
            "  Native coverage: "
            + ("partial" if payload.get("native_available") else "server_observation_only"),
        )


def _append_calls(lines: list[str], calls: Mapping[str, object]) -> None:
    throughput = calls.get("throughput_bps")
    throughput_map = throughput if isinstance(throughput, Mapping) else {}
    active = calls.get("active_connections")
    active_map = active if isinstance(active, Mapping) else {}
    lines.extend([
        "",
        "Calls",
        f"  Transferred: {_bytes(calls.get('total_bytes'))}",
        f"  Average: {_bitrate(calls.get('average_bps'))}",
        (
            f"  Throughput p95/max: {_bitrate(throughput_map.get('p95'))} / "
            f"{_bitrate(throughput_map.get('max'))}"
        ),
        f"  Peak connections: {scalar(active_map.get('max', 0))}",
        f"  User attribution: {_percent(calls.get('attribution_ratio'))}",
        f"  Selected-tester traffic: {_percent(calls.get('tester_traffic_ratio'))}",
    ])


def _append_testers(lines: list[str], testers: Sequence[object]) -> None:
    rows = []
    for raw in testers:
        if not isinstance(raw, Mapping):
            continue
        throughput = raw.get("throughput_bps")
        throughput_map = throughput if isinstance(throughput, Mapping) else {}
        rows.append((
            raw.get("tester_id", "-"),
            _bytes(raw.get("total_bytes")),
            _bitrate(throughput_map.get("p95")),
        ))
    lines.extend(["", "Testers", *table(("ID", "Traffic", "p95"), rows)])


def _append_native_diagnostics(
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
    wire = native.get("wire_breakdown")
    wire_map = wire if isinstance(wire, Mapping) else {}
    if wire_map:
        lines.append(
            "  Wire: "
            f"outer={_bytes(wire_map.get('outer_bytes'))}, "
            f"payload={_bytes(wire_map.get('outer_payload_bytes'))}, "
            f"wrapper={_bytes(wire_map.get('outer_overhead_bytes'))}, "
            f"KCP retx={_bytes(wire_map.get('kcp_retransmit_bytes'))}, "
            f"goodput={_bytes(wire_map.get('relay_goodput_bytes'))}"
        )
    missing_all = [*missing_items, *group_items]
    if missing_all:
        shown = missing_all if detailed else missing_all[:8]
        lines.append("  Missing: " + ", ".join(shown))
        if len(shown) < len(missing_all):
            lines.append(f"    ... and {len(missing_all) - len(shown)} more; run telemetry report")
    _append_native_sessions(lines, native, detailed=detailed)
    _append_native_workers(lines, native, detailed=detailed)


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
                scalar(round(_gauge(report, "kcp_wait_snd", "p95"), 1)),
                f"{_gauge(report, 'kcp_rtt_ms', 'p95'):.0f} ms",
                _percent(_gauge(report, "network_loss_ratio", "p95")),
            ))
    if rows:
        if first_report is not None:
            profile = (
                "adaptive"
                if _gauge(first_report, "multipath_profile", "max") >= 0.5
                else "legacy"
            )
            lines.extend([
                "",
                (
                    "Transport config: "
                    f"profile={profile}, "
                    f"MTU={_gauge(first_report, 'kcp_mtu_bytes', 'max'):.0f}, "
                    f"window={_gauge(first_report, 'kcp_send_window_segments', 'max'):.0f}, "
                    f"pending={_gauge(first_report, 'kcp_max_pending_segments', 'max'):.0f}, "
                    f"update={_gauge(first_report, 'kcp_update_interval_ms', 'max'):.0f} ms, "
                    f"fast-resend={_gauge(first_report, 'kcp_fast_resend', 'max'):.0f}, "
                    f"congestion={_gauge(first_report, 'kcp_congestion_control', 'max'):.0f}, "
                    f"chunk={_gauge(first_report, 'multipath_chunk_packets', 'max'):.0f}/"
                    f"{_gauge(first_report, 'multipath_chunk_dwell_ms', 'max'):.0f} ms"
                ),
            ])
        lines.extend([
            "Transport sessions",
            *table(
                ("Side", "Tester", "Session", "Wire avg", "KCP retx", "Wait p95", "RTT p95", "Loss p95"),
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
            exact_retry = report.get("worker_path_retransmission_ratio")
            if isinstance(exact_retry, (int, float)) and not isinstance(exact_retry, bool):
                retry_pressure = float(exact_retry)
            else:
                retry_pressure = _gauge(report, "worker_path_retry_ratio", "p95")
                if not _has_gauge(report, "worker_path_retry_ratio"):
                    retry_pressure = _gauge(report, "worker_path_loss_ratio", "p95")
            path_rtt = _gauge(report, "worker_path_rtt_ms", "p95")
            delivery = _gauge(report, "worker_path_delivery_rate_bps", "p95")
            path_window = _gauge(report, "worker_path_window_segments", "p50")
            path_flight = _gauge(report, "worker_path_inflight_segments", "p95")
            backoffs = _counter(report, "worker_path_backoff_total")
            delivery_text = (
                _bitrate(delivery)
                if _has_gauge(report, "worker_path_delivery_rate_bps")
                else "-"
            )
            window_text = (
                f"{path_window:.0f}/{path_flight:.0f}"
                if _has_gauge(report, "worker_path_window_segments")
                and _has_gauge(report, "worker_path_inflight_segments")
                else "-"
            )
            queue_delay = _gauge(report, "worker_output_queue_delay_ms", "p95")
            queue_late = _counter(report, "worker_output_queue_late_total")
            active = bool(report.get("active"))
            score = (
                drops * 1000
                + reconnects * 100
                + max(loss, retry_pressure) * 100
                + queue_late
                + backoffs * 10
                + (0 if active else 1)
            )
            row: list[object] = [
                side,
                report.get("tester_id", "-"),
            ]
            if detailed:
                row.append(_short_id(report.get("native_session_id")))
            common = (
                scalar(report.get("worker_id", "-")),
                "yes" if active else "no",
            )
            if detailed:
                row.extend(
                    (
                        *common,
                        _bitrate(report.get("wire_bps")),
                        delivery_text,
                        _percent(loss),
                        _percent(retry_pressure),
                        window_text,
                        f"{path_rtt:.0f} ms",
                        f"{queue_delay:.0f} ms/{scalar(round(queue_late, 1))}",
                        scalar(round(backoffs, 1)),
                        scalar(round(drops, 1)),
                        scalar(round(reconnects, 1)),
                        scalar(round(
                            _gauge(report, "turn_selected_endpoint_ordinal", "p95"),
                            1,
                        )),
                    ),
                )
            else:
                row.extend(
                    (
                        *common,
                        delivery_text,
                        _percent(retry_pressure),
                        window_text,
                        f"{path_rtt:.0f} ms",
                        scalar(round(drops, 1)),
                        scalar(round(
                            _gauge(report, "turn_selected_endpoint_ordinal", "p95"),
                            1,
                        )),
                    ),
                )
            candidates.append((score, tuple(row)))
    if not candidates:
        return
    candidates.sort(key=lambda item: item[0], reverse=True)
    shown = candidates if detailed else candidates[:12]
    headers = ["Side", "Tester"]
    if detailed:
        headers.append("Session")
        headers.extend((
            "ID", "Active", "Wire avg", "Delivered", "Net loss", "Path retry",
            "Win/flight", "Path RTT", "Queue/late", "Backoff", "Drops",
            "Reconnect", "TURN #",
        ))
    else:
        headers.extend((
            "ID", "Active", "Delivered", "Path retry", "Win/flight", "Path RTT",
            "Drops", "TURN #",
        ))
    lines.extend([
        "",
        "Workers" + ("" if detailed else f" (top {len(shown)} of {len(candidates)})"),
        *table(
            tuple(headers),
            [row for _, row in shown],
        ),
    ])
    if hidden:
        lines.append(f"  Historical/inactive workers hidden: {hidden}; run telemetry report")


def _append_findings_and_paths(
    lines: list[str],
    payload: Mapping[str, object],
) -> None:
    findings = payload.get("findings")
    if isinstance(findings, Sequence) and findings:
        lines.extend(["", "Findings"])
        for raw in findings:
            if isinstance(raw, Mapping):
                lines.append(
                    f"  [{raw.get('severity', 'info')}] {raw.get('message', '')}",
                )
                if raw.get("next_step"):
                    lines.append(f"    Next: {raw['next_step']}")
    if payload.get("samples_path"):
        lines.extend(["", f"  Data: {payload['samples_path']}"])
    if payload.get("timeline_path"):
        lines.extend(["", f"  Timeline: {payload['timeline_path']}"])


def render_calls_telemetry_record(
    record: Mapping[str, object],
    *,
    color: bool,
) -> str:
    del color
    timestamp = _timestamp(record.get("timestamp"))
    kind = str(record.get("kind", "event"))
    if kind == "mark":
        return f"{timestamp} MARK {record.get('label', '-')}"
    if kind == "event":
        return (
            f"{timestamp} EVENT {record.get('code', '-')} "
            f"source={record.get('source', '-')}"
        )
    if kind == "native":
        metrics = record.get("metrics")
        metric_map = metrics if isinstance(metrics, Mapping) else {}
        important = (
            "worker_active",
            "kcp_wait_snd",
            "kcp_rtt_ms",
            "kcp_retrans_segments_total",
            "network_loss_ratio",
            "outer_bytes_in_total",
            "outer_bytes_out_total",
            "worker_send_queue_drops_total",
            "telemetry_record_drops_total",
        )
        preview = ", ".join(
            f"{key}={scalar(metric_map[key])}"
            for key in important
            if key in metric_map
        )
        identity = record.get("tester_id") or "server"
        entity = record.get("native_entity") or record.get("native_scope") or "native"
        worker = (
            f" worker={record['worker_id']}"
            if record.get("worker_id") is not None
            else ""
        )
        session = _short_id(record.get("native_session_id"))
        event = f" event={record['event']}" if record.get("event") else ""
        return (
            f"{timestamp} NATIVE {entity} {identity} session={session}"
            f"{worker}{event} {preview}"
        ).rstrip()
    return _sample_record(timestamp, record)


def _sample_record(timestamp: str, record: Mapping[str, object]) -> str:
    calls = record.get("calls")
    calls_map = calls if isinstance(calls, Mapping) else {}
    interval = calls_map.get("interval")
    interval_map = interval if isinstance(interval, Mapping) else {}
    delta = int(interval_map.get("upload_bytes", 0) or 0) + int(
        interval_map.get("download_bytes", 0) or 0,
    )
    host = record.get("host")
    host_map = host if isinstance(host, Mapping) else {}
    udp = record.get("udp")
    udp_map = udp if isinstance(udp, Mapping) else {}
    return (
        f"{timestamp} SAMPLE delta={_bytes(delta)} "
        f"active={calls_map.get('active_connections', 0)} "
        f"cpu={float(host_map.get('cpu_percent', 0) or 0):.1f}% "
        f"udp_drops={udp_map.get('listener_drops', 0)}"
    )


__all__ = ["render_calls_telemetry", "render_calls_telemetry_record"]
