"""Human-oriented rendering for Hydra VK Tunnel telemetry."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.cli_format import scalar, table
from hydra.cli_render_calls_common import (
    bitrate as _bitrate,
    bytes_value as _bytes,
    percent as _percent,
    short_id as _short_id,
    timestamp as _timestamp,
)
from hydra.cli_render_calls_native import (
    append_native_diagnostics as _append_native_diagnostics,
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
    _append_data_paths(lines, payload)
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


def _append_data_paths(
    lines: list[str],
    payload: Mapping[str, object],
) -> None:
    """Печатает только пути к данным.

    Раздел Findings убран намеренно: телеметрия показывает числа, а разбор
    возможных причин остаётся человеку. Сами findings по-прежнему лежат в
    JSON-выводе для внешних потребителей, но в текстовый отчёт не идут -
    двадцать заключений по два абзаца делали вывод нечитаемым.
    """
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
            "lane_count",
            "lane_flow_count",
            "kcp_wait_snd",
            "kcp_rtt_ms",
            "kcp_rto_ms",
            "kcp_retrans_segments_total",
            "kcp_fast_retrans_estimate_segments_total",
            "kcp_rto_retrans_estimate_segments_total",
            "network_loss_ratio",
            "outer_bytes_in_total",
            "outer_bytes_out_total",
            "worker_send_queue_drops_total",
            "worker_output_queue_delay_ms",
            "worker_output_queue_late_total",
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
