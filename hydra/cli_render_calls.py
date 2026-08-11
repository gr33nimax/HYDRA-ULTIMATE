"""Human-oriented rendering for Hydra VK Tunnel telemetry."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

from hydra.cli_format import scalar, table


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
    native = payload.get("native")
    native_map = native if isinstance(native, Mapping) else {}
    native_level = native_map.get("diagnostic_level")
    if native_level:
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
        preview = ", ".join(
            f"{key}={scalar(value)}"
            for key, value in list(metric_map.items())[:8]
        )
        identity = record.get("tester_id") or "server"
        event = f" event={record['event']}" if record.get("event") else ""
        return f"{timestamp} NATIVE {identity}{event} {preview}".rstrip()
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


def _timestamp(value: object) -> str:
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ",
        )
    except (OSError, TypeError, ValueError):
        return "unknown-time"


def _bytes(value: object) -> str:
    amount = float(value or 0)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return "0.0 B"


def _bitrate(value: object) -> str:
    amount = float(value or 0)
    units = ("bit/s", "Kbit/s", "Mbit/s", "Gbit/s")
    for unit in units:
        if abs(amount) < 1000 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1000
    return "0.0 bit/s"


def _percent(value: object) -> str:
    return f"{float(value or 0) * 100:.1f}%"


__all__ = ["render_calls_telemetry", "render_calls_telemetry_record"]
