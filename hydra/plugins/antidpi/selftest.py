"""Compatibility facade for modular AntiDPI diagnostic self-tests."""
from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from hydra import __version__
from hydra.core.host import HOST
from hydra.core.sni_router import (
    DECOY_LOG,
    TRUSTTUNNEL_LOG,
    get_effective_port,
)
from hydra.core.source_relay import MAP_FILE
from hydra.core.state_models import AppState
from hydra.plugins.antidpi.paths import NAIVE_ACCESS_LOG
from hydra.plugins.antidpi.selftest_capture import (
    all_journal,
    all_new_log_lines,
    capture_event_summary,
    runtime_delta,
    udp_diagnostics,
    write_capture_archive,
)
from hydra.plugins.antidpi.selftest_probes import (
    PAYLOADS,
    SINGBOX_CLIENT_PROTOCOLS,
    ClientConfigProvider,
    client_environment,
    free_tcp_port,
    invalid_client_config,
    native_client_probe,
    native_naive_probe,
    probe,
    socks_trigger,
)
from hydra.plugins.antidpi.selftest_report import (
    environment,
    journal,
    log_filter_matches,
    new_log_lines,
    offsets,
    record_summary,
    redactor,
    relevant_journal_record,
    secret_values,
    write_selftest_archive,
)
from hydra.plugins.antidpi.selftest_targets import (
    JOURNAL_UNITS,
    SUPPORTED_PROTOCOLS,
    Target,
    awg_handshake_payload,
    targets,
)

LOG_PATHS = (
    DECOY_LOG,
    TRUSTTUNNEL_LOG,
    NAIVE_ACCESS_LOG,
    Path("/var/log/caddy-l4/antidpi.jsonl"),
)
_PAYLOADS = PAYLOADS
RuntimeSnapshotReader = Callable[[], dict]


def _is_linux_host() -> bool:
    return os.name == "posix" and Path("/proc").exists()


def _environment() -> dict:
    return environment(
        HOST,
        version=__version__,
        journal_units=JOURNAL_UNITS,
    )


def _targets(state: AppState, protocol: str) -> list[Target]:
    return targets(
        state,
        protocol,
        effective_port=get_effective_port,
    )


def _awg_handshake_payload(state: AppState, target: Target) -> bytes:
    return awg_handshake_payload(state, target)


def _probe(
    target: Target,
    timeout: float = 0.8,
    extra_payloads: tuple[bytes, ...] = (),
) -> list[dict]:
    return probe(target, timeout, extra_payloads)


def _free_tcp_port() -> int:
    return free_tcp_port()


def _invalid_client_config(
    state: AppState,
    protocol: str,
    listen_port: int,
    *,
    protocols: ClientConfigProvider | None = None,
) -> tuple[dict | None, str]:
    return invalid_client_config(
        state,
        protocol,
        listen_port,
        protocols=protocols,
    )


def _socks_trigger(port: int) -> str:
    return socks_trigger(port)


def _client_environment() -> dict[str, str]:
    return client_environment()


def _native_client_probe(
    state: AppState,
    protocol: str,
    *,
    protocols: ClientConfigProvider | None = None,
) -> dict:
    def build(
        app_state: AppState,
        name: str,
        port: int,
        provider: ClientConfigProvider | None,
    ) -> tuple[dict | None, str]:
        return _invalid_client_config(
            app_state,
            name,
            port,
            protocols=provider,
        )

    return native_client_probe(
        state,
        protocol,
        protocols=protocols,
        host=HOST,
        config_builder=build,
    )


def _native_naive_probe(state: AppState) -> dict:
    return native_naive_probe(state, host=HOST)


def _journal(protocol: str, since: float, until: float) -> list[dict]:
    return journal(
        protocol,
        since,
        until,
        host=HOST,
        journal_units=JOURNAL_UNITS,
    )


def _relevant_journal_record(protocol: str, record: dict) -> bool:
    return relevant_journal_record(
        protocol,
        record,
        journal_units=JOURNAL_UNITS,
    )


def _offsets() -> dict[Path, int]:
    return offsets(LOG_PATHS)


def _new_log_lines(before: dict[Path, int]) -> dict[str, list[str]]:
    return new_log_lines(before)


def _secret_values(state: AppState) -> set[str]:
    return secret_values(state)


def _redactor(state: AppState) -> Callable[[str], str]:
    return redactor(state)


def _record_summary(protocol: str, records: list[dict]) -> dict:
    return record_summary(protocol, records)


def _log_filter_matches(
    protocol: str,
    logs: dict[str, list[str]],
) -> list[dict]:
    return log_filter_matches(protocol, logs)


def _protocol_report(enabled: bool) -> dict[str, object]:
    return {
        "enabled": enabled,
        "targets": [],
        "probes": [],
        "logs": {},
        "coverage": {
            "malformed_probe_sent": False,
            "native_client_probe_sent": False,
            "native_log_observed": False,
            "filter_match": False,
            "external_source_attribution": False,
            "firewall_enforcement": False,
            "telegram_delivery": False,
        },
    }


def _exercise_protocol(
    state: AppState,
    protocol: str,
    *,
    wait_seconds: float,
    full: bool,
    protocols: ClientConfigProvider | None,
    redact: Callable[[str], str],
) -> tuple[dict[str, object], dict[str, object] | None]:
    plugin_state = state.protocols.get(protocol)
    item = _protocol_report(bool(plugin_state and plugin_state.enabled))
    coverage = item["coverage"]
    if not item["enabled"]:
        item["status"] = "skipped_disabled"
        return item, None
    protocol_targets = _targets(state, protocol)
    item["targets"] = [asdict(target) for target in protocol_targets]
    if not protocol_targets:
        item["status"] = "skipped_no_target"
        return item, None
    before = _offsets()
    since = time.time() - 0.05
    for target in protocol_targets:
        extra = (
            (_awg_handshake_payload(state, target),)
            if protocol == "amneziawg"
            else ()
        )
        item["probes"].extend(_probe(target, extra_payloads=extra))
    coverage["malformed_probe_sent"] = bool(item["probes"])
    if full:
        native_client = _safe_native_probe(
            state,
            protocol,
            protocols=protocols,
        )
        if native_client.get("client_log"):
            native_client["client_log"] = redact(
                str(native_client["client_log"]),
            )
        item["native_client"] = native_client
        coverage["native_client_probe_sent"] = bool(
            native_client.get("triggered"),
        )
    time.sleep(max(0.0, min(float(wait_seconds), 10.0)))
    records = _journal(protocol, since, time.time() + 0.05)
    logs = _new_log_lines(before)
    item.update(_record_summary(protocol, records))
    item["current_filter_matches"].extend(
        _log_filter_matches(protocol, logs),
    )
    item["logs"] = {path: len(lines) for path, lines in logs.items()}
    coverage["native_log_observed"] = bool(records or logs)
    coverage["filter_match"] = bool(
        item.get("current_filter_matches")
        or item.get("protocol_context_matches"),
    )
    if coverage["filter_match"]:
        item["status"] = "filter_match"
    elif records or logs:
        item["status"] = "native_log_unmatched"
    else:
        item["status"] = "no_native_log_output"
    return item, {"journal": records, "logs": logs}


def _safe_native_probe(
    state: AppState,
    protocol: str,
    *,
    protocols: ClientConfigProvider | None,
) -> dict:
    try:
        return _native_client_probe(
            state,
            protocol,
            protocols=protocols,
        )
    except Exception as exc:
        return {
            "status": "client_error",
            "started": False,
            "triggered": False,
            "error_type": exc.__class__.__name__,
        }


def _coverage_summary(report: dict) -> dict:
    enabled_items = [
        item
        for item in report["protocols"].values()
        if item.get("enabled")
    ]
    return {
        "enabled_protocols": len(enabled_items),
        "native_logs": sum(
            bool(item["coverage"]["native_log_observed"])
            for item in enabled_items
        ),
        "filter_matches": sum(
            bool(item["coverage"]["filter_match"])
            for item in enabled_items
        ),
        "native_clients_executed": sum(
            bool(item["coverage"]["native_client_probe_sent"])
            for item in enabled_items
        ),
        "external_test_required": [
            "source attribution from a non-whitelisted public IP",
            "ipset/firewall enforcement from that same IP",
            "Telegram delivery for an actual ALERT or BAN event",
        ],
    }


def _archive_path(output: str | None, *, kind: str, stamp: str) -> Path:
    archive = (
        Path(output)
        if output
        else Path(f"/tmp/hydra-antidpi-{kind}-{stamp}.tar.gz")
    )
    if archive.is_dir():
        archive = archive / f"hydra-antidpi-{kind}-{stamp}.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    return archive


def run_selftest(
    state: AppState,
    output: str | None = None,
    wait_seconds: float = 2.0,
    *,
    full: bool = False,
    protocols: ClientConfigProvider | None = None,
) -> dict:
    """Probe enabled transports and write a redacted diagnostic archive."""
    if not _is_linux_host():
        raise RuntimeError("AntiDPI selftest must run on the HYDRA Linux host")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = _archive_path(output, kind="selftest", stamp=stamp)
    redact = _redactor(state)
    report = {
        "schema": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "safe_local_test": True,
        "mode": "full" if full else "malformed",
        "warning": (
            "Loopback probes test native logging and filters; they "
            "intentionally do not test external source attribution, "
            "firewall bans, or Telegram delivery."
        ),
        "environment": _environment(),
        "protocols": {},
    }
    raw = {}
    for protocol in SUPPORTED_PROTOCOLS:
        item, captured = _exercise_protocol(
            state,
            protocol,
            wait_seconds=wait_seconds,
            full=full,
            protocols=protocols,
            redact=redact,
        )
        report["protocols"][protocol] = item
        if captured is not None:
            raw[protocol] = captured
    report["coverage"] = _coverage_summary(report)
    write_selftest_archive(
        archive,
        report=report,
        raw=raw,
        redact=redact,
        full=full,
    )
    captured_count = sum(
        1
        for item in report["protocols"].values()
        if item.get("status") in {"filter_match", "native_log_unmatched"}
    )
    return {
        "ok": True,
        "archive": str(archive),
        "captured_protocols": captured_count,
        "report": report,
    }


def _all_journal(since: float, until: float) -> list[dict]:
    return all_journal(
        since,
        until,
        host=HOST,
        journal_units=JOURNAL_UNITS,
    )


def _all_new_log_lines(
    before: dict[Path, int],
) -> dict[str, list[str]]:
    return all_new_log_lines(before)


def _udp_diagnostics(state: AppState) -> dict:
    return udp_diagnostics(state, host=HOST, map_file=MAP_FILE)


def _capture_event_summary(
    records: list[dict],
    state: AppState,
) -> list[dict]:
    return capture_event_summary(records, state)


def _runtime_delta(before: dict, after: dict) -> dict:
    return runtime_delta(before, after)


def capture_external_tests(
    state: AppState,
    output: str | None = None,
    seconds: float = 120.0,
    *,
    runtime_snapshot: RuntimeSnapshotReader | None = None,
) -> dict:
    """Capture external tests using an injected public runtime snapshot."""
    if not _is_linux_host():
        raise RuntimeError("AntiDPI capture must run on the HYDRA Linux host")
    if runtime_snapshot is None:
        raise ValueError("runtime_snapshot is required")
    duration = max(10.0, min(float(seconds), 600.0))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = _archive_path(output, kind="capture", stamp=stamp)
    redact = _redactor(state)
    before = _offsets()
    runtime_before = runtime_snapshot()
    since = time.time()
    print(
        f"AntiDPI capture active for {duration:.0f}s. "
        "Run invalid-password clients now from an external IP...",
        flush=True,
    )
    time.sleep(duration)
    until = time.time()
    records = _all_journal(since - 0.1, until + 0.1)
    logs = _all_new_log_lines(before)
    runtime = runtime_snapshot()
    report = {
        "schema": 3,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": "external_capture",
        "duration_seconds": round(until - since, 3),
        "environment": _environment(),
        "journal_records": len(records),
        "log_lines": {path: len(lines) for path, lines in logs.items()},
        "antidpi_runtime": runtime,
        "capture_delta": _runtime_delta(runtime_before, runtime),
        "observed_events": _capture_event_summary(records, state),
        "udp_diagnostics": _udp_diagnostics(state),
    }
    write_capture_archive(
        archive,
        report=report,
        records=records,
        logs=logs,
        redact=redact,
    )
    return {
        "ok": True,
        "archive": str(archive),
        "duration_seconds": duration,
    }
