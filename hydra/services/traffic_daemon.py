"""Background Sing-box traffic-accounting entry point.

Infrastructure polling stays here; attribution parsing and state mutation live
in independently testable modules.  Compatibility helpers retain the historic
test/import surface while delegating to those modules.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from hydra.core.host import HOST
from hydra.core.state import load_state, update_state
from hydra.core.state_models import AppState
from hydra.services.device_sessions import (
    connections_to_close,
    update_sessions,
)
from hydra.services.traffic_accounting import apply_connection_snapshot
from hydra.services.traffic_attribution import (
    TrafficEvidence,
    parse_hysteria2_users,
)
from hydra.services.traffic_daemon_infrastructure import (
    collect_traffic_evidence,
)
from hydra.services.traffic_log import maintain_traffic_log as _maintain_traffic_log
from hydra.utils.commands import redact_text


TRAFFIC_LOG = Path("/var/log/hydra/traffic-daemon.log")
TRAFFIC_LOG_BACKUP = Path("/var/log/hydra/traffic-daemon.log.1")
TRAFFIC_LOG_MAX_BYTES = 5 * 1024 * 1024

# Historical private import retained for callers and tests.
_parse_hysteria2_users = parse_hysteria2_users


def maintain_traffic_log() -> None:
    """Compatibility wrapper retaining historical monkeypatch seams."""
    _maintain_traffic_log(
        TRAFFIC_LOG,
        TRAFFIC_LOG_BACKUP,
        TRAFFIC_LOG_MAX_BYTES,
    )


def _write_log(message: str) -> None:
    """Append one redacted event while keeping the custom log bounded."""
    try:
        maintain_traffic_log()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with TRAFFIC_LOG.open("a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {redact_text(message)}\n")
    except OSError:
        pass


def _split_destination_evidence(
    values: dict[tuple[str, str], str | None],
) -> tuple[dict[tuple[str, str], str | None], dict[str, str]]:
    destinations: dict[tuple[str, str], str | None] = {}
    connection_ids: dict[str, str] = {}
    for key, user in values.items():
        if key[0] == "__id__":
            if user:
                connection_ids[key[1]] = user
        else:
            destinations[key] = user
    return destinations, connection_ids


def _apply_connection_snapshot(
    state: AppState,
    connections: list[dict[str, Any]],
    anytls_ports: dict[str, str],
    trusttunnel_users: dict[tuple[str, str], str | None],
    mieru_users: dict[tuple[str, str], str],
    shadowtls_users: dict[tuple[str, str], str | None] | None = None,
    hysteria2_users: dict[tuple[str, str], str] | None = None,
) -> bool:
    """Compatibility adapter for the former protocol-specific signature."""
    trust_destinations, trust_ids = _split_destination_evidence(
        trusttunnel_users,
    )
    shadow_destinations, shadow_ids = _split_destination_evidence(
        shadowtls_users or {},
    )
    evidence = TrafficEvidence(
        source_ports={"anytls": anytls_ports},
        sources={
            "mieru": mieru_users,
            "hysteria2": hysteria2_users or {},
        },
        destinations={
            "trusttunnel": trust_destinations,
            "shadowtls": shadow_destinations,
        },
        connection_ids={
            "trusttunnel": trust_ids,
            "shadowtls": shadow_ids,
        },
    )
    return apply_connection_snapshot(state, connections, evidence)


def _fetch_connections(port: int, secret: str) -> list[dict[str, Any]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/connections",
    )
    if secret:
        request.add_header("Authorization", f"Bearer {secret}")
    with urllib.request.urlopen(request, timeout=5) as response:
        data = json.loads(response.read().decode("utf-8"))
    connections = data.get("connections", [])
    return connections if isinstance(connections, list) else []


def _close_connection(port: int, secret: str, connection_id: str) -> bool:
    """Ask Sing-Box to drop one connection through the Clash API."""
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/connections/{urllib.parse.quote(connection_id)}",
        method="DELETE",
    )
    if secret:
        request.add_header("Authorization", f"Bearer {secret}")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return 200 <= int(response.status or 0) < 300
    except urllib.error.HTTPError as exc:
        return exc.code in (204, 404)
    except Exception:
        return False


def _enforce_device_limits(
    state: AppState,
    *,
    port: int,
    secret: str,
) -> int:
    """Close connections from devices beyond a user's simultaneous limit."""
    refused = update_sessions(state)
    if not refused:
        return 0
    closed = 0
    for connection_id in connections_to_close(state, refused):
        if _close_connection(port, secret, connection_id):
            closed += 1
    for user, addresses in sorted(refused.items()):
        _write_log(
            f"Device limit for {user}: refusing "
            + ", ".join(sorted(addresses)),
        )
    if not closed:
        _write_log(
            "Device limit enforcement could not close connections; "
            "check that the Clash API allows DELETE /connections",
        )
    return closed


def _log_summary(
    state: AppState,
    *,
    counters_updated: bool,
) -> None:
    active = state.install.get("traffic_connection_counters", {})
    active_records = [
        record
        for record in active.values()
        if int(record.get("missed_polls", 0)) == 0
    ]
    attributed = sum(
        bool(record.get("user")) and record.get("protocol") != "unknown"
        for record in active_records
    )
    active_bytes = sum(
        max(0, int(record.get("upload", 0)))
        + max(0, int(record.get("download", 0)))
        for record in active_records
    )
    _write_log(
        "Traffic snapshot: "
        f"connections={len(active_records)}, attributed={attributed}, "
        f"active_bytes={active_bytes}, "
        f"counters_updated={str(counters_updated).lower()}",
    )


def run_daemon() -> None:
    """Poll Clash API forever, persisting only monotonic traffic deltas."""
    last_summary_at = 0.0
    last_api_error_at = 0.0

    while True:
        try:
            state = load_state()
            if not state.network.clash_api_enabled:
                time.sleep(15)
                continue
            try:
                connections = _fetch_connections(
                    state.network.clash_api_port,
                    state.network.clash_api_secret,
                )
            except urllib.error.URLError as exc:
                current = time.monotonic()
                if current - last_api_error_at >= 60:
                    _write_log(f"Clash API unavailable: {exc}")
                    last_api_error_at = current
                time.sleep(10)
                continue
            except Exception as exc:
                _write_log(f"API query error: {exc}")
                time.sleep(10)
                continue

            evidence = collect_traffic_evidence(HOST)

            def account(latest: AppState) -> bool:
                updated = apply_connection_snapshot(
                    latest,
                    connections,
                    evidence,
                )
                _enforce_device_limits(
                    latest,
                    port=latest.network.clash_api_port,
                    secret=latest.network.clash_api_secret,
                )
                return updated

            state, counters_updated = update_state(account)
            current = time.monotonic()
            if current - last_summary_at >= 300:
                _log_summary(
                    state,
                    counters_updated=counters_updated,
                )
                last_summary_at = current
        except Exception as exc:
            _write_log(f"General error: {exc}")
        time.sleep(2)


if __name__ == "__main__":
    try:
        run_daemon()
    except Exception as exc:
        print(f"Traffic daemon fatal error: {exc}", file=sys.stderr)
        sys.exit(1)
