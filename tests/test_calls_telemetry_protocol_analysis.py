from __future__ import annotations

from hydra.services.calls_telemetry_findings import extended_native_findings
from hydra.services.calls_telemetry_protocol_analysis import (
    CLIENT_SESSION_REQUIRED,
    CLIENT_WORKER_REQUIRED,
    SERVER_PROCESS_REQUIRED,
    SERVER_SESSION_REQUIRED,
    SERVER_WORKER_REQUIRED,
    analyze_native,
    protocol_findings,
)


def _metrics(groups: dict[str, tuple[str, ...]]) -> dict[str, float]:
    return {
        metric: 1.0
        for required in groups.values()
        for metric in required
    }


def test_full_diagnostic_level_requires_every_server_and_tester_group() -> None:
    records = [
        {
            "kind": "native",
            "native_scope": "server",
            "native_kind": "snapshot",
            "native_entity": "server_process",
            "metrics": _metrics(SERVER_PROCESS_REQUIRED),
        },
        {
            "kind": "native",
            "native_scope": "server",
            "native_kind": "snapshot",
            "native_entity": "server_session",
            "tester_id": "tester-1",
            "native_session_id": "native-session",
            "metrics": _metrics(SERVER_SESSION_REQUIRED),
        },
        {
            "kind": "native",
            "native_scope": "server",
            "native_kind": "snapshot",
            "native_entity": "server_worker",
            "tester_id": "tester-1",
            "native_session_id": "native-session",
            "worker_id": 0,
            "metrics": _metrics(SERVER_WORKER_REQUIRED),
        },
        {
            "kind": "native",
            "native_scope": "client",
            "native_kind": "snapshot",
            "native_entity": "client_session",
            "tester_id": "tester-1",
            "native_session_id": "native-session",
            "metrics": _metrics(CLIENT_SESSION_REQUIRED),
        },
        {
            "kind": "native",
            "native_scope": "client",
            "native_kind": "snapshot",
            "native_entity": "client_worker",
            "tester_id": "tester-1",
            "native_session_id": "native-session",
            "worker_id": 0,
            "metrics": _metrics(CLIENT_WORKER_REQUIRED),
        },
    ]

    result = analyze_native(records, ["tester-1"])

    assert result["diagnostic_level"] == "full"
    assert all(result["server_groups"].values())
    assert all(result["client_groups"]["tester-1"].values())


def test_native_findings_separate_transport_host_and_relay_directions() -> None:
    native = {
        "goodput_wire_efficiency_ratio": 0.5,
        "server": {
            "counters": {
                "handshake_timeout_total": 2,
                "outer_auth_failures_total": 10,
                "outer_packets_in_total": 1000,
                "relay_connect_failure_total": 3,
            },
            "gauges": {"kcp_rtt_ms": {"p95": 350}},
        },
        "clients": {
            "tester-1": {
                "counters": {"worker_reconnect_total": 4},
                "gauges": {"network_loss_ratio": {"p95": 0.1}},
            },
        },
    }

    codes = {finding["code"] for finding in extended_native_findings(native)}

    assert codes == {
        "handshake_capacity_pressure",
        "worker_transport_instability",
        "outer_packet_authentication_failures",
        "relay_connect_failures",
        "client_network_loss",
        "high_kcp_rtt",
        "low_wire_efficiency",
    }


def test_client_summary_does_not_multiply_session_counters_by_workers() -> None:
    records = []
    for value in (100, 140):
        records.append({
            "kind": "native",
            "native_scope": "client",
            "native_kind": "snapshot",
            "native_entity": "client_session",
            "tester_id": "tester-1",
            "native_session_id": "session-1",
            "metrics": {"worker_reconnect_total": value},
        })
        for worker_id in range(4):
            records.append({
                "kind": "native",
                "native_scope": "client",
                "native_kind": "snapshot",
                "native_entity": "client_worker",
                "tester_id": "tester-1",
                "native_session_id": "session-1",
                "worker_id": worker_id,
                "metrics": {"worker_reconnect_total": value},
            })

    result = analyze_native(records, ["tester-1"])

    assert result["clients"]["tester-1"]["counters"]["worker_reconnect_total"] == 40


def test_server_process_generations_are_aggregated_without_cross_series_resets() -> None:
    records = []
    for generation in ("generation-1", "generation-2"):
        for sequence, value in ((1, 10), (2, 25)):
            records.append({
                "kind": "native",
                "native_scope": "server",
                "native_kind": "snapshot",
                "native_entity": "server_process",
                "native_session_id": generation,
                "metrics": {
                    "telemetry_sequence": sequence,
                    "handshake_rejected_total": value,
                },
            })

    result = analyze_native(records, [])

    assert result["server"]["generations"] == 2
    assert result["server"]["counters"]["handshake_rejected_total"] == 40
    assert result["continuity"]["server_generations"] == 2


def test_entity_reports_mark_only_recent_live_session_as_current() -> None:
    records = [
        {
            "kind": "native",
            "timestamp": 10.0,
            "native_scope": "server",
            "native_kind": "snapshot",
            "native_entity": "server_worker",
            "tester_id": "tester-1",
            "native_session_id": "old-session",
            "worker_id": 0,
            "metrics": {"worker_active": 1},
        },
        {
            "kind": "native",
            "timestamp": 30.0,
            "native_scope": "server",
            "native_kind": "snapshot",
            "native_entity": "server_worker",
            "tester_id": "tester-1",
            "native_session_id": "current-session",
            "worker_id": 0,
            "metrics": {"worker_active": 1},
        },
    ]

    result = analyze_native(records, ["tester-1"])
    reports = {item["native_session_id"]: item for item in result["server_workers"]}

    assert reports["old-session"]["active"] is True
    assert reports["old-session"]["current"] is False
    assert reports["current-session"]["current"] is True


def test_negligible_outer_auth_noise_is_not_reported_as_critical() -> None:
    native = {
        "server": {
            "counters": {
                "outer_auth_failures_total": 16,
                "outer_packets_in_total": 3_000_000,
            },
            "gauges": {},
        },
        "clients": {},
    }

    codes = {finding["code"] for finding in extended_native_findings(native)}

    assert "outer_packet_authentication_failures" not in codes


def test_protocol_findings_distinguish_legacy_reordering_from_adaptive_retries() -> None:
    legacy = {
        "server": {
            "counters": {
                "kcp_out_segments_total": 1000,
                "kcp_retrans_segments_total": 400,
            },
            "gauges": {},
        },
        "clients": {},
        "server_sessions": [{
            "gauges": {"multipath_profile": {"max": 0}},
        }],
        "client_sessions": [],
    }
    legacy_codes = {
        finding["code"] for finding in protocol_findings(legacy, {})
    }
    assert "legacy_multipath_reordering" in legacy_codes

    adaptive = {
        **legacy,
        "server_sessions": [{
            "gauges": {"multipath_profile": {"max": 1}},
        }],
        "server_workers": [{
            "gauges": {"worker_path_retry_ratio": {"p95": 0.2}},
        }],
    }
    adaptive_codes = {
        finding["code"] for finding in protocol_findings(adaptive, {})
    }
    assert "legacy_multipath_reordering" not in adaptive_codes
    assert "adaptive_path_pressure" in adaptive_codes


def test_protocol_findings_detect_post_kcp_output_queue_delay() -> None:
    native = {
        "diagnostic_level": "full",
        "server": {
            "counters": {"worker_output_queue_late_total": 4},
            "gauges": {},
        },
        "clients": {},
        "server_sessions": [],
        "client_sessions": [],
        "server_workers": [{
            "gauges": {"worker_output_queue_delay_ms": {"p95": 35}},
        }],
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert "post_kcp_output_queue_delay" in codes
