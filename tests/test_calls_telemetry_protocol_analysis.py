from __future__ import annotations

from hydra.services.calls_telemetry_findings import extended_native_findings
from hydra.services.calls_telemetry_protocol_analysis import (
    CLIENT_SESSION_REQUIRED,
    CLIENT_WORKER_REQUIRED,
    SERVER_PROCESS_REQUIRED,
    SERVER_SESSION_REQUIRED,
    SERVER_WORKER_REQUIRED,
    analyze_native,
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
                "outer_auth_failures_total": 1,
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
