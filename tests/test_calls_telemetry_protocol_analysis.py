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


def test_worker_report_uses_cumulative_kcp_segments_for_exact_retry_ratio() -> None:
    records = []
    for timestamp, segments, retransmissions in ((10.0, 100, 10), (20.0, 200, 30)):
        records.append({
            "kind": "native",
            "timestamp": timestamp,
            "native_scope": "server",
            "native_kind": "snapshot",
            "native_entity": "server_worker",
            "tester_id": "tester-1",
            "native_session_id": "session-1",
            "worker_id": 0,
            "metrics": {
                "worker_active": 1,
                "kcp_out_segments_total": segments,
                "kcp_retrans_segments_total": retransmissions,
            },
        })

    result = analyze_native(records, ["tester-1"])

    assert result["server_workers"][0]["kcp_retransmission_ratio"] == 0.2


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


def test_lane_findings_require_all_four_independent_kcp_lanes() -> None:
    native = {
        "server": {"counters": {}, "gauges": {}},
        "clients": {},
        "server_sessions": [],
        "client_sessions": [],
        "server_workers": [
            {
                "current": True,
                "active": True,
                "tester_id": "tester-1",
                "native_session_id": "session-1",
                "worker_id": lane,
                "wire_bps": 1_000_000,
                "kcp_retransmission_ratio": 0.02,
                "gauges": {"kcp_rtt_ms": {"p95": 50}},
                "counters": {},
            }
            for lane in range(3)
        ],
        "client_workers": [],
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert "four_lane_session_incomplete" in codes


def test_lane_findings_isolate_retransmission_imbalance() -> None:
    native = {
        "server": {"counters": {}, "gauges": {}},
        "clients": {},
        "server_sessions": [],
        "client_sessions": [],
        "server_workers": [
            {
                "current": True,
                "active": True,
                "tester_id": "tester-1",
                "native_session_id": "session-1",
                "worker_id": lane,
                "wire_bps": 1_000_000,
                "kcp_retransmission_ratio": ratio,
                "gauges": {"kcp_rtt_ms": {"p95": 50}},
                "counters": {},
            }
            for lane, ratio in enumerate((0.02, 0.03, 0.04, 0.25))
        ],
        "client_workers": [],
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert "lane_kcp_imbalance" in codes


def test_kcp_pending_saturation_uses_reported_aggregate_cap() -> None:
    native = {
        "server": {
            "counters": {},
            "gauges": {
                "kcp_wait_snd": {"p95": 500},
                "kcp_max_pending_segments": {"p95": 640},
            },
        },
        "clients": {},
        "server_sessions": [],
        "client_sessions": [],
    }

    findings = protocol_findings(native, {})
    finding = next(item for item in findings if item["code"] == "kcp_send_window_saturated")

    assert "640-segment" in finding["message"]
    assert "per-lane WaitSnd" in finding["next_step"]


def test_protocol_findings_do_not_mix_retransmit_bytes_with_segment_ratio() -> None:
    native = {
        "server": {
            "counters": {
                "kcp_out_segments_total": 1000,
                "kcp_retrans_segments_total": 20,
                "kcp_retrans_bytes_total": 50_000_000,
            },
            "gauges": {},
        },
        "clients": {},
        "server_sessions": [],
        "client_sessions": [],
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert "kcp_retransmission_pressure" not in codes


def test_current_findings_ignore_historical_queue_drops() -> None:
    native = {
        "server": {
            "counters": {
                "worker_send_queue_drops_total": 100,
                "worker_reconnect_total": 100,
            },
            "gauges": {},
        },
        "clients": {},
        "server_processes": [{
            "current": True,
            "counters": {"udp_ingress_queue_drops_total": 0},
            "gauges": {},
        }],
        "server_sessions": [{
            "current": True,
            "counters": {"worker_send_queue_drops_total": 0},
            "gauges": {},
        }],
        "client_sessions": [],
        "server_workers": [],
        "client_workers": [],
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}
    extended_codes = {
        finding["code"] for finding in extended_native_findings(native)
    }

    assert "internal_queue_loss" not in codes
    assert "worker_transport_instability" not in extended_codes


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
