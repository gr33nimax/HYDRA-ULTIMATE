from __future__ import annotations

from hydra.services.calls_telemetry_findings import extended_native_findings
from hydra.services.calls_telemetry_lane_analysis import lane_pipeline_summary
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


def test_worker_lane_coverage_does_not_require_session_config_metrics() -> None:
    assert "lane_admission_bytes_per_second" not in SERVER_WORKER_REQUIRED["lanes"]
    assert "outer_rtp_payload_type" not in CLIENT_WORKER_REQUIRED["lanes"]
    assert "lane_admission_bytes_per_second" in SERVER_SESSION_REQUIRED["lanes"]
    assert "outer_rtp_payload_type" in CLIENT_SESSION_REQUIRED["lanes"]
    assert "lane_generation" in SERVER_WORKER_REQUIRED["lanes"]
    assert "lane_pacing_bytes_per_second" in CLIENT_WORKER_REQUIRED["lanes"]
    assert "lane_reset_commit_total" in SERVER_WORKER_REQUIRED["lanes"]
    assert "aggregate_progress_age_seconds" in CLIENT_SESSION_REQUIRED["lanes"]


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


def test_worker_report_splits_fast_and_rto_retransmission_estimates() -> None:
    records = []
    for timestamp, segments, retransmissions, fast, rto in (
        (10.0, 100, 10, 6, 4),
        (20.0, 200, 30, 18, 12),
    ):
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
                "kcp_fast_retrans_estimate_segments_total": fast,
                "kcp_rto_retrans_estimate_segments_total": rto,
            },
        })

    result = analyze_native(records, ["tester-1"])

    assert result["server_workers"][0]["kcp_retransmission_ratio"] == 0.2
    assert result["server_workers"][0]["kcp_fast_retransmission_ratio"] == 0.12
    assert result["server_workers"][0]["kcp_rto_retransmission_ratio"] == 0.08
    assert result["server_workers"][0]["kcp_fast_retransmission_share"] == 0.6
    assert result["server_workers"][0]["kcp_rto_retransmission_share"] == 0.4


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


def test_lane_findings_report_bounded_session_recovery_events() -> None:
    native = {
        "events": {
            "lane_send_stalled": 1,
            "lane_reorder_timeout": 1,
            "lane_udp_reorder_timeout": 1,
            "network_rebind_lane_failed": 1,
        },
        "lane_recovery": {
            "attempts": 1,
            "matched_recoveries": 1,
            "unresolved": 0,
        },
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert "lane_recovery_succeeded" in codes
    assert "lane_reorder_timeout_recovery" in codes
    assert "lane_udp_reorder_timeout" in codes
    assert "network_rebind_lane_failed" in codes


def test_wire_v7_findings_identify_four_call_capacity_ceiling() -> None:
    native = {
        "events": {},
        "server_sessions": [],
        "client_sessions": [],
        "server_workers": [
            {
                "current": True,
                "worker_id": lane,
                "tester_id": "tester-1",
                "native_session_id": "session-1",
                "wire_bps": 1_600_000,
                "kcp_retransmission_ratio": 0.04,
                "gauges": {
                    "lane_pacing_bytes_per_second": {
                        "p50": 200_000,
                        "p95": 200_000,
                    },
                    "lane_delivered_bytes_per_second": {"p95": 180_000},
                },
                "counters": {"lane_token_starvation_total": 0},
            }
            for lane in range(4)
        ],
        "client_workers": [],
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert "physical_capacity_ceiling" in codes
    assert "congestion_pacing_collapse" not in codes


def test_wire_v7_findings_report_reset_and_session_failure_categories() -> None:
    native = {
        "events": {"session_replacement": 1},
        "server_sessions": [],
        "client_sessions": [],
        "server_workers": [{
            "current": True,
            "wire_bps": 1_000_000,
            "kcp_retransmission_ratio": 0.2,
            "gauges": {
                "lane_pacing_bytes_per_second": {"p50": 32_000, "p95": 40_000},
                "lane_delivered_bytes_per_second": {"p95": 20_000},
                "lane_probe_result": {"p95": 0},
            },
            "counters": {
                "lane_token_starvation_total": 2,
                "lane_reset_request_total": 2,
                "lane_reset_commit_total": 1,
            },
        }],
        "client_workers": [],
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert "congestion_pacing_collapse" in codes
    assert "lane_reset_failed" in codes
    assert "full_session_replacement" in codes


def test_native_analysis_pairs_session_wide_lane_recovery_duration() -> None:
    records = [
        {
            "kind": "native",
            "timestamp": timestamp,
            "native_scope": "server",
            "native_kind": "event",
            "native_entity": "server_worker",
            "tester_id": "tester-1",
            "native_session_id": "session-1",
            "worker_id": 2,
            "event": event,
            "metrics": {},
        }
        for timestamp, event in (
            (10.0, "lane_send_stalled"),
            (10.1, "lane_send_recovery"),
            (11.6, "lane_send_recovered"),
        )
    ]

    recovery = analyze_native(records, ["tester-1"])["lane_recovery"]

    assert recovery["stalls"] == 1
    assert recovery["attempts"] == 1
    assert recovery["matched_recoveries"] == 1
    assert recovery["unresolved"] == 0
    assert recovery["duration_seconds"]["p95"] == 1.5


def test_native_analysis_resolves_recovery_escalated_to_session_replace() -> None:
    records = [
        {
            "kind": "native",
            "timestamp": timestamp,
            "native_scope": "server",
            "native_kind": "event",
            "native_entity": "server_worker",
            "tester_id": "tester-1",
            "native_session_id": "session-1",
            "worker_id": 2,
            "event": event,
            "metrics": {},
        }
        for timestamp, event in (
            (10.0, "lane_send_recovery"),
            (12.0, "lane_send_recovery_escalated"),
        )
    ]

    recovery = analyze_native(records, ["tester-1"])["lane_recovery"]

    assert recovery["escalated"] == 1
    assert recovery["unresolved"] == 0


def test_lane_findings_use_ack_progress_and_rtt_sample_coverage() -> None:
    worker = {
        "current": True,
        "active": True,
        "wire_bps": 1_000_000,
        "kcp_ack_progress_ratio": 0.8,
        "kcp_rtt_sample_coverage_ratio": 0.0,
        "counters": {"kcp_out_segments_total": 1000},
        "gauges": {},
    }
    native = {
        "events": {},
        "lane_recovery": {},
        "server_workers": [worker],
        "client_workers": [],
        "server_sessions": [],
        "client_sessions": [],
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert "lane_rtt_sampling_missing" in codes


def test_protocol_findings_distinguish_rto_dominated_retransmissions() -> None:
    native = {
        "server": {
            "counters": {
                "kcp_out_segments_total": 1000,
                "kcp_retrans_segments_total": 300,
                "kcp_fast_retrans_estimate_segments_total": 60,
                "kcp_rto_retrans_estimate_segments_total": 240,
            },
            "gauges": {},
        },
        "clients": {},
        "server_sessions": [],
        "client_sessions": [],
    }

    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert "kcp_retransmission_pressure" in codes
    assert "kcp_rto_retransmission_dominant" in codes
    assert "kcp_fast_retransmission_dominant" not in codes


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


def test_debug23_pipeline_metrics_identify_internal_and_physical_pressure() -> None:
    worker = {
        "current": True,
        "active": True,
        "gauges": {
            "kcp_output_queue_depth": {"p95": 128},
            "kcp_output_queue_capacity": {"max": 128},
            "lane_admission_window_segments": {"p50": 48, "p95": 64},
            "worker_write_latency_ms": {"p95": 25},
        },
        "counters": {
            "kcp_update_backpressure_total": 3,
            "kcp_mutex_blocked_seconds_total": 0.075,
        },
    }
    native = {
        "diagnostic_level": "full",
        "server": {"counters": {}, "gauges": {}},
        "clients": {},
        "events": {},
        "lane_recovery": {},
        "server_workers": [worker],
        "client_workers": [],
        "server_sessions": [{
            "current": True,
            "counters": {"flow_reorder_abort_total": 1},
            "gauges": {},
        }],
        "client_sessions": [],
    }

    pipeline = lane_pipeline_summary(native)
    native["lane_pipeline"] = pipeline
    codes = {finding["code"] for finding in protocol_findings(native, {})}

    assert pipeline == {
        "available": True,
        "output_queue_depth_p95": 128.0,
        "output_queue_capacity": 128.0,
        "output_queue_utilization_ratio": 1.0,
        "admission_window_p50_min": 48.0,
        "admission_window_p95_max": 64.0,
        "worker_write_latency_p95_ms": 25.0,
        "update_backpressure_total": 3.0,
        "mutex_blocked_seconds_total": 0.075,
        "flow_reorder_abort_total": 1.0,
    }
    assert {
        "kcp_output_staging_backpressure",
        "kcp_mutex_contention",
        "worker_physical_write_latency",
        "ordered_flow_reorder_abort",
    } <= codes
