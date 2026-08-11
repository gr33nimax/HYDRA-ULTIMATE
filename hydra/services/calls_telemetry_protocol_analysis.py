"""Protocol-specific analysis for Hydracore Calls telemetry records."""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence


SERVER_PROCESS_REQUIRED = {
    "auth": ("auth_success_total", "auth_failure_total"),
    "dtls": (
        "dtls_handshake_success_total",
        "dtls_handshake_failure_total",
        "dtls_handshake_latency_ms",
    ),
    "handshake": (
        "handshake_pending",
        "handshake_rejected_total",
        "handshake_timeout_total",
        "handshake_latency_ms",
    ),
    "runtime": (
        "runtime_goroutines",
        "runtime_heap_bytes",
        "runtime_gc_pause_seconds_total",
    ),
    "session": ("session_active", "session_created_total", "session_closed_total"),
    "telemetry": (
        "telemetry_sequence",
        "telemetry_control_drops_total",
        "telemetry_record_drops_total",
        "telemetry_sink_rotations_total",
    ),
}
SERVER_SESSION_REQUIRED = {
    "kcp": (
        "kcp_wait_snd",
        "kcp_out_segments_total",
        "kcp_retrans_segments_total",
        "kcp_rtt_ms",
        "kcp_rto_ms",
        "kcp_send_blocked_seconds_total",
        "kcp_mtu_bytes",
        "kcp_send_window_segments",
        "kcp_receive_window_segments",
        "kcp_max_pending_segments",
        "kcp_update_interval_ms",
        "kcp_fast_resend",
        "kcp_congestion_control",
    ),
    "outer": (
        "outer_packets_in_total",
        "outer_packets_out_total",
        "outer_bytes_in_total",
        "outer_bytes_out_total",
        "outer_auth_failures_total",
        "outer_wrap_failures_total",
    ),
    "relay": (
        "relay_tcp_active",
        "relay_udp_active",
        "relay_bytes_total",
        "relay_queue_depth",
        "relay_queue_drops_total",
        "relay_connect_failure_total",
    ),
    "session": ("session_active", "session_age_seconds", "session_idle_seconds"),
    "worker": (
        "worker_desired",
        "worker_active",
        "worker_send_queue_depth",
        "worker_send_queue_drops_total",
        "worker_no_available_drops_total",
        "worker_liveness_expired_total",
        "worker_send_queue_capacity",
        "worker_heartbeat_interval_ms",
        "worker_liveness_timeout_ms",
    ),
    "telemetry": ("telemetry_sequence", "telemetry_control_drops_total"),
}
SERVER_WORKER_REQUIRED = {
    "outer": (
        "outer_packets_in_total",
        "outer_packets_out_total",
        "outer_bytes_in_total",
        "outer_bytes_out_total",
        "outer_auth_failures_total",
        "outer_wrap_failures_total",
    ),
    "peer": ("peer_read_queue_depth", "peer_read_queue_drops_total"),
    "worker": (
        "worker_active",
        "worker_send_queue_depth",
        "worker_send_queue_drops_total",
        "worker_liveness_expired_total",
    ),
    "telemetry": ("telemetry_sequence",),
}
CLIENT_WORKER_REQUIRED = {
    "vk": (
        "vk_auth_success_total",
        "vk_auth_failure_total",
        "vk_auth_latency_ms",
        "vk_auth_anonym_token_latency_ms",
        "vk_call_preview_latency_ms",
        "vk_anonym_call_token_latency_ms",
        "vk_anonym_login_latency_ms",
        "vk_join_conversation_latency_ms",
        "vk_credential_request_total",
        "vk_credential_fetch_total",
        "vk_credential_cache_hit_total",
    ),
    "turn": (
        "turn_allocate_success_total",
        "turn_allocate_failure_total",
        "turn_allocate_latency_ms",
        "turn_endpoints_tried_total",
        "turn_endpoint_count",
        "turn_selected_endpoint_ordinal",
    ),
    "dtls": (
        "dtls_handshake_success_total",
        "dtls_handshake_failure_total",
        "dtls_handshake_latency_ms",
    ),
    "inner_auth": (
        "inner_auth_success_total",
        "inner_auth_failure_total",
        "inner_auth_latency_ms",
    ),
    "worker": (
        "worker_active",
        "worker_reconnect_total",
        "worker_reconnect_backoff_ms",
        "worker_send_queue_depth",
        "worker_send_queue_drops_total",
        "worker_liveness_expired_total",
    ),
    "outer": (
        "outer_packets_in_total",
        "outer_packets_out_total",
        "outer_bytes_in_total",
        "outer_bytes_out_total",
        "outer_auth_failures_total",
        "outer_wrap_failures_total",
    ),
    "telemetry": ("telemetry_sequence",),
}
CLIENT_SESSION_REQUIRED = {
    "worker": (
        "worker_desired",
        "worker_active",
        "worker_reconnect_total",
        "worker_send_queue_capacity",
        "worker_heartbeat_interval_ms",
        "worker_liveness_timeout_ms",
    ),
    "kcp": (
        "kcp_wait_snd",
        "kcp_out_segments_total",
        "kcp_retrans_segments_total",
        "kcp_rtt_ms",
        "kcp_rto_ms",
        "kcp_send_blocked_seconds_total",
        "kcp_mtu_bytes",
        "kcp_send_window_segments",
        "kcp_receive_window_segments",
        "kcp_max_pending_segments",
        "kcp_update_interval_ms",
        "kcp_fast_resend",
        "kcp_congestion_control",
    ),
    "network": (
        "network_loss_ratio",
        "network_jitter_ms",
        "network_handover_total",
        "network_change_total",
    ),
    "runtime": ("runtime_cpu_percent", "runtime_rss_bytes", "runtime_thermal_state"),
    "telemetry": (
        "telemetry_sequence",
        "telemetry_record_drops_total",
        "telemetry_lease_expired_total",
    ),
}

# Compatibility unions for callers that need the complete metric vocabulary.
SERVER_REQUIRED = SERVER_PROCESS_REQUIRED | SERVER_SESSION_REQUIRED
CLIENT_REQUIRED = CLIENT_SESSION_REQUIRED | CLIENT_WORKER_REQUIRED


def analyze_native(
    records: Sequence[Mapping[str, object]],
    tester_ids: Sequence[str],
) -> dict[str, object]:
    native = [record for record in records if record.get("kind") == "native"]
    snapshots = [
        record for record in native if record.get("native_kind") == "snapshot"
    ]
    entities: dict[str, list[Mapping[str, object]]] = {
        "server_process": [],
        "server_session": [],
        "server_worker": [],
        "client_session": [],
        "client_worker": [],
    }
    events: dict[str, int] = {}
    for record in native:
        event = str(record.get("event", ""))
        if event:
            events[event] = events.get(event, 0) + 1
    for record in snapshots:
        entity = _record_entity(record)
        if entity in entities:
            entities[entity].append(record)

    server_process = entities["server_process"]
    server_sessions = _group_entities(entities["server_session"])
    server_workers = _group_entities(entities["server_worker"])
    client_sessions = _group_entities(entities["client_session"])
    client_workers = _group_entities(entities["client_worker"])
    server_groups = _observed_groups(server_process, SERVER_PROCESS_REQUIRED)
    tester_coverage: dict[str, dict[str, object]] = {}
    missing_entities: list[str] = []
    for tester_id in tester_ids:
        tester_server_sessions = _tester_entity_records(server_sessions, tester_id)
        tester_server_workers = _tester_entity_records(server_workers, tester_id)
        tester_client_sessions = _tester_entity_records(client_sessions, tester_id)
        tester_client_workers = _tester_entity_records(client_workers, tester_id)
        desired = int(max(
            _metric_peak(tester_server_sessions, "worker_desired"),
            _metric_peak(tester_client_sessions, "worker_desired"),
        ))
        server_worker_ids = _worker_ids(tester_server_workers)
        client_worker_ids = _worker_ids(tester_client_workers)
        required = {
            "server_session": bool(tester_server_sessions),
            "server_worker": bool(tester_server_workers),
            "client_session": bool(tester_client_sessions),
            "client_worker": bool(tester_client_workers),
        }
        for name, available in required.items():
            if not available:
                missing_entities.append(f"{tester_id}:{name}")
        if desired:
            for worker_id in range(desired):
                if worker_id not in server_worker_ids:
                    missing_entities.append(
                        f"{tester_id}:server_worker:{worker_id}",
                    )
                if worker_id not in client_worker_ids:
                    missing_entities.append(
                        f"{tester_id}:client_worker:{worker_id}",
                    )
        tester_coverage[tester_id] = {
            "required": required,
            "worker_desired": desired,
            "server_worker_ids": sorted(server_worker_ids),
            "client_worker_ids": sorted(client_worker_ids),
            "server_session_groups": _observed_groups(
                tester_server_sessions,
                SERVER_SESSION_REQUIRED,
            ),
            "server_worker_groups": _observed_groups(
                tester_server_workers,
                SERVER_WORKER_REQUIRED,
            ),
            "client_session_groups": _observed_groups(
                tester_client_sessions,
                CLIENT_SESSION_REQUIRED,
            ),
            "client_worker_groups": _observed_groups(
                tester_client_workers,
                CLIENT_WORKER_REQUIRED,
            ),
        }
    missing_groups = [
        f"server_process:{name}"
        for name, available in server_groups.items()
        if not available
    ]
    for tester_id, coverage in tester_coverage.items():
        for field in (
            "server_session_groups",
            "server_worker_groups",
            "client_session_groups",
            "client_worker_groups",
        ):
            for name, available in _mapping(coverage.get(field)).items():
                if not available:
                    missing_groups.append(f"{tester_id}:{field}:{name}")
    full_server = all(server_groups.values())
    full_clients = bool(tester_ids) and not missing_entities and not missing_groups
    diagnostic_level = (
        "full"
        if full_server and full_clients
        else "partial"
        if native
        else "server_observation_only"
    )
    return {
        "available": bool(native),
        "diagnostic_level": diagnostic_level,
        "records": len(native),
        "server_records": sum(
            len(entities[name])
            for name in ("server_process", "server_session", "server_worker")
        ),
        "client_records": sum(
            len(entities[name])
            for name in ("client_session", "client_worker")
        ),
        "server_groups": server_groups,
        "client_groups": {
            tester_id: _mapping(coverage.get("client_session_groups"))
            | _mapping(coverage.get("client_worker_groups"))
            for tester_id, coverage in tester_coverage.items()
        },
        "missing_testers": [
            tester_id
            for tester_id in tester_ids
            if not any(
                str(record.get("tester_id", "")) == tester_id
                for record in snapshots
            )
        ],
        "missing_entities": missing_entities,
        "missing_groups": missing_groups,
        "tester_coverage": tester_coverage,
        "server": _metric_summary(server_process),
        "clients": {
            tester_id: _metric_summary(
                [
                    record
                    for entity in ("client_session", "client_worker")
                    for record in entities[entity]
                    if (str(record.get("tester_id", "")) or "unattributed")
                    == tester_id
                ],
            )
            for tester_id in sorted({
                str(record.get("tester_id", "")) or "unattributed"
                for entity in ("client_session", "client_worker")
                for record in entities[entity]
            })
        },
        "server_sessions": _entity_reports(server_sessions),
        "server_workers": _entity_reports(server_workers),
        "client_sessions": _entity_reports(client_sessions),
        "client_workers": _entity_reports(client_workers),
        "continuity": _native_continuity(entities),
        "events": events,
    }


def _record_entity(record: Mapping[str, object]) -> str:
    explicit = str(record.get("native_entity", ""))
    if explicit:
        return explicit
    scope = str(record.get("native_scope", ""))
    if scope == "server":
        if record.get("worker_id") is not None:
            return "server_worker"
        return "server_session" if record.get("tester_id") else "server_process"
    if scope == "client":
        return "client_worker" if record.get("worker_id") is not None else "client_session"
    return ""


def _entity_key(record: Mapping[str, object]) -> tuple[str, str, int | None]:
    tester_id = str(record.get("tester_id", "")) or "unattributed"
    session_id = str(record.get("native_session_id", "")) or "none"
    worker = record.get("worker_id")
    worker_id = int(worker) if type(worker) is int else None
    return tester_id, session_id, worker_id


def _group_entities(
    records: Sequence[Mapping[str, object]],
) -> dict[tuple[str, str, int | None], list[Mapping[str, object]]]:
    grouped: dict[
        tuple[str, str, int | None],
        list[Mapping[str, object]],
    ] = {}
    for record in records:
        grouped.setdefault(_entity_key(record), []).append(record)
    return grouped


def _tester_entity_records(
    groups: Mapping[
        tuple[str, str, int | None],
        Sequence[Mapping[str, object]],
    ],
    tester_id: str,
) -> list[Mapping[str, object]]:
    return [
        record
        for key, records in groups.items()
        if key[0] == tester_id
        for record in records
    ]


def _worker_ids(records: Sequence[Mapping[str, object]]) -> set[int]:
    return {
        int(record["worker_id"])
        for record in records
        if type(record.get("worker_id")) is int
    }


def _metric_peak(records: Sequence[Mapping[str, object]], name: str) -> float:
    return max(
        (
            _number(_mapping(record.get("metrics")).get(name))
            for record in records
        ),
        default=0.0,
    )


def _entity_reports(
    groups: Mapping[
        tuple[str, str, int | None],
        Sequence[Mapping[str, object]],
    ],
) -> list[dict[str, object]]:
    reports: list[dict[str, object]] = []
    for (tester_id, session_id, worker_id), records in sorted(
        groups.items(),
        key=lambda item: item[0],
    ):
        summary = _metric_summary(records)
        counters = _mapping(summary.get("counters"))
        ordered = sorted(records, key=lambda record: _number(record.get("timestamp")))
        duration = max(
            0.0,
            _number(ordered[-1].get("timestamp"))
            - _number(ordered[0].get("timestamp")),
        ) if len(ordered) > 1 else 0.0
        wire_bytes = _number(counters.get("outer_bytes_in_total")) + _number(
            counters.get("outer_bytes_out_total"),
        )
        wire_in = _number(counters.get("outer_bytes_in_total"))
        wire_out = _number(counters.get("outer_bytes_out_total"))
        relay_bytes = _number(counters.get("relay_bytes_total"))
        out_segments = _number(counters.get("kcp_out_segments_total"))
        retrans = _number(counters.get("kcp_retrans_segments_total"))
        reports.append({
            "tester_id": tester_id,
            "native_session_id": session_id,
            "worker_id": worker_id,
            **summary,
            "duration_seconds": round(duration, 3),
            "wire_bytes": round(wire_bytes, 3),
            "wire_bps": round(wire_bytes * 8 / duration, 3) if duration else 0.0,
            "wire_in_bps": round(wire_in * 8 / duration, 3) if duration else 0.0,
            "wire_out_bps": round(wire_out * 8 / duration, 3) if duration else 0.0,
            "relay_bytes": round(relay_bytes, 3),
            "relay_wire_efficiency_ratio": (
                round(relay_bytes / wire_bytes, 6) if wire_bytes else None
            ),
            "kcp_retransmission_ratio": (
                round(retrans / out_segments, 6) if out_segments else None
            ),
        })
    return reports


def _native_continuity(
    entities: Mapping[str, Sequence[Mapping[str, object]]],
) -> dict[str, object]:
    gap_count = 0
    max_gap = 0.0
    sequence_gaps = 0
    summaries_by_entity: dict[str, list[Mapping[str, object]]] = {}
    for entity, records in entities.items():
        for grouped in _group_entities(records).values():
            ordered = sorted(
                grouped,
                key=lambda record: _number(record.get("timestamp")),
            )
            for previous_record, current_record in zip(ordered, ordered[1:]):
                gap = _number(current_record.get("timestamp")) - _number(
                    previous_record.get("timestamp"),
                )
                stride = max(
                    1,
                    _integer(previous_record.get("analysis_stride")),
                    _integer(current_record.get("analysis_stride")),
                )
                if gap > 5 * stride:
                    gap_count += 1
                    max_gap = max(max_gap, gap)
                previous = int(_number(
                    _mapping(previous_record.get("metrics")).get(
                        "telemetry_sequence",
                    ),
                ))
                current = int(_number(
                    _mapping(current_record.get("metrics")).get(
                        "telemetry_sequence",
                    ),
                ))
                if previous and current > previous + stride:
                    sequence_gaps += current - previous - stride
            summaries_by_entity.setdefault(entity, []).append(
                _metric_summary(ordered),
            )
    server_process = summaries_by_entity.get("server_process", [])
    client_sessions = summaries_by_entity.get("client_session", [])
    return {
        "gap_count": gap_count,
        "max_gap_seconds": round(max_gap, 3),
        "missing_sequences": sequence_gaps,
        "control_drops": int(_summary_counter_total(
            server_process,
            "telemetry_control_drops_total",
        )),
        "server_record_drops": int(_summary_counter_total(
            server_process,
            "telemetry_record_drops_total",
        )),
        "client_record_drops": int(_summary_counter_total(
            client_sessions,
            "telemetry_record_drops_total",
        )),
        "lease_expirations": int(_summary_counter_total(
            client_sessions,
            "telemetry_lease_expired_total",
        )),
        "source_rotations": int(_summary_counter_total(
            server_process,
            "telemetry_sink_rotations_total",
        )),
    }


def _summary_counter_total(
    summaries: Sequence[Mapping[str, object]],
    name: str,
) -> float:
    return sum(
        _number(_mapping(summary.get("counters")).get(name))
        for summary in summaries
    )


def analyze_kernel(samples: Sequence[Mapping[str, object]]) -> dict[str, object]:
    return {
        "softnet_drops": _nested_counter_delta(samples, ("kernel", "softnet"), "dropped"),
        "softnet_time_squeeze": _nested_counter_delta(
            samples,
            ("kernel", "softnet"),
            "time_squeeze",
        ),
        "interface_rx_drops": _nested_counter_delta(
            samples,
            ("kernel", "interfaces"),
            "rx_drops",
        ),
        "interface_tx_drops": _nested_counter_delta(
            samples,
            ("kernel", "interfaces"),
            "tx_drops",
        ),
        "interface_rx_errors": _nested_counter_delta(
            samples,
            ("kernel", "interfaces"),
            "rx_errors",
        ),
        "interface_tx_errors": _nested_counter_delta(
            samples,
            ("kernel", "interfaces"),
            "tx_errors",
        ),
        "cpu_psi_some_avg10": _distribution(
            _nested_values(samples, ("kernel", "pressure", "cpu", "some"), "avg10"),
        ),
        "memory_psi_some_avg10": _distribution(
            _nested_values(samples, ("kernel", "pressure", "memory", "some"), "avg10"),
        ),
        "io_psi_some_avg10": _distribution(
            _nested_values(samples, ("kernel", "pressure", "io", "some"), "avg10"),
        ),
        "conntrack_peak_ratio": _conntrack_peak(samples),
        "minimum_telemetry_disk_free_bytes": min(
            _nested_values(samples, ("kernel", "telemetry_disk"), "free_bytes"),
            default=0.0,
        ),
    }


def phase_reports(
    samples: Sequence[Mapping[str, object]],
    records: Sequence[Mapping[str, object]],
    *,
    started_at: float,
    observed_until: float,
) -> list[dict[str, object]]:
    marks = sorted(
        (record for record in records if record.get("kind") == "mark"),
        key=lambda record: _number(record.get("timestamp")),
    )
    boundaries = [(started_at, "unmarked")]
    boundaries.extend(
        (_number(mark.get("timestamp")), str(mark.get("label", "")))
        for mark in marks
    )
    reports: list[dict[str, object]] = []
    for index, (begin, label) in enumerate(boundaries):
        end = boundaries[index + 1][0] if index + 1 < len(boundaries) else observed_until
        selected = [
            sample
            for sample in samples
            if begin <= _number(sample.get("timestamp")) < end
        ]
        rates = _sample_rates(selected)
        reports.append({
            "label": label,
            "started_at": begin,
            "ended_at": end,
            "duration_seconds": max(0.0, end - begin),
            "samples": len(selected),
            "throughput_bps": _distribution(rates),
            "peak_connections": max(
                (
                    _integer(_mapping(sample.get("calls")).get("active_connections"))
                    for sample in selected
                ),
                default=0,
            ),
        })
    return reports


def protocol_findings(
    native: Mapping[str, object],
    kernel: Mapping[str, object],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if native.get("diagnostic_level") != "full":
        findings.append(_finding(
            "critical",
            "native_coverage_incomplete",
            "Native client/server metrics do not cover every diagnostic stage.",
            "Use an instrumented Hydracore build for all testers before drawing a protocol-level conclusion.",
        ))
    continuity = _mapping(native.get("continuity"))
    if _sum_matching(
        continuity,
        (
            "control_drops",
            "server_record_drops",
            "client_record_drops",
            "lease_expirations",
            "missing_sequences",
        ),
    ):
        findings.append(_finding(
            "critical",
            "native_telemetry_discontinuity",
            "Native control or snapshot records were lost during the measurement window.",
            "Use per-tester continuity counters before comparing rates; "
            "repeat phases whose client sequence has gaps.",
        ))
    server = _mapping(native.get("server"))
    counters = _combined_counters(native)
    gauges = _mapping(server.get("gauges"))
    if _sum_matching(counters, ("queue_drops", "no_worker", "peer_queue")):
        findings.append(_finding(
            "critical",
            "internal_queue_loss",
            "Hydracore dropped records because an internal worker or peer queue was full.",
            "Profile the single UDP unwrap path and worker queues; compare larger queues against latency and RSS.",
        ))
    retrans = _sum_matching(counters, ("kcp_retrans", "kcp_fast_retrans", "kcp_lost"))
    out_segments = _sum_matching(counters, ("kcp_out_segments",))
    if retrans and (not out_segments or retrans / max(1, out_segments) >= 0.1):
        findings.append(_finding(
            "warning",
            "kcp_retransmission_pressure",
            "KCP retransmission/loss counters are high relative to transmitted segments.",
            "Compare by tester, room and worker; tune KCP/window only after separating RTT from packet loss.",
        ))
    server_paths = [
        report
        for report in native.get("server_sessions", [])
        if isinstance(report, Mapping)
    ]
    client_paths = [
        report
        for report in native.get("client_sessions", [])
        if isinstance(report, Mapping)
    ]
    downstream_pressure = any(
        _number(report.get("kcp_retransmission_ratio")) >= 0.1
        for report in server_paths
    ) or any(
        _number(
            _mapping(_mapping(report.get("gauges")).get("network_loss_ratio")).get("p95"),
        ) >= 0.05
        for report in client_paths
    )
    uplink_pressure = any(
        _number(report.get("kcp_retransmission_ratio")) >= 0.1
        for report in client_paths
    ) or any(
        _number(
            _mapping(_mapping(report.get("gauges")).get("network_loss_ratio")).get("p95"),
        ) >= 0.05
        for report in server_paths
    )
    if downstream_pressure and not uplink_pressure:
        findings.append(_finding(
            "critical",
            "downstream_transport_bottleneck",
            "Server-to-client KCP retransmission or client receive loss dominates the reverse direction.",
            "Compare client workers by TURN ordinal, wire rate and loss; "
            "then A/B downstream pacing, congestion control and KCP windows.",
        ))
    elif uplink_pressure and not downstream_pressure:
        findings.append(_finding(
            "critical",
            "uplink_transport_bottleneck",
            "Client-to-server KCP retransmission or server receive loss dominates the reverse direction.",
            "Compare server worker ingress and client TURN paths before tuning client-side pacing and send windows.",
        ))
    wait_p95 = _number(_mapping(gauges.get("kcp_wait_snd")).get("p95"))
    wait_p95 = max(
        wait_p95,
        _entity_gauge_peak(native, "server_sessions", "kcp_wait_snd"),
    )
    wait_p95 = max(wait_p95, _client_gauge_peak(native, "kcp_wait_snd"))
    if wait_p95 >= 1536:
        findings.append(_finding(
            "warning",
            "kcp_send_window_saturated",
            "KCP pending-send depth spent time near the current 2048-segment backpressure cap.",
            "Measure RTT and retransmissions, then test a larger adaptive window or congestion-control strategy.",
        ))
    stale_sessions = [
        report
        for report in native.get("server_sessions", [])
        if isinstance(report, Mapping)
        and _number(
            _mapping(_mapping(report.get("gauges")).get("worker_active")).get("max"),
        ) == 0
        and _number(
            _mapping(_mapping(report.get("gauges")).get("session_idle_seconds")).get("max"),
        ) >= 30
    ]
    if stale_sessions:
        findings.append(_finding(
            "warning",
            "stale_server_sessions",
            "The server retained one or more sessions with no live worker for at least 30 seconds.",
            "Use session IDs to verify idle reaping and exclude stale "
            "sessions from transport comparisons.",
        ))
    if _sum_matching(counters, ("dtls_handshake_failure", "turn_failure", "vk_auth_failure")):
        findings.append(_finding(
            "warning",
            "worker_setup_failures",
            "VK authentication, TURN allocation or DTLS worker setup failed during the run.",
            "Use stage latency/failure distributions to isolate VK control plane, TURN endpoint or DTLS.",
        ))
    if _worker_path_imbalance(native):
        findings.append(_finding(
            "warning",
            "worker_path_imbalance",
            "Parallel VK/TURN workers carried materially different wire rates.",
            "Compare TURN ordinal, loss, queue drops and reconnects per worker; deprioritize persistently weak paths.",
        ))
    if any(
        _integer(kernel.get(key))
        for key in (
            "softnet_drops",
            "interface_rx_drops",
            "interface_tx_drops",
            "interface_rx_errors",
            "interface_tx_errors",
        )
    ):
        findings.append(_finding(
            "critical",
            "kernel_network_loss",
            "The kernel or network interface dropped packets during the experiment.",
            "Remove host/NIC loss before attributing retransmissions to VK TURN or the tunnel protocol.",
        ))
    return findings


def _metric_summary(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    series: dict[str, list[float]] = {}
    for record in records:
        metrics = _mapping(record.get("metrics"))
        for key, value in metrics.items():
            if type(value) in {int, float, bool}:
                series.setdefault(str(key), []).append(float(value))
    counters: dict[str, float] = {}
    gauges: dict[str, dict[str, float]] = {}
    for key, values in sorted(series.items()):
        if key.endswith("_total"):
            counters[key] = round(_monotonic_series_delta(values), 3)
        else:
            gauges[key] = _distribution(values)
    return {"records": len(records), "counters": counters, "gauges": gauges}


def _observed_groups(
    records: Sequence[Mapping[str, object]],
    groups: Mapping[str, Sequence[str]],
) -> dict[str, bool]:
    names = {
        str(name)
        for record in records
        for name in _mapping(record.get("metrics"))
    }
    return {
        group: all(required in names for required in required_names)
        for group, required_names in groups.items()
    }


def _sample_rates(samples: Sequence[Mapping[str, object]]) -> list[float]:
    rates: list[float] = []
    previous_at = 0.0
    previous_total = 0
    for sample in samples:
        timestamp = _number(sample.get("timestamp"))
        calls = _mapping(sample.get("calls"))
        interval = _mapping(calls.get("interval"))
        interval_bytes = _integer(interval.get("upload_bytes")) + _integer(
            interval.get("download_bytes"),
        )
        if interval_bytes and previous_at:
            rates.append(interval_bytes * 8 / max(0.001, timestamp - previous_at))
        elif previous_at:
            total = _integer(calls.get("upload_bytes")) + _integer(calls.get("download_bytes"))
            rates.append(max(0, total - previous_total) * 8 / max(0.001, timestamp - previous_at))
        previous_at = timestamp
        previous_total = _integer(calls.get("upload_bytes")) + _integer(calls.get("download_bytes"))
    return rates


def _nested_counter_delta(
    samples: Sequence[Mapping[str, object]],
    path: Sequence[str],
    key: str,
) -> int:
    values = _nested_values(samples, path, key)
    return int(_monotonic_series_delta(values))


def _nested_values(
    samples: Sequence[Mapping[str, object]],
    path: Sequence[str],
    key: str,
) -> list[float]:
    values: list[float] = []
    for sample in samples:
        current: object = sample
        for part in path:
            current = _mapping(current).get(part)
        value = _mapping(current).get(key)
        if type(value) in {int, float}:
            values.append(float(value))
    return values


def _conntrack_peak(samples: Sequence[Mapping[str, object]]) -> float:
    ratios = []
    for sample in samples:
        metrics = _mapping(_mapping(sample.get("kernel")).get("conntrack"))
        maximum = _integer(metrics.get("max"))
        if maximum:
            ratios.append(_integer(metrics.get("count")) / maximum)
    return round(max(ratios, default=0.0), 6)


def _sum_matching(values: Mapping[str, object], fragments: Sequence[str]) -> float:
    return sum(
        _number(value)
        for key, value in values.items()
        if any(fragment in str(key) for fragment in fragments)
    )


def _combined_counters(native: Mapping[str, object]) -> dict[str, float]:
    combined: dict[str, float] = {}
    summaries = [_mapping(native.get("server"))]
    summaries.extend(
        _mapping(summary)
        for summary in _mapping(native.get("clients")).values()
    )
    summaries.extend(
        _mapping(summary)
        for summary in native.get("server_sessions", [])
        if isinstance(summary, Mapping)
    )
    for summary in summaries:
        for key, value in _mapping(summary.get("counters")).items():
            name = str(key)
            combined[name] = combined.get(name, 0.0) + _number(value)
    return combined


def _client_gauge_peak(native: Mapping[str, object], key: str) -> float:
    return max(
        (
            _number(
                _mapping(
                    _mapping(_mapping(summary).get("gauges")).get(key),
                ).get("p95"),
            )
            for summary in _mapping(native.get("clients")).values()
        ),
        default=0.0,
    )


def _entity_gauge_peak(
    native: Mapping[str, object],
    entity: str,
    key: str,
) -> float:
    records = native.get(entity, [])
    if not isinstance(records, Sequence):
        return 0.0
    return max(
        (
            _number(
                _mapping(_mapping(record.get("gauges")).get(key)).get("p95"),
            )
            for record in records
            if isinstance(record, Mapping)
        ),
        default=0.0,
    )


def _worker_path_imbalance(native: Mapping[str, object]) -> bool:
    reports = native.get("client_workers", [])
    if not isinstance(reports, Sequence):
        return False
    rates_by_tester: dict[str, list[float]] = {}
    for report in reports:
        if not isinstance(report, Mapping):
            continue
        rate = _number(report.get("wire_bps"))
        if rate > 0:
            tester_id = str(report.get("tester_id", "")) or "unattributed"
            rates_by_tester.setdefault(tester_id, []).append(rate)
    return any(
        len(rates) >= 2
        and max(rates) >= 1_000_000
        and max(rates) / max(1, min(rates)) >= 2
        for rates in rates_by_tester.values()
    )


def _monotonic_series_delta(values: Sequence[float]) -> float:
    total = 0.0
    previous: float | None = None
    for current in values:
        if previous is not None:
            total += current - previous if current >= previous else current
        previous = current
    return total


def _distribution(values: Sequence[float]) -> dict[str, float]:
    cleaned = sorted(value for value in values if math.isfinite(value))
    return {
        "min": round(min(cleaned, default=0.0), 3),
        "p50": round(_percentile(cleaned, 50), 3),
        "p95": round(_percentile(cleaned, 95), 3),
        "p99": round(_percentile(cleaned, 99), 3),
        "max": round(max(cleaned, default=0.0), 3),
    }


def _percentile(values: Sequence[float], percentile: int) -> float:
    if not values:
        return 0.0
    index = max(0, math.ceil(percentile / 100 * len(values)) - 1)
    return values[index]


def _finding(severity: str, code: str, message: str, next_step: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "message": message, "next_step": next_step}


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _integer(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _number(value: object) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else 0.0
    except (TypeError, ValueError):
        return 0.0


__all__ = ["analyze_kernel", "analyze_native", "phase_reports", "protocol_findings"]
