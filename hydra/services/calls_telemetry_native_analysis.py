"""Per-process, session, and worker analysis for native VK tunnel records."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from hydra.services.calls_telemetry_analysis_common import (
    _integer,
    _mapping,
    _metric_summary,
    _number,
    _observed_groups,
)
from hydra.services.calls_telemetry_native_contract import (
    CLIENT_SESSION_REQUIRED,
    CLIENT_WORKER_REQUIRED,
    SERVER_PROCESS_REQUIRED,
    SERVER_SESSION_REQUIRED,
    SERVER_WORKER_REQUIRED,
)

def analyze_native(
    records: Sequence[Mapping[str, object]],
    tester_ids: Sequence[str],
) -> dict[str, object]:
    native = [record for record in records if record.get("kind") == "native"]
    snapshots = [record for record in native if record.get("native_kind") == "snapshot"]
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
        "server": _process_metric_summary(server_process),
        "clients": {
            tester_id: _metric_summary(
                [
                    record
                    for record in entities["client_session"]
                    if (str(record.get("tester_id", "")) or "unattributed")
                    == tester_id
                ],
            )
            for tester_id in sorted({
                str(record.get("tester_id", "")) or "unattributed"
                for record in entities["client_session"]
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
    sequence_resets = 0
    counter_resets = 0
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
                if previous and current and current < previous:
                    sequence_resets += 1
                previous_metrics = _mapping(previous_record.get("metrics"))
                current_metrics = _mapping(current_record.get("metrics"))
                if any(
                    name.endswith("_total")
                    and name in current_metrics
                    and _number(current_metrics.get(name)) < _number(value)
                    for name, value in previous_metrics.items()
                ):
                    counter_resets += 1
            summaries_by_entity.setdefault(entity, []).append(
                _metric_summary(ordered),
            )
    server_process = summaries_by_entity.get("server_process", [])
    client_sessions = summaries_by_entity.get("client_session", [])
    return {
        "gap_count": gap_count,
        "max_gap_seconds": round(max_gap, 3),
        "missing_sequences": sequence_gaps,
        "sequence_resets": sequence_resets,
        "counter_resets": counter_resets,
        "server_generations": len(_group_entities(entities.get("server_process", []))),
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


def _process_metric_summary(
    records: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    summary = _metric_summary(records)
    counters: dict[str, float] = {}
    groups = _group_entities(records)
    ordered_groups = sorted(
        groups.values(),
        key=lambda grouped: min(
            (_number(record.get("timestamp")) for record in grouped),
            default=0.0,
        ),
    )
    for index, grouped in enumerate(ordered_groups):
        grouped_counters = _mapping(_metric_summary(grouped).get("counters"))
        for name, value in grouped_counters.items():
            key = str(name)
            counters[key] = counters.get(key, 0.0) + _number(value)
        if index:
            first = min(grouped, key=lambda record: _number(record.get("timestamp")))
            for name, value in _mapping(first.get("metrics")).items():
                if str(name).endswith("_total"):
                    key = str(name)
                    counters[key] = counters.get(key, 0.0) + _number(value)
    summary["counters"] = {
        name: round(value, 3)
        for name, value in sorted(counters.items())
    }
    summary["generations"] = len(groups)
    return summary


def _summary_counter_total(
    summaries: Sequence[Mapping[str, object]],
    name: str,
) -> float:
    return sum(
        _number(_mapping(summary.get("counters")).get(name))
        for summary in summaries
    )


__all__ = ["analyze_native"]
