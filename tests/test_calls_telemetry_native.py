from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hydra.services.calls_telemetry_native import ingest_native_records


def _session() -> dict[str, object]:
    return {
        "started_at": 1000.0,
        "salt": "salt",
        "tester_hashes": {},
    }


def _record() -> str:
    return json.dumps({
        "schema": 1,
        "timestamp": 1001.0,
        "scope": "server",
        "kind": "snapshot",
        "session_id": "server-0123456789abcdef",
        "metrics": {"worker_active": 3},
    })


def test_incomplete_native_line_is_retried_after_writer_finishes(tmp_path: Path) -> None:
    path = tmp_path / "native.jsonl"
    path.write_text(_record(), encoding="utf-8")
    session = _session()

    assert ingest_native_records(session, path, now=1002.0) == ([], 0)
    assert session["native_cursor"]["offset"] == 0

    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n")

    records, invalid = ingest_native_records(session, path, now=1002.0)
    assert invalid == 0
    assert len(records) == 1
    assert records[0]["native_entity"] == "server_process"


def test_oversized_native_line_does_not_consume_the_next_record(tmp_path: Path) -> None:
    path = tmp_path / "native.jsonl"
    path.write_bytes(b"x" * (64 * 1024 + 1) + b"\n" + _record().encode() + b"\n")

    records, invalid = ingest_native_records(_session(), path, now=1002.0)

    assert invalid == 1
    assert len(records) == 1


def test_four_lane_session_metrics_are_accepted_as_one_complete_record(
    tmp_path: Path,
) -> None:
    path = tmp_path / "native.jsonl"
    payload = {
        "schema": 1,
        "timestamp": 1001.0,
        "scope": "server",
        "kind": "snapshot",
        "user": "tester-user",
        "session_id": "session-0123456789abcdef",
        "metrics": {
            "lane_count": 4,
            "lane_flow_count": 12,
            "lane_admission_bytes_per_second": 190_000,
            "outer_rtp_payload_type": 96,
            "kcp_wait_snd": 8,
            "kcp_rtt_ms": 55,
            "kcp_rto_ms": 120,
            "worker_output_queue_delay_ms": 2.5,
            "worker_output_queue_late_total": 0,
            "kcp_congestion_control": 0,
        },
    }
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    records, invalid = ingest_native_records(_session(), path, now=1002.0)

    assert invalid == 0
    assert len(records) == 1
    assert records[0]["native_entity"] == "server_session"
    assert records[0]["metrics"] == payload["metrics"]


def test_native_rotation_handoff_is_drained_before_the_new_runtime_file(tmp_path: Path) -> None:
    path = tmp_path / "native.jsonl"
    path.write_text(_record() + "\n", encoding="utf-8")
    session = _session() | {"session_id": "20260811T120000Z-deadbeef"}

    first, invalid = ingest_native_records(session, path, now=1002.0)
    assert invalid == 0
    assert len(first) == 1
    with path.open("a", encoding="utf-8") as handle:
        handle.write(_record() + "\n")
    segment = Path(
        f"{path}.{session['session_id']}.part-00001.jsonl",
    )
    path.replace(segment)
    path.write_text(_record() + "\n", encoding="utf-8")

    old_tail, invalid = ingest_native_records(session, path, now=1003.0)
    assert invalid == 0
    assert len(old_tail) == 1
    assert segment.exists()
    new_head, invalid = ingest_native_records(session, path, now=1004.0)
    assert invalid == 0
    assert len(new_head) == 1
    assert not segment.exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation is privileged")
def test_native_source_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text(_record() + "\n", encoding="utf-8")
    path = tmp_path / "native.jsonl"
    path.symlink_to(target)

    assert ingest_native_records(_session(), path, now=1002.0) == ([], 1)
