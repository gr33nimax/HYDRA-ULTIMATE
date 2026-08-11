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


def test_oversized_native_line_does_not_consume_the_next_record(tmp_path: Path) -> None:
    path = tmp_path / "native.jsonl"
    path.write_bytes(b"x" * (64 * 1024 + 1) + b"\n" + _record().encode() + b"\n")

    records, invalid = ingest_native_records(_session(), path, now=1002.0)

    assert invalid == 1
    assert len(records) == 1


@pytest.mark.skipif(os.name == "nt", reason="Windows symlink creation is privileged")
def test_native_source_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text(_record() + "\n", encoding="utf-8")
    path = tmp_path / "native.jsonl"
    path.symlink_to(target)

    assert ingest_native_records(_session(), path, now=1002.0) == ([], 1)
