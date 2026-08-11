"""Readers and sampling buckets for segmented Calls telemetry timelines."""
from __future__ import annotations

import gzip
import json
import os
from collections.abc import Mapping
from pathlib import Path

from hydra.services.calls_telemetry_analysis_common import _integer

def _tail_from_handle(handle, limit: int) -> list[dict[str, object]]:
    handle.seek(0, os.SEEK_END)
    position = handle.tell()
    data = b""
    while position > 0 and data.count(b"\n") <= limit:
        size = min(65536, position)
        position -= size
        handle.seek(position)
        data = handle.read(size) + data
    lines = data.splitlines()[-limit:]
    records = [_decode_record(line.decode("utf-8", errors="replace")) for line in lines]
    return [record for record in records if record is not None]


def _tail_path(path: Path, limit: int) -> list[dict[str, object]]:
    if path.suffix != ".gz":
        with path.open("rb") as handle:
            return _tail_from_handle(handle, limit)
    records: list[dict[str, object]] = []
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            record = _decode_record(line)
            if record is not None:
                records.append(record)
                if len(records) > limit:
                    del records[: len(records) - limit]
    return records


def _decode_record(line: str) -> dict[str, object] | None:
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    return record if isinstance(record, dict) else None


def _analysis_bucket(record: Mapping[str, object]) -> str:
    kind = str(record.get("kind", "event"))
    if kind != "native":
        return kind
    entity = str(record.get("native_entity", ""))
    if not entity:
        scope = str(record.get("native_scope", ""))
        worker = record.get("worker_id")
        if scope == "server":
            entity = (
                "server_worker"
                if worker is not None
                else "server_session"
                if record.get("tester_id")
                else "server_process"
            )
        elif scope == "client":
            entity = "client_worker" if worker is not None else "client_session"
        else:
            entity = "unknown"
    return "|".join((
        "native",
        entity,
        str(record.get("tester_id", "")),
        str(record.get("native_session_id", "")),
        str(record.get("worker_id", "")),
        str(record.get("native_kind", "")),
    ))


__all__ = ["_analysis_bucket", "_decode_record", "_tail_path"]
