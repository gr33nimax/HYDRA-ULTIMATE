"""Readers and sampling buckets for segmented Calls telemetry timelines."""
from __future__ import annotations

import gzip
import json
import os
from collections.abc import Callable, Iterator, Mapping
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


def _sample_analysis_records(
    records: Callable[[], Iterator[dict[str, object]]],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Uniformly sample two passes over one immutable timeline snapshot."""
    limits = {"sample": 100_000, "event": 50_000}
    counts: dict[str, int] = {}
    bucket_counts: dict[str, int] = {}
    for record in records():
        kind = str(record.get("kind", "event"))
        counts[kind] = counts.get(kind, 0) + 1
        bucket = _analysis_bucket(record)
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
    native_buckets = [
        bucket for bucket in bucket_counts if bucket.startswith("native|")
    ]
    native_limit = max(32, 100_000 // max(1, len(native_buckets)))
    strides = {
        bucket: max(1, (count + limit - 1) // limit)
        for bucket, count in bucket_counts.items()
        if (
            limit := (
                native_limit
                if bucket.startswith("native|")
                else limits.get(bucket, count)
            )
        )
    }
    seen: dict[str, int] = {}
    retained: list[dict[str, object]] = []
    for record in records():
        bucket = _analysis_bucket(record)
        seen[bucket] = seen.get(bucket, 0) + 1
        stride = strides.get(bucket, 1)
        if (
            seen[bucket] == 1
            or seen[bucket] == bucket_counts[bucket]
            or (seen[bucket] - 1) % stride == 0
        ):
            if stride > 1:
                record = dict(record)
                record["analysis_stride"] = stride
            retained.append(record)
    return retained, {
        "timeline_records": sum(counts.values()),
        "analyzed_records": len(retained),
        "counts": counts,
        "strides": strides,
    }


__all__ = [
    "_analysis_bucket",
    "_decode_record",
    "_sample_analysis_records",
    "_tail_path",
]
