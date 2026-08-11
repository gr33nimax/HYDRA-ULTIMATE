"""Safe ingestion contract for instrumented Hydracore Calls metrics."""
from __future__ import annotations

import json
import math
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path

from hydra.services.calls_telemetry_connections import identity_hash


NATIVE_TELEMETRY_PATH = Path(
    os.environ.get(
        "HYDRA_CALLS_NATIVE_TELEMETRY_FILE",
        "/run/hydra/calls-telemetry.jsonl",
    ),
)
_SLUG = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_METRIC = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_METRIC_PREFIXES = (
    "auth_",
    "client_",
    "dtls_",
    "goodput_",
    "handshake_",
    "inner_",
    "kcp_",
    "network_",
    "outer_",
    "packet_",
    "peer_",
    "queue_",
    "relay_",
    "runtime_",
    "server_",
    "session_",
    "turn_",
    "vk_",
    "wire_",
    "worker_",
)
_MAX_NATIVE_LINE_BYTES = 64 * 1024
_MAX_RECORDS_PER_POLL = 1024


def ingest_native_records(
    session: dict[str, object],
    path: Path,
    *,
    now: float,
) -> tuple[list[dict[str, object]], int]:
    """Read new core records, rejecting secrets and unbounded structures."""
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        file_stat = os.fstat(descriptor)
    except OSError:
        return ([], 1) if path.is_symlink() else ([], 0)
    try:
        if not stat.S_ISREG(file_stat.st_mode) or path.is_symlink():
            return [], 1
        cursor = session.get("native_cursor")
        cursor_map = cursor if isinstance(cursor, dict) else {}
        inode = int(getattr(file_stat, "st_ino", 0))
        offset = _integer(cursor_map.get("offset"))
        if _integer(cursor_map.get("inode")) != inode or file_stat.st_size < offset:
            offset = 0
        records: list[dict[str, object]] = []
        invalid = 0
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            handle.seek(offset)
            for _ in range(_MAX_RECORDS_PER_POLL):
                line_start = handle.tell()
                raw = handle.readline(_MAX_NATIVE_LINE_BYTES + 1)
                if not raw:
                    break
                if len(raw) > _MAX_NATIVE_LINE_BYTES:
                    invalid += 1
                    if not raw.endswith(b"\n"):
                        handle.readline()
                    continue
                if not raw.endswith(b"\n"):
                    handle.seek(line_start)
                    break
                record = _normalize_native_record(session, raw, now=now)
                if record is None:
                    invalid += 1
                else:
                    records.append(record)
                    _remember_latest(session, record)
            session["native_cursor"] = {"inode": inode, "offset": handle.tell()}
    except OSError:
        return [], invalid + 1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if records:
        session["native_first_at"] = session.get("native_first_at") or records[0][
            "timestamp"
        ]
        session["native_last_at"] = records[-1]["timestamp"]
    return records, invalid


def native_sample(session: Mapping[str, object]) -> dict[str, object]:
    latest = session.get("native_latest")
    return {
        "available": bool(session.get("native_record_count")),
        "records": _integer(session.get("native_record_count")),
        "invalid_records": _integer(session.get("native_invalid_count")),
        "first_at": _number(session.get("native_first_at")) or None,
        "last_at": _number(session.get("native_last_at")) or None,
        "latest": latest if isinstance(latest, Mapping) else {},
    }


def _normalize_native_record(
    session: Mapping[str, object],
    raw: bytes,
    *,
    now: float,
) -> dict[str, object] | None:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping) or payload.get("schema") != 1:
        return None
    scope = str(payload.get("scope", ""))
    kind = str(payload.get("kind", ""))
    if scope not in {"server", "client"} or kind not in {"snapshot", "event"}:
        return None
    metrics = payload.get("metrics")
    if not isinstance(metrics, Mapping) or len(metrics) > 128:
        return None
    safe_metrics: dict[str, int | float | bool] = {}
    for raw_name, raw_value in metrics.items():
        name = str(raw_name)
        if not _METRIC.fullmatch(name) or not name.startswith(_METRIC_PREFIXES):
            return None
        value = _safe_scalar(raw_value)
        if value is None:
            return None
        safe_metrics[name] = value
    event = str(payload.get("event", ""))
    stage = str(payload.get("stage", ""))
    reason = str(payload.get("reason", ""))
    for value in (event, stage, reason):
        if value and not _SLUG.fullmatch(value):
            return None
    timestamp = _number(payload.get("timestamp"))
    started_at = _number(session.get("started_at"))
    if not started_at - 300 <= timestamp <= now + 300:
        timestamp = now
    tester_id = _tester_id(session, str(payload.get("user", "")))
    native_session = str(payload.get("session_id", ""))
    native_session_id = (
        "native-" + identity_hash(str(session.get("salt", "")), native_session)[:12]
        if native_session
        else ""
    )
    worker_id = payload.get("worker_id")
    if worker_id is not None and (
        type(worker_id) is not int or not 0 <= worker_id <= 65535
    ):
        return None
    return {
        "kind": "native",
        "timestamp": timestamp,
        "native_scope": scope,
        "native_kind": kind,
        "event": event,
        "stage": stage,
        "reason": reason,
        "tester_id": tester_id,
        "native_session_id": native_session_id,
        "worker_id": worker_id,
        "metrics": safe_metrics,
    }


def _remember_latest(session: dict[str, object], record: Mapping[str, object]) -> None:
    if record.get("native_kind") != "snapshot":
        return
    latest = session.setdefault("native_latest", {})
    if not isinstance(latest, dict):
        raise RuntimeError("invalid native telemetry state")
    scope = str(record.get("native_scope", ""))
    metrics = dict(record.get("metrics", {}))
    if scope == "server":
        latest["server"] = metrics
        return
    clients = latest.setdefault("clients", {})
    if not isinstance(clients, dict):
        raise RuntimeError("invalid native client telemetry state")
    tester_id = str(record.get("tester_id", "")) or "unattributed"
    clients[tester_id] = metrics


def _tester_id(session: Mapping[str, object], user: str) -> str:
    if not user:
        return ""
    hashes = session.get("tester_hashes", {})
    if not isinstance(hashes, Mapping):
        return ""
    return str(
        hashes.get(identity_hash(str(session.get("salt", "")), user), ""),
    )


def _safe_scalar(value: object) -> int | float | bool | None:
    if type(value) is bool:
        return value
    if type(value) is int:
        return value if 0 <= value <= 2**63 - 1 else None
    if type(value) is float and math.isfinite(value) and 0 <= value <= 1e18:
        return value
    return None


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


__all__ = ["NATIVE_TELEMETRY_PATH", "ingest_native_records", "native_sample"]
