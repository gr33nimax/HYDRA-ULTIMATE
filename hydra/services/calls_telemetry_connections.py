"""Anonymized Calls connection lifecycle and goodput observations."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping

from hydra.core.state_models import AppState


def update_calls_connections(
    session: dict[str, object],
    state: AppState,
    *,
    now: float,
) -> None:
    raw_records = state.install.get("traffic_connection_counters", {})
    records = raw_records if isinstance(raw_records, Mapping) else {}
    cursors = _dict(session.setdefault("connection_cursors", {}))
    cumulative = _dict(session.setdefault("cumulative", {}))
    interval = _dict(session.setdefault("connection_interval", {}))
    tester_totals = _dict(cumulative.setdefault("testers", {}))
    tester_ids = [str(value) for value in session.get("tester_ids", [])]
    active_by_tester = {tester_id: 0 for tester_id in tester_ids}
    no_progress = {"5s": 0, "15s": 0, "30s": 0}
    present: set[str] = set()
    baseline_complete = bool(session.get("baseline_complete"))
    active_connections = 0
    attributed_connections = 0
    tester_attributed_connections = 0

    for connection_id, raw_record in records.items():
        record = raw_record if isinstance(raw_record, Mapping) else {}
        if str(record.get("protocol", "")) != "calls":
            continue
        cursor_id = identity_hash(str(session.get("salt", "")), str(connection_id))
        present.add(cursor_id)
        upload = _integer(record.get("upload"))
        download = _integer(record.get("download"))
        active = _integer(record.get("missed_polls")) == 0
        previous = cursors.get(cursor_id)
        previous_map = previous if isinstance(previous, dict) else None
        tester_id = _tester_id(session, str(record.get("user", "")))
        if previous_map is None:
            previous_map = {
                "upload": upload,
                "download": download,
                "first_seen_at": now,
                "last_progress_at": now,
                "active": active,
                "tester_id": tester_id,
                "observed_bytes": 0,
            }
            cursors[cursor_id] = previous_map
            if baseline_complete and active:
                _increment(cumulative, "connections_opened")
                _increment(interval, "connections_opened")
                _increment_tester(tester_totals, tester_id, "connections_opened")

        upload_delta, upload_reset = _counter_delta(upload, previous_map.get("upload"))
        download_delta, download_reset = _counter_delta(
            download,
            previous_map.get("download"),
        )
        if not baseline_complete:
            upload_delta = 0
            download_delta = 0
        if upload_reset or download_reset:
            _increment(cumulative, "counter_resets")
            _increment(interval, "counter_resets")
            _increment_tester(tester_totals, tester_id, "counter_resets")
        _add_bytes(
            cumulative,
            interval,
            tester_totals,
            tester_id,
            bool(record.get("user")),
            upload_delta,
            download_delta,
        )

        progress = upload_delta + download_delta
        previous_map["observed_bytes"] = _integer(previous_map.get("observed_bytes")) + progress
        if progress:
            previous_map["last_progress_at"] = now
        was_active = bool(previous_map.get("active"))
        if baseline_complete and active and not was_active:
            previous_map["first_seen_at"] = now
            previous_map["last_progress_at"] = now
            previous_map["observed_bytes"] = progress
            _increment(cumulative, "connections_opened")
            _increment(interval, "connections_opened")
            _increment_tester(tester_totals, tester_id, "connections_opened")
        elif baseline_complete and not active and was_active:
            _record_close(cumulative, interval, tester_totals, previous_map, now)

        previous_map.update({
            "upload": upload,
            "download": download,
            "active": active,
            "tester_id": tester_id,
            "last_seen_at": now,
        })
        if active:
            active_connections += 1
            if record.get("user"):
                attributed_connections += 1
            if tester_id:
                active_by_tester[tester_id] += 1
                tester_attributed_connections += 1
            silent_for = max(0.0, now - _number(previous_map.get("last_progress_at")))
            for label, threshold in (("5s", 5), ("15s", 15), ("30s", 30)):
                if silent_for >= threshold:
                    no_progress[label] += 1

    for cursor_id in set(cursors) - present:
        previous = cursors.pop(cursor_id, None)
        if baseline_complete and isinstance(previous, dict) and previous.get("active"):
            _record_close(cumulative, interval, tester_totals, previous, now)
    session["baseline_complete"] = True
    session["live"] = {
        "active_connections": active_connections,
        "attributed_connections": attributed_connections,
        "tester_attributed_connections": tester_attributed_connections,
        "other_user_connections": attributed_connections - tester_attributed_connections,
        "unattributed_connections": active_connections - attributed_connections,
        "active_by_tester": active_by_tester,
        "no_progress": no_progress,
    }


def connection_sample(session: dict[str, object]) -> dict[str, object]:
    cumulative = _mapping(session.get("cumulative"))
    interval = _mapping(session.get("connection_interval"))
    tester_totals = _mapping(cumulative.get("testers"))
    live = _mapping(session.get("live"))
    active_by_tester = _mapping(live.get("active_by_tester"))
    testers: dict[str, object] = {}
    for tester_id in (str(value) for value in session.get("tester_ids", [])):
        totals = _mapping(tester_totals.get(tester_id))
        testers[tester_id] = {
            "upload_bytes": _integer(totals.get("upload_bytes")),
            "download_bytes": _integer(totals.get("download_bytes")),
            "active_connections": _integer(active_by_tester.get(tester_id)),
            "connections_opened": _integer(totals.get("connections_opened")),
            "connections_closed": _integer(totals.get("connections_closed")),
            "zero_byte_connections": _integer(totals.get("zero_byte_connections")),
            "short_connections": _integer(totals.get("short_connections")),
            "counter_resets": _integer(totals.get("counter_resets")),
        }
    result = {
        "upload_bytes": _integer(cumulative.get("upload_bytes")),
        "download_bytes": _integer(cumulative.get("download_bytes")),
        "active_connections": _integer(live.get("active_connections")),
        "attributed_connections": _integer(live.get("attributed_connections")),
        "tester_attributed_connections": _integer(
            live.get("tester_attributed_connections"),
        ),
        "other_user_connections": _integer(live.get("other_user_connections")),
        "unattributed_connections": _integer(live.get("unattributed_connections")),
        "other_user_upload_bytes": _integer(cumulative.get("other_user_upload_bytes")),
        "other_user_download_bytes": _integer(
            cumulative.get("other_user_download_bytes"),
        ),
        "unattributed_upload_bytes": _integer(
            cumulative.get("unattributed_upload_bytes"),
        ),
        "unattributed_download_bytes": _integer(
            cumulative.get("unattributed_download_bytes"),
        ),
        "connections_opened": _integer(cumulative.get("connections_opened")),
        "connections_closed": _integer(cumulative.get("connections_closed")),
        "zero_byte_connections": _integer(cumulative.get("zero_byte_connections")),
        "short_connections": _integer(cumulative.get("short_connections")),
        "counter_resets": _integer(cumulative.get("counter_resets")),
        "connection_lifetime_seconds_sum": _number(
            cumulative.get("connection_lifetime_seconds_sum"),
        ),
        "connection_lifetime_seconds_max": _number(
            cumulative.get("connection_lifetime_seconds_max"),
        ),
        "no_progress": dict(_mapping(live.get("no_progress"))),
        "interval": {
            key: _integer(interval.get(key))
            for key in (
                "upload_bytes",
                "download_bytes",
                "connections_opened",
                "connections_closed",
                "counter_resets",
            )
        },
        "testers": testers,
    }
    session["connection_interval"] = {}
    return result


def identity_hash(salt: str, value: str) -> str:
    return hashlib.sha256(f"{salt}\0{value.casefold()}".encode()).hexdigest()


def _tester_id(session: Mapping[str, object], email: str) -> str:
    if not email:
        return ""
    hashes = session.get("tester_hashes", {})
    if not isinstance(hashes, Mapping):
        return ""
    return str(hashes.get(identity_hash(str(session.get("salt", "")), email), ""))


def _add_bytes(
    cumulative: dict,
    interval: dict,
    tester_totals: dict,
    tester_id: str,
    has_user: bool,
    upload: int,
    download: int,
) -> None:
    for target in (cumulative, interval):
        target["upload_bytes"] = _integer(target.get("upload_bytes")) + upload
        target["download_bytes"] = _integer(target.get("download_bytes")) + download
    if tester_id:
        totals = _dict(tester_totals.setdefault(tester_id, {}))
        totals["upload_bytes"] = _integer(totals.get("upload_bytes")) + upload
        totals["download_bytes"] = _integer(totals.get("download_bytes")) + download
    else:
        prefix = "other_user" if has_user else "unattributed"
        for target in (cumulative, interval):
            target[f"{prefix}_upload_bytes"] = (
                _integer(target.get(f"{prefix}_upload_bytes")) + upload
            )
            target[f"{prefix}_download_bytes"] = (
                _integer(target.get(f"{prefix}_download_bytes")) + download
            )


def _record_close(
    cumulative: dict,
    interval: dict,
    tester_totals: dict,
    cursor: Mapping[str, object],
    now: float,
) -> None:
    tester_id = str(cursor.get("tester_id", ""))
    duration = max(0.0, now - _number(cursor.get("first_seen_at")))
    observed_bytes = _integer(cursor.get("observed_bytes"))
    _increment(cumulative, "connections_closed")
    _increment(interval, "connections_closed")
    _increment_tester(tester_totals, tester_id, "connections_closed")
    cumulative["connection_lifetime_seconds_sum"] = (
        _number(cumulative.get("connection_lifetime_seconds_sum")) + duration
    )
    cumulative["connection_lifetime_seconds_max"] = max(
        _number(cumulative.get("connection_lifetime_seconds_max")),
        duration,
    )
    if observed_bytes == 0:
        _increment(cumulative, "zero_byte_connections")
        _increment_tester(tester_totals, tester_id, "zero_byte_connections")
    if duration < 5:
        _increment(cumulative, "short_connections")
        _increment_tester(tester_totals, tester_id, "short_connections")


def _increment(target: dict, key: str) -> None:
    target[key] = _integer(target.get(key)) + 1


def _increment_tester(tester_totals: dict, tester_id: str, key: str) -> None:
    if tester_id:
        _increment(_dict(tester_totals.setdefault(tester_id, {})), key)


def _counter_delta(current: int, previous: object) -> tuple[int, bool]:
    if previous is None:
        return current, False
    old = _integer(previous)
    return (current - old, False) if current >= old else (current, True)


def _dict(value: object) -> dict:
    if not isinstance(value, dict):
        raise RuntimeError("invalid mutable Calls telemetry state")
    return value


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _integer(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _number(value: object) -> float:
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return 0.0


__all__ = ["connection_sample", "identity_hash", "update_calls_connections"]
