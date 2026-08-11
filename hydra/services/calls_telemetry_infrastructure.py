"""Protected runtime for operator-controlled Hydra VK Tunnel telemetry."""
from __future__ import annotations

import math
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Mapping, Sequence

from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.services.calls_telemetry_connections import (
    connection_sample,
    identity_hash,
    update_calls_connections,
)
from hydra.services.calls_telemetry_host import (
    collect_environment,
    collect_host_metrics,
    collect_kernel_metrics,
    collect_runtime_metrics,
    collect_udp_metrics,
    system_clock_ticks,
    system_page_size,
)
from hydra.services.calls_telemetry_journal import collect_calls_journal_events
from hydra.services.calls_telemetry_native import (
    NATIVE_TELEMETRY_PATH,
    ingest_native_records,
    native_sample,
)
from hydra.services.calls_telemetry_projection import (
    report_projection as _report_projection,
    storage_projection as _storage_projection,
)
from hydra.services.calls_telemetry_report import build_calls_telemetry_report
from hydra.services.calls_telemetry_storage import (
    MARK_LABEL_PATTERN,
    CallsTelemetryStore,
)
from hydra.services.system_monitoring import SystemMonitoring


CALLS_TELEMETRY_STATE_DIR = Path(
    os.environ.get(
        "HYDRA_CALLS_TELEMETRY_STATE_DIR",
        "/var/lib/hydra/calls/vk/telemetry",
    ),
)
CALLS_TELEMETRY_DATA_DIR = Path(
    os.environ.get(
        "HYDRA_CALLS_TELEMETRY_DATA_DIR",
        "/var/log/hydra/calls-telemetry",
    ),
)


@dataclass
class CallsTelemetryInfrastructure:
    """Own one anonymized timeline until the operator explicitly stops it."""

    host: HostBackend
    monitoring: SystemMonitoring
    state_dir: Path = CALLS_TELEMETRY_STATE_DIR
    data_dir: Path = CALLS_TELEMETRY_DATA_DIR
    proc_root: Path = Path("/proc")
    sys_root: Path = Path("/sys")
    native_path: Path = NATIVE_TELEMETRY_PATH
    clock: Callable[[], float] = time.time
    sleeper: Callable[[float], None] = time.sleep
    token_hex: Callable[[int], str] = secrets.token_hex
    clock_ticks_per_second: int = field(default_factory=system_clock_ticks)
    page_size: int = field(default_factory=system_page_size)

    @property
    def store(self) -> CallsTelemetryStore:
        return CallsTelemetryStore(
            self.host,
            self.state_dir,
            self.data_dir,
            self.clock,
            self.sleeper,
        )

    @property
    def active_file(self) -> Path:
        return self.store.active_file

    @property
    def lock_file(self) -> Path:
        return self.store.lock_file

    def start(
        self,
        tester_emails: Sequence[str],
        *,
        sample_interval_seconds: int,
        max_data_bytes: int,
        metadata: dict[str, object],
    ) -> dict[str, object]:
        store = self.store
        with store.locked():
            current = store.active_session(required=False)
            now = self.clock()
            if current is not None and self._is_active(current, now):
                raise RuntimeError(
                    f"Calls telemetry session {current['session_id']} is already active",
                )
            session_id = (
                datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
                + self.token_hex(4)
            )
            salt = self.token_hex(16)
            tester_ids = [f"tester-{index}" for index in range(1, len(tester_emails) + 1)]
            tester_hashes = {
                identity_hash(salt, email): tester_id
                for email, tester_id in zip(tester_emails, tester_ids)
            }
            safe_metadata = dict(metadata)
            safe_metadata["environment"] = collect_environment(
                self.host,
                self.proc_root,
                self.sys_root,
            )
            session: dict[str, object] = {
                "schema": 2,
                "session_id": session_id,
                "started_at": now,
                "stopped_at": 0.0,
                "sample_interval_seconds": sample_interval_seconds,
                "max_data_bytes": max_data_bytes,
                "data_bytes": 0,
                "raw_data_bytes": 0,
                "compressed_bytes": 0,
                "timeline_segments": 0,
                "tester_ids": tester_ids,
                "tester_hashes": tester_hashes,
                "salt": salt,
                "metadata": safe_metadata,
                "sequence": 0,
                "sample_count": 0,
                "event_count": 0,
                "native_record_count": 0,
                "native_invalid_count": 0,
                "mark_count": 0,
                "last_sample_at": now,
                "last_poll_at": 0.0,
                "last_journal_at": 0.0,
                "journal_cursor": "",
                "baseline_complete": False,
                "connection_cursors": {},
                "connection_interval": {},
                "cumulative": {
                    "upload_bytes": 0,
                    "download_bytes": 0,
                    "testers": {tester_id: {} for tester_id in tester_ids},
                },
                "live": {},
                "events": {},
            }
            store.publish(session)
            store.append_record(
                session,
                {"kind": "event", "timestamp": now, "source": "operator", "code": "session_started"},
                counter="event_count",
            )
            return self._public_status(session, now=now) | {
                "ok": True,
                "timeline_path": str(store.timeline_path(session_id)),
            }

    def status(self) -> dict[str, object]:
        store = self.store
        with store.locked():
            session = store.active_session(required=False)
            if session is None:
                return {"ok": True, "active": False, "session_id": "", "samples": 0}
            now = self.clock()
            status = {"ok": True} | self._public_status(session, now=now)
            recent = (
                store.tail(str(session["session_id"]), limit=5000)
                if _integer(session.get("native_record_count"))
                else []
            )
        if recent:
            status |= _report_projection(
                build_calls_telemetry_report(session, recent, now=now),
                recent_records=len(recent),
            )
        return status

    def report(self, session_id: str = "") -> dict[str, object]:
        store = self.store
        session = store.read_session(session_id) if session_id else store.active_session(required=True)
        records, analysis_input = store.analysis_records(str(session["session_id"]))
        report = build_calls_telemetry_report(session, records, now=self.clock())
        report |= _storage_projection(session)
        report["analysis_input"] = analysis_input
        report["timeline_path"] = str(store.timeline_path(str(session["session_id"])))
        return report

    def tail(self, session_id: str = "", *, limit: int = 50) -> dict[str, object]:
        store = self.store
        session = store.read_session(session_id) if session_id else store.active_session(required=True)
        records = store.tail(str(session["session_id"]), limit=limit)
        return {
            "ok": True,
            **self._public_status(session, now=self.clock()),
            "records": records,
        }

    def follow(
        self,
        session_id: str = "",
        *,
        limit: int = 20,
    ) -> Iterator[dict[str, object]]:
        store = self.store
        session = store.read_session(session_id) if session_id else store.active_session(required=True)
        return store.follow(str(session["session_id"]), limit=limit)

    def mark(self, label: str) -> dict[str, object]:
        normalized = str(label).strip()
        if not MARK_LABEL_PATTERN.fullmatch(normalized):
            raise ValueError("telemetry mark must be a 1..48 character ASCII slug")
        store = self.store
        with store.locked():
            session = store.active_session(required=True)
            now = self.clock()
            if not self._is_active(session, now):
                raise ValueError("Calls telemetry session is not active")
            stored = store.append_record(
                session,
                {"kind": "mark", "timestamp": now, "label": normalized},
                counter="mark_count",
            )
            return {"ok": stored, "label": normalized} | self._public_status(
                session,
                now=now,
            )

    def export(self, session_id: str = "", output: str = "") -> dict[str, object]:
        store = self.store
        with store.locked():
            session = store.read_session(session_id) if session_id else store.active_session(required=True)
        records, analysis_input = store.analysis_records(str(session["session_id"]))
        report = build_calls_telemetry_report(session, records, now=self.clock())
        report |= _storage_projection(session)
        report["analysis_input"] = analysis_input
        target = store.export(session, report, output)
        return {
            "ok": True,
            "session_id": str(session["session_id"]),
            "active": self._is_active(session, self.clock()),
            "output": str(target),
            "bytes": target.stat().st_size,
        }

    def stop(self) -> dict[str, object]:
        store = self.store
        with store.locked():
            session = store.active_session(required=False)
            if session is None:
                return {"ok": True, "active": False, "stopped": False, "session_id": ""}
            now = self.clock()
            stopped = self._is_active(session, now)
            if stopped:
                store.append_record(
                    session,
                    {"kind": "event", "timestamp": now, "source": "operator", "code": "session_stopped"},
                    counter="event_count",
                )
                session["stopped_at"] = now
                session["stop_reason"] = "operator"
                store.write_session(session)
            result = {"ok": True, "stopped": stopped} | self._public_status(
                session,
                now=now,
            )
        records, analysis_input = store.analysis_records(str(session["session_id"]))
        report = build_calls_telemetry_report(session, records, now=now)
        result |= _report_projection(report, recent_records=len(records))
        result["analysis_input"] = analysis_input
        return result

    def record(self, state: AppState) -> bool:
        """Update high-frequency cursors and periodically append a full sample."""
        if not self.active_file.exists():
            return False
        store = self.store
        with store.locked():
            session = store.active_session(required=False)
            now = self.clock()
            if session is None or not self._is_active(session, now):
                return False
            update_calls_connections(session, state, now=now)
            session["last_poll_at"] = now
            self._ingest_native(store, session, now=now)
            if not self._is_active(session, now):
                return False
            self._ingest_journal(store, session, now=now)
            if not self._is_active(session, now):
                return False
            last_sample_at = _number(session.get("last_sample_at"))
            interval = max(1, _integer(session.get("sample_interval_seconds")))
            if now - last_sample_at < interval:
                store.write_session(session)
                return False
            calls = state.protocols.get("calls")
            listen_port = _integer(calls.config.get("listen_port", 0)) if calls else 0
            sample = {
                "kind": "sample",
                "timestamp": now,
                "calls": connection_sample(session),
                "host": collect_host_metrics(self.monitoring),
                "runtime": collect_runtime_metrics(
                    self.host,
                    self.proc_root,
                    page_size=self.page_size,
                    clock_ticks_per_second=self.clock_ticks_per_second,
                ),
                "udp": collect_udp_metrics(self.proc_root, listen_port),
                "kernel": collect_kernel_metrics(self.proc_root, self.data_dir),
                "native": native_sample(session),
            }
            stored = store.append_record(session, sample, counter="sample_count")
            if stored:
                session["last_sample_at"] = now
                store.write_session(session)
            return stored

    def record_event(self, code: str) -> bool:
        if not MARK_LABEL_PATTERN.fullmatch(code) or not self.active_file.exists():
            return False
        store = self.store
        with store.locked():
            session = store.active_session(required=False)
            now = self.clock()
            if session is None or not self._is_active(session, now):
                return False
            self._count_event(session, code)
            return store.append_record(
                session,
                {"kind": "event", "timestamp": now, "source": "traffic_daemon", "code": code},
                counter="event_count",
            )

    def _ingest_native(
        self,
        store: CallsTelemetryStore,
        session: dict[str, object],
        *,
        now: float,
    ) -> None:
        records, invalid = ingest_native_records(session, self.native_path, now=now)
        if invalid:
            session["native_invalid_count"] = _integer(
                session.get("native_invalid_count"),
            ) + invalid
            self._count_event(session, "native_record_invalid", invalid)
        for record in records:
            if not store.append_record(
                session,
                record,
                counter="native_record_count",
            ):
                break

    def _ingest_journal(
        self,
        store: CallsTelemetryStore,
        session: dict[str, object],
        *,
        now: float,
    ) -> None:
        if now - _number(session.get("last_journal_at")) < 5:
            return
        events, cursor, failed = collect_calls_journal_events(
            self.host,
            cursor=str(session.get("journal_cursor", "")),
            started_at=_number(session.get("started_at")),
        )
        session["last_journal_at"] = now
        session["journal_cursor"] = cursor
        if failed:
            self._count_event(session, "journal_unavailable")
            return
        for event in events:
            code = str(event.get("code", ""))
            self._count_event(session, code)
            if not store.append_record(session, event, counter="event_count"):
                break

    @staticmethod
    def _count_event(session: dict[str, object], code: str, amount: int = 1) -> None:
        events = session.setdefault("events", {})
        if not isinstance(events, dict):
            raise RuntimeError("invalid Calls telemetry event state")
        events[code] = _integer(events.get(code)) + max(1, amount)

    @staticmethod
    def _is_active(session: Mapping[str, object], now: float) -> bool:
        del now
        return not bool(_number(session.get("stopped_at")))

    def _public_status(self, session: Mapping[str, object], *, now: float) -> dict[str, object]:
        started_at = _number(session.get("started_at"))
        stopped_at = _number(session.get("stopped_at"))
        interval = max(1, _integer(session.get("sample_interval_seconds")))
        observed_until = stopped_at or now
        expected = max(0, math.floor(max(0.0, observed_until - started_at) / interval))
        samples = _integer(session.get("sample_count"))
        data_bytes = _integer(session.get("data_bytes"))
        raw_data_bytes = _integer(session.get("raw_data_bytes")) or data_bytes
        max_bytes = _integer(session.get("max_data_bytes"))
        return {
            "session_id": str(session.get("session_id", "")),
            "active": self._is_active(session, now),
            "started_at": started_at,
            "elapsed_seconds": max(0.0, observed_until - started_at),
            "stopped_at": stopped_at or None,
            "stop_reason": str(session.get("stop_reason", "")),
            "sample_interval_seconds": interval,
            "tester_ids": list(session.get("tester_ids", [])),
            "samples": samples,
            "expected_samples": expected,
            "coverage_ratio": round(min(1.0, samples / expected), 4) if expected else 0.0,
            "events": _integer(session.get("event_count")),
            "marks": _integer(session.get("mark_count")),
            "native_records": _integer(session.get("native_record_count")),
            "native_available": bool(session.get("native_record_count")),
            "data_bytes": data_bytes,
            "raw_data_bytes": raw_data_bytes,
            "compression_ratio": round(data_bytes / raw_data_bytes, 6) if raw_data_bytes else 1.0,
            "timeline_segments": _integer(session.get("timeline_segments")),
            "max_data_bytes": max_bytes,
            "storage_ratio": round(data_bytes / max_bytes, 6) if max_bytes else 0.0,
        }

    # Compatibility helpers retained for focused tests and external diagnostics.
    def _session_path(self, session_id: str) -> Path:
        return self.store.session_path(session_id)

    def _samples_path(self, session_id: str) -> Path:
        return self.store.timeline_path(session_id)

    def _read_samples(self, session_id: str) -> list[dict[str, object]]:
        return [
            record
            for record in self.store.records(session_id)
            if record.get("kind", "sample") == "sample"
        ]


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


__all__ = [
    "CALLS_TELEMETRY_DATA_DIR",
    "CALLS_TELEMETRY_STATE_DIR",
    "CallsTelemetryInfrastructure",
]
