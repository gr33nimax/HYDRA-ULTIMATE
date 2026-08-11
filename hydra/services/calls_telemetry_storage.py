"""Protected timeline storage for Hydra VK Tunnel telemetry."""
from __future__ import annotations

import io
import json
import os
import re
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping

from hydra.core.host import HostBackend


SESSION_ID_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$")
MARK_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$")


@dataclass
class CallsTelemetryStore:
    host: HostBackend
    state_dir: Path
    data_dir: Path
    clock: Callable[[], float] = time.time
    sleeper: Callable[[float], None] = time.sleep

    @property
    def active_file(self) -> Path:
        return self.state_dir / "active.json"

    @property
    def lock_file(self) -> Path:
        return self.state_dir / "telemetry.lock"

    @contextmanager
    def locked(self) -> Iterator[None]:
        self.host.ensure_directory(self.state_dir, mode=0o700)
        with self.lock_file.open("a+b") as handle:
            self.lock_file.chmod(0o600)
            try:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except ImportError:
                pass
            try:
                yield
            finally:
                try:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except ImportError:
                    pass

    def publish(self, session: Mapping[str, object]) -> None:
        session_id = str(session.get("session_id", ""))
        self.host.ensure_directory(self.state_dir, mode=0o700)
        self.host.ensure_directory(self.data_dir, mode=0o700)
        self.write_session(session)
        self.host.atomic_write(self.timeline_path(session_id), "", mode=0o600)
        self.host.atomic_write(
            self.active_file,
            json.dumps({"session_id": session_id}, separators=(",", ":")),
            mode=0o600,
        )

    def active_session(self, *, required: bool) -> dict[str, object] | None:
        if not self.active_file.exists():
            if required:
                raise ValueError("no Calls telemetry session is available")
            return None
        pointer = self.read_json(self.active_file)
        session_id = str(pointer.get("session_id", ""))
        if not session_id:
            if required:
                raise ValueError("no Calls telemetry session is available")
            return None
        return self.read_session(session_id)

    def read_session(self, session_id: str) -> dict[str, object]:
        return self.read_json(self.session_path(session_id))

    def read_json(self, path: Path) -> dict[str, object]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"cannot read Calls telemetry file {path.name}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"invalid Calls telemetry file {path.name}")
        return payload

    def write_session(self, session: Mapping[str, object]) -> None:
        self.host.atomic_write(
            self.session_path(str(session.get("session_id", ""))),
            json.dumps(session, ensure_ascii=False, separators=(",", ":")),
            mode=0o600,
        )

    def append_record(
        self,
        session: dict[str, object],
        record: Mapping[str, object],
        *,
        counter: str = "",
    ) -> bool:
        session_id = str(session.get("session_id", ""))
        sequence = _integer(session.get("sequence")) + 1
        normalized = {
            "schema": 2,
            "session_id": session_id,
            "sequence": sequence,
            **record,
        }
        payload = (
            json.dumps(normalized, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        path = self.timeline_path(session_id)
        max_bytes = _integer(session.get("max_data_bytes"))
        current_bytes = path.stat().st_size if path.exists() else 0
        if max_bytes and current_bytes + len(payload) > max_bytes:
            now = self.clock()
            session["stopped_at"] = now
            session["stop_reason"] = "storage_limit"
            session["data_bytes"] = current_bytes
            self.write_session(session)
            return False
        descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)
        path.chmod(0o600)
        session["sequence"] = sequence
        session["data_bytes"] = current_bytes + len(payload)
        if counter:
            session[counter] = _integer(session.get(counter)) + 1
        self.write_session(session)
        return True

    def records(self, session_id: str) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        try:
            with self.timeline_path(session_id).open(encoding="utf-8") as handle:
                for line in handle:
                    record = _decode_record(line)
                    if record is not None:
                        records.append(record)
        except OSError:
            pass
        return records

    def analysis_records(
        self,
        session_id: str,
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        """Load a uniform bounded analysis set while retaining the full timeline."""
        limits = {"sample": 100_000, "native": 100_000, "event": 50_000}
        counts: dict[str, int] = {}
        path = self.timeline_path(session_id)
        try:
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    record = _decode_record(line)
                    if record is not None:
                        kind = str(record.get("kind", "event"))
                        counts[kind] = counts.get(kind, 0) + 1
        except OSError:
            return [], {"timeline_records": 0, "analyzed_records": 0, "strides": {}}
        strides = {
            kind: max(1, (count + limits[kind] - 1) // limits[kind])
            for kind, count in counts.items()
            if kind in limits
        }
        seen: dict[str, int] = {}
        retained: list[dict[str, object]] = []
        try:
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    record = _decode_record(line)
                    if record is None:
                        continue
                    kind = str(record.get("kind", "event"))
                    seen[kind] = seen.get(kind, 0) + 1
                    stride = strides.get(kind, 1)
                    if (
                        kind not in limits
                        or seen[kind] == 1
                        or seen[kind] == counts[kind]
                        or (seen[kind] - 1) % stride == 0
                    ):
                        retained.append(record)
        except OSError:
            pass
        return retained, {
            "timeline_records": sum(counts.values()),
            "analyzed_records": len(retained),
            "counts": counts,
            "strides": strides,
        }

    def tail(self, session_id: str, *, limit: int) -> list[dict[str, object]]:
        if limit <= 0:
            return []
        try:
            with self.timeline_path(session_id).open("rb") as handle:
                return _tail_from_handle(handle, limit)
        except OSError:
            return []

    def follow(self, session_id: str, *, limit: int) -> Iterator[dict[str, object]]:
        path = self.timeline_path(session_id)
        with path.open("rb") as handle:
            for record in _tail_from_handle(handle, limit):
                yield record
            handle.seek(0, os.SEEK_END)
            pending = b""
            while True:
                chunk = handle.read()
                if chunk:
                    pending += chunk
                    lines = pending.split(b"\n")
                    pending = lines.pop()
                    for raw in lines:
                        record = _decode_record(raw.decode("utf-8", errors="replace"))
                        if record is not None:
                            yield record
                    continue
                session = self.read_session(session_id)
                if _number(session.get("stopped_at")):
                    if pending:
                        record = _decode_record(
                            pending.decode("utf-8", errors="replace"),
                        )
                        if record is not None:
                            yield record
                    return
                self.sleeper(0.5)

    def export(
        self,
        session: Mapping[str, object],
        report: Mapping[str, object],
        output: str,
    ) -> Path:
        session_id = str(session.get("session_id", ""))
        target = Path(output).expanduser() if output else self.data_dir / f"{session_id}.tar.gz"
        if not str(target).lower().endswith(".tar.gz"):
            raise ValueError("Calls telemetry export must use a .tar.gz file")
        target = target.resolve()
        if not target.parent.exists():
            self.host.ensure_directory(target.parent, mode=0o700)
        manifest = _public_manifest(session)
        schema = (
            "HYDRA Calls telemetry schema 2\n"
            "timeline.jsonl contains sample, event, mark and native records.\n"
            "Tester and native session identifiers are scoped pseudonyms.\n"
            "No join links, credentials, peer addresses or destinations are exported.\n"
        ).encode("utf-8")
        temporary = tempfile.NamedTemporaryFile(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        )
        temp_path = Path(temporary.name)
        temporary.close()
        try:
            with tarfile.open(temp_path, "w:gz") as archive:
                archive.add(self.timeline_path(session_id), arcname="timeline.jsonl")
                _add_bytes(archive, "manifest.json", _json_bytes(manifest))
                _add_bytes(archive, "report.json", _json_bytes(report))
                _add_bytes(archive, "SCHEMA.txt", schema)
            temp_path.chmod(0o600)
            temp_path.replace(target)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
        return target

    def session_path(self, session_id: str) -> Path:
        _validate_session_id(session_id)
        return self.state_dir / f"{session_id}.json"

    def timeline_path(self, session_id: str) -> Path:
        _validate_session_id(session_id)
        return self.data_dir / f"{session_id}.jsonl"


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


def _decode_record(line: str) -> dict[str, object] | None:
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    return record if isinstance(record, dict) else None


def _public_manifest(session: Mapping[str, object]) -> dict[str, object]:
    fields = (
        "schema",
        "session_id",
        "started_at",
        "stopped_at",
        "stop_reason",
        "sample_interval_seconds",
        "tester_ids",
        "metadata",
        "max_data_bytes",
        "data_bytes",
        "sample_count",
        "event_count",
        "native_record_count",
        "mark_count",
    )
    return {field: session.get(field) for field in fields if field in session}


def _json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"


def _add_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o600
    info.mtime = 0
    archive.addfile(info, io.BytesIO(payload))


def _validate_session_id(session_id: str) -> None:
    if not SESSION_ID_PATTERN.fullmatch(session_id):
        raise ValueError("invalid Calls telemetry session id")


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


__all__ = [
    "CallsTelemetryStore",
    "MARK_LABEL_PATTERN",
    "SESSION_ID_PATTERN",
]
