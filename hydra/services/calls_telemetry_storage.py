"""Protected timeline storage for Hydra VK Tunnel telemetry."""
from __future__ import annotations

import gzip
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping

from hydra.core.host import HostBackend
from hydra.services.calls_telemetry_storage_readers import (
    _analysis_bucket,
    _decode_record,
    _tail_path,
)


SESSION_ID_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$")
MARK_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$")
DEFAULT_TIMELINE_SEGMENT_BYTES = 8 * 1024 * 1024


@dataclass
class CallsTelemetryStore:
    host: HostBackend
    state_dir: Path
    data_dir: Path
    clock: Callable[[], float] = time.time
    sleeper: Callable[[float], None] = time.sleep
    segment_bytes: int = DEFAULT_TIMELINE_SEGMENT_BYTES

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
        self._rotate_timeline_if_needed(session, len(payload))
        max_bytes = _integer(session.get("max_data_bytes"))
        current_bytes = path.stat().st_size if path.exists() else 0
        compressed_bytes = _integer(session.get("compressed_bytes"))
        storage_bytes = compressed_bytes + current_bytes
        if max_bytes and storage_bytes + len(payload) > max_bytes:
            now = self.clock()
            session["stopped_at"] = now
            session["stop_reason"] = "storage_limit"
            session["data_bytes"] = storage_bytes
            self.write_session(session)
            return False
        descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)
        path.chmod(0o600)
        session["sequence"] = sequence
        session["raw_data_bytes"] = _integer(
            session.get("raw_data_bytes"),
        ) + len(payload)
        session["data_bytes"] = compressed_bytes + current_bytes + len(payload)
        if counter:
            session[counter] = _integer(session.get(counter)) + 1
        self.write_session(session)
        return True

    def _rotate_timeline_if_needed(
        self,
        session: dict[str, object],
        incoming_bytes: int,
    ) -> None:
        session_id = str(session.get("session_id", ""))
        current = self.timeline_path(session_id)
        current_size = current.stat().st_size if current.exists() else 0
        threshold = max(1024, int(self.segment_bytes))
        if current_size == 0 or current_size + incoming_bytes <= threshold:
            return
        index = self._next_segment_index(session_id)
        target = self.segment_path(session_id, index)
        temporary = tempfile.NamedTemporaryFile(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=self.data_dir,
            delete=False,
        )
        temp_path = Path(temporary.name)
        try:
            with current.open("rb") as source, temporary:
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    fileobj=temporary,
                    compresslevel=6,
                    mtime=0,
                ) as compressed:
                    shutil.copyfileobj(source, compressed, length=1024 * 1024)
            temp_path.chmod(0o600)
            temp_path.replace(target)
            self.host.atomic_write(current, "", mode=0o600)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
        session["timeline_segments"] = index
        compressed_bytes = sum(
            path.stat().st_size for path in self.segment_paths(session_id)
        )
        session["compressed_bytes"] = compressed_bytes
        session["data_bytes"] = compressed_bytes

    def records(self, session_id: str) -> list[dict[str, object]]:
        return list(self._iter_records(session_id))

    def analysis_records(
        self,
        session_id: str,
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        """Load a uniform bounded analysis set while retaining the full timeline."""
        limits = {"sample": 100_000, "event": 50_000}
        counts: dict[str, int] = {}
        bucket_counts: dict[str, int] = {}
        for record in self._iter_records(session_id):
            kind = str(record.get("kind", "event"))
            counts[kind] = counts.get(kind, 0) + 1
            bucket = _analysis_bucket(record)
            bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        native_buckets = [
            bucket for bucket in bucket_counts if bucket.startswith("native|")
        ]
        native_limit = max(32, 100_000 // max(1, len(native_buckets)))
        strides = {
            bucket: max(
                1,
                (count + limit - 1) // limit,
            )
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
        for record in self._iter_records(session_id):
            kind = str(record.get("kind", "event"))
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

    def tail(self, session_id: str, *, limit: int) -> list[dict[str, object]]:
        if limit <= 0:
            return []
        remaining = limit
        parts: list[list[dict[str, object]]] = []
        for path in reversed(self.timeline_sources(session_id)):
            try:
                records = _tail_path(path, remaining)
            except OSError:
                continue
            if records:
                parts.insert(0, records)
                remaining -= len(records)
            if remaining <= 0:
                break
        return [record for part in parts for record in part][-limit:]

    def follow(self, session_id: str, *, limit: int) -> Iterator[dict[str, object]]:
        path = self.timeline_path(session_id)
        for record in self.tail(session_id, limit=limit):
            yield record
        handle = path.open("rb")
        try:
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
                try:
                    if os.fstat(handle.fileno()).st_ino != path.stat().st_ino:
                        handle.close()
                        handle = path.open("rb")
                        pending = b""
                except OSError:
                    pass
                self.sleeper(0.5)
        finally:
            handle.close()

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
        timeline_temporary = tempfile.NamedTemporaryFile(
            prefix=f".{session_id}-timeline.",
            suffix=".jsonl",
            dir=target.parent,
            delete=False,
        )
        timeline_temp_path = Path(timeline_temporary.name)
        try:
            with timeline_temporary:
                for record in self._iter_records(session_id):
                    timeline_temporary.write(
                        (
                            json.dumps(
                                record,
                                ensure_ascii=False,
                                separators=(",", ":"),
                            )
                            + "\n"
                        ).encode("utf-8"),
                    )
            with tarfile.open(temp_path, "w:gz") as archive:
                archive.add(timeline_temp_path, arcname="timeline.jsonl")
                _add_bytes(archive, "manifest.json", _json_bytes(manifest))
                _add_bytes(archive, "report.json", _json_bytes(report))
                _add_bytes(archive, "SCHEMA.txt", schema)
            temp_path.chmod(0o600)
            temp_path.replace(target)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
        finally:
            timeline_temp_path.unlink(missing_ok=True)
        return target

    def session_path(self, session_id: str) -> Path:
        _validate_session_id(session_id)
        return self.state_dir / f"{session_id}.json"

    def timeline_path(self, session_id: str) -> Path:
        _validate_session_id(session_id)
        return self.data_dir / f"{session_id}.jsonl"

    def segment_path(self, session_id: str, index: int) -> Path:
        _validate_session_id(session_id)
        if index < 1 or index > 99999:
            raise ValueError("invalid Calls telemetry segment index")
        return self.data_dir / f"{session_id}.part-{index:05d}.jsonl.gz"

    def segment_paths(self, session_id: str) -> list[Path]:
        _validate_session_id(session_id)
        return sorted(self.data_dir.glob(f"{session_id}.part-*.jsonl.gz"))

    def timeline_sources(self, session_id: str) -> list[Path]:
        return [*self.segment_paths(session_id), self.timeline_path(session_id)]

    def _next_segment_index(self, session_id: str) -> int:
        paths = self.segment_paths(session_id)
        if not paths:
            return 1
        match = re.search(r"\.part-([0-9]{5})\.jsonl\.gz$", paths[-1].name)
        return int(match.group(1)) + 1 if match else len(paths) + 1

    def _iter_records(self, session_id: str) -> Iterator[dict[str, object]]:
        seen_sequences: set[int] = set()
        for path in self.timeline_sources(session_id):
            try:
                opener = gzip.open if path.suffix == ".gz" else open
                with opener(path, "rt", encoding="utf-8") as handle:
                    for line in handle:
                        record = _decode_record(line)
                        if record is None:
                            continue
                        sequence = _integer(record.get("sequence"))
                        if sequence and sequence in seen_sequences:
                            continue
                        if sequence:
                            seen_sequences.add(sequence)
                        yield record
            except (OSError, EOFError, gzip.BadGzipFile):
                continue


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
        "raw_data_bytes",
        "compressed_bytes",
        "timeline_segments",
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
