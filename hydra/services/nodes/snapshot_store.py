"""Durable, immutable storage for confirmed node client exports."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

from hydra.contracts.node_export import NodeClientExport
from hydra.contracts.node_validation import MAX_NODE_BODY_BYTES, checked_node_id
from hydra.core.host import HostBackend

_DIGEST = re.compile(r"[0-9a-f]{64}")
_MAX_GENERATION = 2**63 - 1


class SnapshotStoreError(RuntimeError):
    """A node export could not be stored or verified safely."""


@dataclass(frozen=True)
class StoredNodeExport:
    node_id: str
    generation: int
    sha256: str
    path: Path


@dataclass
class NodeSnapshotStore:
    host: HostBackend
    root: Path = Path("/var/lib/hydra/node-exports")
    max_bytes: int = MAX_NODE_BODY_BYTES
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        if not self.root.is_absolute():
            raise ValueError("snapshot root must be an absolute path")
        if type(self.max_bytes) is not int or self.max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")

    def store(self, export: NodeClientExport) -> StoredNodeExport:
        export.validate()
        raw = json.dumps(
            export.to_document(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(raw) > self.max_bytes:
            raise SnapshotStoreError("node export exceeds the snapshot size limit")
        digest = hashlib.sha256(raw).hexdigest()
        path = self._snapshot_path(export.node_id, export.generation)
        with self._lock:
            directory = self._node_directory(export.node_id, create=True)
            if path.is_symlink():
                raise SnapshotStoreError("snapshot file must not be a symlink")
            if path.exists():
                existing = self._read_file(path)
                if not hmac.compare_digest(hashlib.sha256(existing).hexdigest(), digest):
                    raise SnapshotStoreError("snapshot generation is immutable")
                self._decode(existing, export.node_id, export.generation)
            else:
                self.host.atomic_write(path, raw, mode=0o600, durable=True)
        return StoredNodeExport(export.node_id, export.generation, digest, path)

    def load(self, node_id: str, generation: int, sha256: str) -> NodeClientExport:
        expected = self._checked_digest(sha256)
        path = self._snapshot_path(node_id, generation)
        with self._lock:
            self._node_directory(node_id, create=False)
            raw = self._read_file(path)
        actual = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(actual, expected):
            raise SnapshotStoreError("snapshot digest does not match its published reference")
        return self._decode(raw, node_id, generation)

    def delete(self, node_id: str, generation: int, sha256: str) -> bool:
        expected = self._checked_digest(sha256)
        path = self._snapshot_path(node_id, generation)
        with self._lock:
            self._node_directory(node_id, create=False)
            if not path.exists():
                return False
            if path.is_symlink():
                raise SnapshotStoreError("snapshot file must not be a symlink")
            raw = self._read_file(path)
            actual = hashlib.sha256(raw).hexdigest()
            if not hmac.compare_digest(actual, expected):
                raise SnapshotStoreError("refusing to delete a snapshot with a different digest")
            self.host.remove_file(path)
        return True

    def _node_directory(self, node_id: str, *, create: bool) -> Path:
        checked_node_id(node_id, context="node_id")
        if self.root.is_symlink():
            raise SnapshotStoreError("snapshot root must not be a symlink")
        if not self.root.exists():
            if not create:
                raise SnapshotStoreError("snapshot directory is unavailable")
            self.host.ensure_directory(self.root, mode=0o700)
        elif create:
            self.host.ensure_directory(self.root, mode=0o700)
        if not self.root.is_dir():
            raise SnapshotStoreError("snapshot root is not a directory")
        directory = self.root / node_id
        if directory.is_symlink():
            raise SnapshotStoreError("node snapshot directory must not be a symlink")
        if not directory.exists():
            if not create:
                raise SnapshotStoreError("node snapshot directory is unavailable")
            self.host.ensure_directory(directory, mode=0o700)
        elif create:
            self.host.ensure_directory(directory, mode=0o700)
        if not directory.is_dir():
            raise SnapshotStoreError("node snapshot path is not a directory")
        return directory

    def _snapshot_path(self, node_id: str, generation: int) -> Path:
        checked_node_id(node_id, context="node_id")
        if type(generation) is not int or not 0 <= generation <= _MAX_GENERATION:
            raise ValueError("generation must be a non-negative integer")
        return self.root / node_id / f"{generation}.json"

    def _read_file(self, path: Path) -> bytes:
        if path.is_symlink() or not path.is_file():
            raise SnapshotStoreError("snapshot file is unavailable or unsafe")
        try:
            if path.stat().st_size > self.max_bytes:
                raise SnapshotStoreError("stored snapshot exceeds the size limit")
            raw = path.read_bytes()
        except OSError as exc:
            raise SnapshotStoreError("snapshot file could not be read") from exc
        if len(raw) > self.max_bytes:
            raise SnapshotStoreError("stored snapshot exceeds the size limit")
        return raw

    @staticmethod
    def _decode(raw: bytes, node_id: str, generation: int) -> NodeClientExport:
        try:
            export = NodeClientExport.from_document(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise SnapshotStoreError("stored node export is invalid") from exc
        if export.node_id != node_id or export.generation != generation:
            raise SnapshotStoreError("stored node export identity does not match its path")
        return export

    @staticmethod
    def _checked_digest(value: str) -> str:
        if not isinstance(value, str) or not _DIGEST.fullmatch(value):
            raise ValueError("sha256 must be a lowercase hexadecimal digest")
        return value


__all__ = ["NodeSnapshotStore", "SnapshotStoreError", "StoredNodeExport"]
