"""Scoped, mode-0600 state snapshots for crash-safe node apply rollback."""

from __future__ import annotations

import re
from pathlib import Path

from hydra.core.host import HostBackend
from hydra.core.state_snapshots import deserialize_state_snapshot, serialize_state_snapshot
from hydra.core.state_models import AppState

_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_SNAPSHOT = 16 * 1024 * 1024


class ManagedNodeSnapshotStore:
    def __init__(self, *, host: HostBackend, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("managed-node snapshot root must be absolute")
        self._host = host
        self._root = root

    def save(self, operation_id: str, state: AppState) -> None:
        path = self._path(operation_id)
        if self._root.is_symlink() or path.is_symlink():
            raise ValueError("managed-node snapshot path is unsafe")
        payload = serialize_state_snapshot(state)
        if len(payload) > _MAX_SNAPSHOT:
            raise ValueError("managed-node state snapshot exceeds the size limit")
        if self._root.exists() and path.exists():
            self._assert_same_snapshot(path, payload)
            return
        self._host.ensure_directory(self._root, mode=0o700)
        if self._root.is_symlink() or path.is_symlink():
            raise ValueError("managed-node snapshot path is unsafe")
        if path.exists():
            self._assert_same_snapshot(path, payload)
            return
        self._host.atomic_write(path, payload, mode=0o600, durable=True)

    def load(self, operation_id: str) -> AppState | None:
        path = self._path(operation_id)
        if self._root.is_symlink() or path.is_symlink():
            raise ValueError("managed-node snapshot path is unsafe")
        if not path.is_file():
            return None
        return deserialize_state_snapshot(self._host.read_bytes(path, max_bytes=_MAX_SNAPSHOT))

    def remove(self, operation_id: str) -> None:
        path = self._path(operation_id)
        if self._root.is_symlink() or path.is_symlink():
            raise ValueError("managed-node snapshot path is unsafe")
        self._host.remove_file(path, missing_ok=True)

    def _assert_same_snapshot(self, path: Path, payload: bytes) -> None:
        current = self._host.read_bytes(path, max_bytes=_MAX_SNAPSHOT)
        if current != payload:
            raise ValueError("managed-node rollback snapshot is immutable")

    def _path(self, operation_id: str) -> Path:
        if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
            raise ValueError("managed-node snapshot operation id is invalid")
        return self._root / f"{operation_id}.json"


__all__ = ["ManagedNodeSnapshotStore"]
