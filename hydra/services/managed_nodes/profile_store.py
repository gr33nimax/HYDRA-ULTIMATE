"""Protected immutable profile bundles with an atomic per-node pointer."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Callable

from hydra.contracts.managed_node_observations import ConfirmedProfiles
from hydra.core.host import HostBackend

_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_BUNDLE = 2 * 1024 * 1024


class ManagedNodeProfileStore:
    """Persist validated profile bundles; failed commits leave the prior pointer."""

    def __init__(self, *, host: HostBackend, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("managed-node profile root must be absolute")
        self._host = host
        self._root = root

    def commit(
        self,
        bundle: ConfirmedProfiles,
        *,
        expected_users: set[str],
    ) -> None:
        bundle.validate()
        if not isinstance(expected_users, set) or any(not isinstance(item, str) for item in expected_users):
            raise ValueError("expected profile users must be a set of UUIDs")
        covered = {profile.user_uuid for profile in bundle.profiles}
        if covered - expected_users or expected_users - covered:
            raise ValueError("confirmed profiles do not cover the expected user set")
        directory = self._directory(bundle.node_id)
        self._safe_directory(directory)
        payload = json.dumps(bundle.to_document(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        if len(payload) > _MAX_BUNDLE:
            raise ValueError("confirmed profile bundle exceeds the size limit")
        storage_id = hashlib.sha256(payload).hexdigest()
        bundle_path = directory / f"{storage_id}.json"
        if bundle_path.is_symlink():
            raise ValueError("confirmed profile bundle path is unsafe")
        if not bundle_path.exists():
            self._host.atomic_write(bundle_path, payload, mode=0o600, durable=True)
        else:
            current = self._host.read_bytes(bundle_path, max_bytes=_MAX_BUNDLE)
            if current != payload:
                raise ValueError("immutable profile bundle digest collision")
        pointer_path = directory / "current.json"
        previous = self._read_pointer(pointer_path)
        pointer = {"version": 1, "current": storage_id, "previous": previous.get("current") if previous else None}
        self._host.atomic_write(
            pointer_path,
            json.dumps(pointer, sort_keys=True, separators=(",", ":")),
            mode=0o600,
            durable=True,
        )

    def read(
        self,
        node_id: str,
        *,
        receipt_is_committed: Callable[[ConfirmedProfiles], bool] | None = None,
    ) -> ConfirmedProfiles | None:
        directory = self._directory(node_id)
        if self._root.is_symlink() or directory.is_symlink():
            raise ValueError("managed-node profile directory is unsafe")
        pointer_path = directory / "current.json"
        pointer = self._read_pointer(pointer_path)
        if pointer is None:
            return None
        for digest in (pointer["current"], pointer["previous"]):
            if digest is None:
                continue
            path = directory / f"{digest}.json"
            if path.is_symlink():
                raise ValueError("confirmed profile bundle path is unsafe")
            if not path.is_file():
                continue
            try:
                payload = self._host.read_bytes(path, max_bytes=_MAX_BUNDLE)
                if hashlib.sha256(payload).hexdigest() != digest:
                    continue
                raw = json.loads(payload.decode("utf-8"))
                bundle = ConfirmedProfiles.from_document(raw)
                if bundle.node_id != node_id:
                    continue
                if receipt_is_committed is not None and not receipt_is_committed(bundle):
                    continue
                return bundle
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                continue
        return None

    def _directory(self, node_id: str) -> Path:
        if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
            raise ValueError("managed-node profile identity is invalid")
        return self._root / node_id

    def _safe_directory(self, directory: Path) -> None:
        if self._root.is_symlink() or directory.is_symlink():
            raise ValueError("managed-node profile directory is unsafe")
        self._host.ensure_directory(self._root, mode=0o700)
        self._host.ensure_directory(directory, mode=0o700)

    def _read_pointer(self, path: Path) -> dict[str, str | None] | None:
        if path.is_symlink():
            raise ValueError("managed-node profile pointer path is unsafe")
        if not path.is_file():
            return None
        try:
            raw = json.loads(self._host.read_bytes(path, max_bytes=1024).decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(raw, dict) or set(raw) != {"version", "current", "previous"} or raw["version"] != 1:
            return None
        for name in ("current", "previous"):
            digest = raw[name]
            if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                return None
        return {"current": raw["current"], "previous": raw["previous"]}


__all__ = ["ManagedNodeProfileStore"]
