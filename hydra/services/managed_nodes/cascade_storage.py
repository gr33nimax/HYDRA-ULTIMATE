"""Protected, checksummed local cascade artifacts; no desired state or RPC paths."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from hydra.core.host import HostBackend


class CascadeArtifacts:
    def __init__(self, host: HostBackend, root: Path):
        if not root.is_absolute():
            raise ValueError("cascade artifact root must be absolute")
        self.host, self.root = host, root

    def _path(self, key: str) -> Path:
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}", key):
            raise ValueError("invalid cascade artifact identity")
        for parent in (self.root, *self.root.parents):
            if parent.is_symlink():
                raise ValueError("unsafe cascade artifact directory")
        path = self.root / (key + ".json")
        if path.is_symlink():
            raise ValueError("unsafe cascade artifact path")
        return path

    def read(self, key: str):
        path = self._path(key)
        if not path.exists():
            return None
        if not path.is_file() or (os.name != "nt" and path.stat().st_mode & 0o077):
            raise ValueError("unsafe cascade artifact permissions")
        raw = json.loads(self.host.read_bytes(path, max_bytes=2 * 1024 * 1024))
        if not isinstance(raw, dict) or set(raw) != {"payload", "sha256"}:
            raise ValueError("invalid cascade artifact")
        if hashlib.sha256(_encode(raw["payload"])).hexdigest() != raw["sha256"]:
            raise ValueError("cascade artifact checksum mismatch")
        return raw["payload"]

    def write(self, key: str, document: dict) -> None:
        path = self._path(key)
        payload = _encode(document)
        if len(payload) > 1024 * 1024:
            raise ValueError("cascade artifact exceeds size limit")
        self.host.ensure_directory(self.root, mode=0o700)
        self.host.atomic_write(path, _encode({"payload": document, "sha256": hashlib.sha256(payload).hexdigest()}),
                               mode=0o600, durable=True)

    def remove(self, key: str) -> None:
        self.host.remove_file(self._path(key), missing_ok=True)

    def items(self):
        self._path("inventory")
        if self.root.is_dir():
            for path in sorted(self.root.glob("*.json")):
                yield path.stem, self.read(path.stem)


def _encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
