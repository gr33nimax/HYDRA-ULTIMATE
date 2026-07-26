"""Atomic persistence for AntiDPI runtime evidence."""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows development hosts
    fcntl = None


def empty_state() -> dict:
    """Return a fresh backward-compatible runtime state."""
    return {
        "banned": {},
        "scores": {},
        "events": 0,
        "whitelist": [],
        "history": [],
        "ban_counts": {},
    }


@contextmanager
def lock_state_file(path: Path) -> Iterator[None]:
    """Serialize read-modify-write operations for one state path."""
    if fcntl is None:
        yield
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.with_suffix(".lock").open("w", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                yield
            finally:
                try:
                    fcntl.flock(lock_file, fcntl.LOCK_UN)
                except OSError:
                    pass
    except OSError as exc:
        raise RuntimeError(f"could not lock AntiDPI state: {exc}") from exc


class AntiDPIStateStore:
    """Small explicit store used by the plugin and diagnostic composition."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return empty_state()

    def save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".json.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(self.path)

    def snapshot(self) -> dict:
        """Return a detached state view suitable for application queries."""
        import copy

        return copy.deepcopy(self.load())
