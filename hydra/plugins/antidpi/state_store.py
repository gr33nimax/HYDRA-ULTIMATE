"""Atomic persistence for AntiDPI runtime evidence."""
from __future__ import annotations

import json
import os
import time
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


class AntiDPIStateCorruptError(RuntimeError):
    """The persisted AntiDPI state was quarantined and needs recovery."""


def load_cursor(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()[:4096]
    except OSError:
        return ""


def store_cursor(path: Path, cursor: str) -> None:
    cursor = cursor.strip()[:4096]
    try:
        if not cursor:
            path.unlink(missing_ok=True)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(cursor + "\n", encoding="utf-8")
        temporary.replace(path)
    except OSError:
        pass


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
        except FileNotFoundError:
            if self.degraded():
                raise AntiDPIStateCorruptError(
                    "AntiDPI state is quarantined; restore a valid state file",
                )
            return empty_state()
        except OSError:
            raise
        except ValueError:
            # Corrupt state must not silently masquerade as "no bans and no
            # whitelist": quarantine the file so the evidence survives and
            # the next save starts from a diagnosable fresh state.
            self._quarantine_corrupt()
            raise AntiDPIStateCorruptError(
                "AntiDPI state is corrupt and was quarantined",
            )
        if isinstance(data, dict):
            return data
        self._quarantine_corrupt()
        raise AntiDPIStateCorruptError(
            "AntiDPI state root is not an object and was quarantined",
        )

    def degraded(self) -> bool:
        """Return whether a quarantined state awaits explicit recovery."""
        return not self.path.exists() and any(
            self.path.parent.glob(f"{self.path.name}.corrupt-*")
        )

    def _quarantine_corrupt(self) -> None:
        try:
            quarantine = self.path.with_name(
                f"{self.path.name}.corrupt-{time.time_ns()}",
            )
            self.path.replace(quarantine)
        except OSError:
            pass

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
