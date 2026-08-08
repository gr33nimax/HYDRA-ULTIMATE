"""Inter-process lock adapter for creator consumer transactions."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from hydra.core.host import HostBackend


@dataclass
class CreatorFileLockLease:
    handle: BinaryIO

    def release(self) -> None:
        try:
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()


@dataclass(frozen=True)
class CreatorFileLock:
    host: HostBackend
    path: Path

    def try_acquire(self) -> CreatorFileLockLease | None:
        self.host.ensure_directory(self.path.parent, mode=0o755)
        handle = self.path.open("a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    handle.close()
                    return None
            else:
                import fcntl

                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    handle.close()
                    return None
            return CreatorFileLockLease(handle)
        except Exception:
            handle.close()
            raise


__all__ = ["CreatorFileLock", "CreatorFileLockLease"]
