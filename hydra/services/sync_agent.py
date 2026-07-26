"""Background synchronization entrypoint and process-level adapters."""
from __future__ import annotations

import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, TextIO

from hydra.core.state import update_state
from hydra.services.sync_cycle import run_sync_cycle
from hydra.services.sync_ports import SyncOperations


SYNC_LOCK = Path("/run/hydra/sync-agent.lock")
SYNC_LOG = Path("/var/log/hydra/sync-agent.log")


@contextmanager
def _single_run() -> Iterator[bool]:
    """Prevent timer and interactive synchronization from overlapping."""
    if sys.platform == "win32":
        yield True
        return

    handle: TextIO | None = None
    try:
        import fcntl

        SYNC_LOCK.parent.mkdir(parents=True, exist_ok=True)
        handle = SYNC_LOCK.open("a+", encoding="utf-8")
        try:
            fcntl.flock(
                handle.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        if handle is not None:
            handle.close()


def run_sync(
    force_update_check: bool = False,
    force_all_checks: bool = False,
    *,
    operations: SyncOperations,
) -> tuple[bool, str]:
    """Run one synchronization cycle and report partial failures."""
    with _single_run() as acquired:
        if not acquired:
            message = (
                "Sync Agent уже выполняется другим процессом"
            )
            _log(message)
            return False, message
        return _run_sync(
            force_update_check=force_update_check,
            force_all_checks=force_all_checks,
            operations=operations,
        )


def _run_sync(
    force_update_check: bool = False,
    force_all_checks: bool = False,
    *,
    operations: SyncOperations,
) -> tuple[bool, str]:
    """Compose state and logging adapters around the reusable cycle."""
    from hydra.core.state import load_state

    return run_sync_cycle(
        load_state(),
        operations=operations,
        update_state=update_state,
        log=_log,
        force_update_check=force_update_check,
        force_all_checks=force_all_checks,
    )


def _log(message: str) -> None:
    try:
        SYNC_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with SYNC_LOG.open("a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def log_event(message: str) -> None:
    """Record an adapter-level synchronization failure."""
    _log(message)


if __name__ == "__main__":
    # Compatibility for systemd units installed by HYDRA <= 2.5.3.
    from hydra.entrypoints.sync_agent import main as _main

    raise SystemExit(_main())
