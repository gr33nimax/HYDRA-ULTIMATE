"""Snapshot and restore helpers for the managed creator pool."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from hydra.core.host import HostBackend


@dataclass(frozen=True)
class CreatorPoolRuntimeSnapshot:
    files: dict[Path, tuple[bytes, int]]
    active_units: tuple[str, ...]
    enabled_units: tuple[str, ...]


class PoolSnapshotRuntime(Protocol):
    host: HostBackend
    creator_unit: Path
    pool_state_file: Path

    def call_files(self, *, generation: str, count: int) -> list[Path]: ...
    def creator_units(self, *, generation: str, count: int) -> list[str]: ...


def managed_unit_actions(host: HostBackend, unit: str) -> tuple[str, ...]:
    """Return only state-changing systemd actions needed by one unit."""
    active = host.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
    enabled = host.run(["systemctl", "is-enabled", "--quiet", unit]).returncode == 0
    return tuple(action for action, required in (("stop", active), ("disable", enabled)) if required)


def capture_creator_pool(
    runtime: PoolSnapshotRuntime,
    *,
    count: int,
) -> CreatorPoolRuntimeSnapshot:
    paths = [
        runtime.creator_unit,
        runtime.pool_state_file,
        *(path for generation in ("", "a", "b") for path in runtime.call_files(generation=generation, count=count)),
    ]
    files: dict[Path, tuple[bytes, int]] = {}
    for path in paths:
        try:
            files[path] = (path.read_bytes(), path.stat().st_mode & 0o777)
        except OSError:
            continue
    units = [
        unit for generation in ("", "a", "b") for unit in runtime.creator_units(generation=generation, count=count)
    ]
    active = tuple(
        unit
        for unit in units
        if runtime.host.run(
            ["systemctl", "is-active", "--quiet", unit],
        ).returncode
        == 0
    )
    enabled = tuple(
        unit
        for unit in units
        if runtime.host.run(
            ["systemctl", "is-enabled", "--quiet", unit],
        ).returncode
        == 0
    )
    return CreatorPoolRuntimeSnapshot(files, active, enabled)


def restore_creator_pool_snapshot(
    runtime: PoolSnapshotRuntime,
    snapshot: CreatorPoolRuntimeSnapshot,
    *,
    count: int | None = None,
) -> None:
    if count is not None:
        # An outer transaction may fail after the new generation was finalized.
        # Stop/remove only owned artifacts absent from the pre-mutation snapshot.
        for generation in ("", "a", "b"):
            for unit in runtime.creator_units(generation=generation, count=count):
                for action in managed_unit_actions(runtime.host, unit):
                    retained = snapshot.active_units if action == "stop" else snapshot.enabled_units
                    if unit not in retained and runtime.host.run(["systemctl", action, unit]).returncode != 0:
                        raise RuntimeError("failed to stop newly created VK pool during rollback")
        paths = [runtime.creator_unit, runtime.pool_state_file]
        for generation in ("", "a", "b"):
            paths.extend(runtime.call_files(generation=generation, count=count))
        for path in paths:
            if path not in snapshot.files:
                runtime.host.remove_file(path, missing_ok=True)
    for path, (content, mode) in snapshot.files.items():
        runtime.host.atomic_write(path, content, mode=mode)
    if runtime.host.run(["systemctl", "daemon-reload"]).returncode != 0:
        raise RuntimeError("systemd daemon-reload failed during creator rollback")
    failures: list[str] = []
    for unit in snapshot.enabled_units:
        if runtime.host.run(["systemctl", "enable", unit]).returncode != 0:
            failures.append(f"enable {unit}")
    for unit in snapshot.active_units:
        if runtime.host.run(["systemctl", "start", unit]).returncode != 0:
            failures.append(f"start {unit}")
    if failures:
        raise RuntimeError("failed to restore creator pool: " + ", ".join(failures))


__all__ = [
    "CreatorPoolRuntimeSnapshot",
    "capture_creator_pool",
    "managed_unit_actions",
    "restore_creator_pool_snapshot",
]
