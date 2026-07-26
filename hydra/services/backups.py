"""Application boundary and trusted inventory for backup/restore operations."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from hydra.contracts import BackupPolicy, BackupResource
from hydra.core.backup import CORE_BACKUP_RESOURCES


class BackupOperations(Protocol):
    def create(self, output: str | Path | None = None) -> dict: ...
    def inspect(self, archive: str | Path) -> dict: ...
    def restore(
        self,
        archive: str | Path,
        *,
        dry_run: bool = False,
    ) -> dict: ...


@dataclass(frozen=True)
class UnavailableBackupOperations:
    def create(self, output: str | Path | None = None) -> dict:
        raise RuntimeError("backup service is unavailable")

    def inspect(self, archive: str | Path) -> dict:
        raise RuntimeError("backup service is unavailable")

    def restore(
        self,
        archive: str | Path,
        *,
        dry_run: bool = False,
    ) -> dict:
        raise RuntimeError("backup service is unavailable")


def compose_backup_policy(
    plugin_resources: tuple[BackupResource, ...] = (),
) -> BackupPolicy:
    """Merge trusted declarations once, rejecting ambiguous ownership."""
    by_path: dict[str, BackupResource] = {}
    for resource in (*CORE_BACKUP_RESOURCES, *plugin_resources):
        key = resource.path.replace("\\", "/").rstrip("/")
        previous = by_path.get(key)
        if previous is not None and (
            previous.kind != resource.kind
            or previous.excludes != resource.excludes
        ):
            raise ValueError(
                f"conflicting backup resource declaration: {resource.path}",
            )
        if previous is None:
            by_path[key] = resource
    return BackupPolicy(tuple(by_path.values()))


@dataclass(frozen=True)
class BackupService:
    """Bind archive mechanics to the current trusted application policy."""

    policy: BackupPolicy

    def create(self, output: str | Path | None = None) -> dict:
        from hydra.core.backup import create_backup

        return create_backup(output, policy=self.policy)

    def inspect(self, archive: str | Path) -> dict:
        from hydra.core.backup import inspect_backup

        return inspect_backup(archive, policy=self.policy)

    def restore(
        self,
        archive: str | Path,
        *,
        dry_run: bool = False,
    ) -> dict:
        from hydra.core.backup import restore_backup

        return restore_backup(
            archive,
            dry_run=dry_run,
            policy=self.policy,
        )


__all__ = [
    "BackupOperations",
    "BackupService",
    "CORE_BACKUP_RESOURCES",
    "UnavailableBackupOperations",
    "compose_backup_policy",
]
