"""Trusted backup-resource declarations shared by plugins and adapters."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BackupResource:
    """One exact file or recursively owned tree eligible for backup/restore."""

    path: str
    kind: str
    owner: str = ""
    excludes: tuple[str, ...] = ()


@dataclass(frozen=True)
class BackupPolicy:
    """The current application's complete trusted backup inventory."""

    resources: tuple[BackupResource, ...]


__all__ = ["BackupPolicy", "BackupResource"]
