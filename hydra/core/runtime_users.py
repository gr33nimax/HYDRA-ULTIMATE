"""Represent ephemeral transport credentials without exposing them in reprs."""

from __future__ import annotations

from hydra.core.state_models import User
from dataclasses import dataclass, field
import hashlib


@dataclass(repr=False)
class ProtectedRuntimeUser(User):
    """Canonical User-shaped transient identity with a redacted representation."""

    shared_credentials: bool = field(default=False, repr=False)

    def __repr__(self) -> str:
        return "ProtectedRuntimeUser(<protected>)"


def shared_runtime_password(user: User) -> str:
    """The random scoped UUID carries a cascade credential across participant hosts."""
    return hashlib.sha256(f"anytls-pass|{user.uuid}".encode()).hexdigest()


__all__ = ["ProtectedRuntimeUser"]
