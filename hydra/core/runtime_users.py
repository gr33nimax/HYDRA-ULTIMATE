"""Represent ephemeral transport credentials without exposing them in reprs."""

from __future__ import annotations

from hydra.core.state_models import User


class ProtectedRuntimeUser(User):
    """Canonical User-shaped transient identity with a redacted representation."""

    def __repr__(self) -> str:
        return "ProtectedRuntimeUser(<protected>)"


__all__ = ["ProtectedRuntimeUser"]
