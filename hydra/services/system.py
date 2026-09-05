"""Transport-neutral system maintenance use-cases.

CLI, TUI and future remote adapters should not import host diagnostics,
upgrade checks or legacy state import storage directly.  This port keeps those
operations behind the application composition root.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from hydra.core.state_models import AppState


class SystemOperations(Protocol):
    def validate(self, state: AppState) -> dict: ...
    def doctor(self, state: AppState) -> dict: ...
    def upgrade_check(self, state: AppState) -> dict: ...
    def migrate_state(self) -> dict: ...


@dataclass(frozen=True)
class UnavailableSystemOperations:
    def _unavailable(self) -> dict:
        raise RuntimeError("system operations are unavailable")

    def validate(self, state: AppState) -> dict:
        return self._unavailable()

    def doctor(self, state: AppState) -> dict:
        return self._unavailable()

    def upgrade_check(self, state: AppState) -> dict:
        return self._unavailable()

    def migrate_state(self) -> dict:
        return self._unavailable()


@dataclass(frozen=True)
class SystemService:
    """Application owner for read-only checks and explicit legacy state import."""

    validate_state: Callable[[AppState], None]
    doctor_check: Callable[[AppState], dict]
    upgrade_readiness: Callable[[AppState], dict]
    migrate_persisted_state: Callable[[], dict]

    def validate(self, state: AppState) -> dict:
        self.validate_state(state)
        return {
            "valid": True,
            # Compatibility name in the public CLI payload; value is format v1.
            "schema_version": state.format_version,
            "revision": state.revision,
        }

    def doctor(self, state: AppState) -> dict:
        return self.doctor_check(state)

    def upgrade_check(self, state: AppState) -> dict:
        return self.upgrade_readiness(state)

    def migrate_state(self) -> dict:
        return self.migrate_persisted_state()


__all__ = [
    "SystemOperations",
    "SystemService",
    "UnavailableSystemOperations",
]
