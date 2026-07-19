"""Composition root for HYDRA application use-cases.

Transport adapters (CLI, TUI, Telegram and future HTTP handlers) should depend
on this facade instead of assembling orchestrator and registry dependencies on
their own. The lower-level services remain independently injectable for tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hydra.core.state import AppState, User
from hydra.services.protocols import ProtocolService
from hydra.services.users import UserService


@dataclass(frozen=True)
class ApplicationService:
    """Stable application boundary shared by all management transports."""

    users: UserService
    protocols: ProtocolService
    apply_config: Any
    last_apply_error: Any

    def status(self, state: AppState) -> dict[str, Any]:
        from hydra.core.status import build_status

        return build_status(state)

    def apply(self, state: AppState) -> bool:
        return bool(self.apply_config(state))

    def apply_error(self) -> str:
        return str(self.last_apply_error() or "")

    def add_user(self, state: AppState, user: User) -> User:
        return self.users.add(state, user)

    def remove_user(self, state: AppState, email: str) -> None:
        self.users.remove(state, email)

    def block_user(self, state: AppState, email: str) -> None:
        self.users.block(state, email)

    def unblock_user(self, state: AppState, email: str) -> None:
        self.users.unblock(state, email)


def production_application() -> ApplicationService:
    """Build the default composition once at an adapter boundary."""
    from hydra.core import orchestrator
    from hydra.plugins import registry

    return ApplicationService(
        users=UserService(orchestrator),
        protocols=ProtocolService(orchestrator, registry),
        apply_config=orchestrator.apply_config,
        last_apply_error=orchestrator.last_apply_error,
    )
