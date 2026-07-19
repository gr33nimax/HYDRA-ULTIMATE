"""Application service boundary for user lifecycle operations.

The CLI, a future REST API and background jobs can share this facade instead
of importing the orchestration module directly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from hydra.core.state import AppState, User, find_user


class UserOperations(Protocol):
    def add_user(self, state: AppState, user: User) -> None: ...
    def remove_user(self, state: AppState, email: str) -> None: ...
    def block_user(self, state: AppState, email: str) -> None: ...
    def unblock_user(self, state: AppState, email: str) -> None: ...


@dataclass(frozen=True)
class UserService:
    """Stable, transport-neutral facade over user lifecycle orchestration."""

    operations: UserOperations

    def list(self, state: AppState) -> list[User]:
        return list(state.users)

    def get(self, state: AppState, email: str) -> User | None:
        return find_user(state, email)

    def add(self, state: AppState, user: User) -> User:
        self.operations.add_user(state, user)
        return user

    def remove(self, state: AppState, email: str) -> None:
        self.operations.remove_user(state, email)

    def block(self, state: AppState, email: str) -> None:
        self.operations.block_user(state, email)

    def unblock(self, state: AppState, email: str) -> None:
        self.operations.unblock_user(state, email)
