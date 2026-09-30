"""Application service boundary for user lifecycle operations.

The CLI, a future REST API and background jobs can share this facade instead
of importing the orchestration module directly.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from hydra.core.state_models import AppState, User, find_user
from hydra.services.user_access import access_status, entitlement_status

_LOGGER = logging.getLogger(__name__)


class UserOperations(Protocol):
    def add_user(self, state: AppState, user: User) -> None: ...
    def reconcile_users(self, state: AppState, users: list[User]) -> None: ...
    def remove_user(self, state: AppState, email: str) -> None: ...
    def block_user(self, state: AppState, email: str) -> None: ...
    def unblock_user(self, state: AppState, email: str) -> None: ...
    def rename_user(self, state: AppState, email: str, new_email: str) -> None: ...
    def set_user_device_limit(
        self,
        state: AppState,
        email: str,
        limit: int,
        *,
        reset: bool = False,
    ) -> None: ...
    def rotate_user_hydrabox_key(self, state: AppState, email: str) -> None: ...
    def set_user_protocol_enabled(
        self,
        state: AppState,
        email: str,
        name: str,
        enabled: bool,
    ) -> None: ...


@dataclass(frozen=True)
class UserService:
    """Stable, transport-neutral facade over user lifecycle orchestration."""

    operations: UserOperations
    after_node_change: Callable[[], object] = lambda: None

    def _notify_node_reconciler(self) -> None:
        try:
            self.after_node_change()
        except Exception as exc:
            _LOGGER.warning("Best-effort node reconciliation failed (%s)", type(exc).__name__)

    def list(self, state: AppState) -> list[User]:
        return list(state.users)

    def reconcile(self, state: AppState, users: list[User]) -> None:
        """Atomically replace a replicated user view through its lifecycle owner."""
        self.operations.reconcile_users(state, users)
        self._notify_node_reconciler()

    def get(self, state: AppState, email: str) -> User | None:
        return find_user(state, email)

    def access_status(self, user: User) -> tuple[bool, str]:
        return access_status(user)

    def entitlement_status(self, user: User) -> tuple[bool, str]:
        return entitlement_status(user)

    def add(self, state: AppState, user: User) -> User:
        self.operations.add_user(state, user)
        self._notify_node_reconciler()
        return user

    def remove(self, state: AppState, email: str) -> None:
        self.operations.remove_user(state, email)
        self._notify_node_reconciler()

    def block(self, state: AppState, email: str) -> None:
        self.operations.block_user(state, email)
        self._notify_node_reconciler()

    def unblock(self, state: AppState, email: str) -> None:
        self.operations.unblock_user(state, email)
        self._notify_node_reconciler()

    def rename(self, state: AppState, email: str, new_email: str) -> User:
        self.operations.rename_user(state, email, new_email)
        self._notify_node_reconciler()
        user = find_user(state, new_email)
        if user is None:
            raise RuntimeError("renamed user was not found")
        return user

    def set_device_limit(
        self,
        state: AppState,
        email: str,
        limit: int,
        *,
        reset: bool = False,
    ) -> User:
        self.operations.set_user_device_limit(state, email, limit, reset=reset)
        user = find_user(state, email)
        if user is None:
            raise RuntimeError("user was not found")
        return user

    def set_protocol_enabled(
        self,
        state: AppState,
        email: str,
        name: str,
        enabled: bool,
    ) -> None:
        self.operations.set_user_protocol_enabled(state, email, name, enabled)
        self._notify_node_reconciler()

    def rotate_hydrabox_key(self, state: AppState, email: str) -> User:
        self.operations.rotate_user_hydrabox_key(state, email)
        user = find_user(state, email)
        if user is None:
            raise RuntimeError("user was not found")
        return user
