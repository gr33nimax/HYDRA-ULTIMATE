"""Serialize ordinary runtime applies with managed-node participant leases."""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TypeVar

from hydra.contracts.managed_node_models import Operation
from hydra.core.state_managed_nodes import managed_nodes_from_extensions
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.cascade_leases import (
    assert_node_unleased,
    cascade_participants,
    operation_is_active,
)

T = TypeVar("T")
StateReader = Callable[[], AppState]
StateUpdater = Callable[[Callable[[AppState], T]], tuple[AppState, T]]
AuthenticatedParticipant = Callable[[Operation], str | None]


class ManagedNodeApplyRejected(ValueError):
    """An apply cannot acquire its current persisted participant lease."""


class _ApplyAuthorization:
    __slots__ = ("_seal", "operation_id", "plan_digest", "participant_id")

    def __init__(self, seal: object, operation: Operation, participant_id: str) -> None:
        self._seal = seal
        self.operation_id = operation.id
        self.plan_digest = operation.desired_digest
        self.participant_id = participant_id

    def __repr__(self) -> str:
        return "ManagedNodeApplyAuthorization(<protected>)"


class ManagedNodeApplyGate:
    """Hold one cross-process lease from persisted-state check through runtime apply."""

    def __init__(
        self,
        *,
        state_reader: StateReader,
        participant_id: str,
        lock_path: Path,
        authenticated_participant: AuthenticatedParticipant | None = None,
    ) -> None:
        if not isinstance(participant_id, str) or not participant_id:
            raise ValueError("managed-node apply participant identity is invalid")
        if not lock_path.is_absolute():
            raise ValueError("managed-node apply lock path must be absolute")
        self._state_reader = state_reader
        self._participant_id = participant_id
        self._lock_path = lock_path
        self._authenticated_participant = authenticated_participant
        self._seal = object()
        self._thread_lock = threading.Lock()

    def wrap_state_updater(self, state_updater: StateUpdater) -> StateUpdater:
        """Share apply serialization with atomic managed-node operation writes."""

        def update(mutator: Callable[[AppState], T]) -> tuple[AppState, T]:
            with self._operation_change():
                return state_updater(mutator)

        return update

    @contextmanager
    def _operation_change(self) -> Iterator[None]:
        with self._exclusive(blocking=False):
            yield

    @contextmanager
    def participant_mutation(
        self,
        operation_id: str,
        plan_digest: str,
        *,
        require_snapshot: bool = False,
    ) -> Iterator[Operation]:
        """Serialize private participant writes against rollback, commit and state mutation."""
        with self._exclusive(blocking=False):
            namespace = managed_nodes_from_extensions(self._state_reader().feature_extensions)
            operation = next((item for item in namespace.operations if item.id == operation_id), None)
            if operation is None:
                raise ManagedNodeApplyRejected("active frozen cascade participant lease is unavailable")
            self._validate_owner_operation(operation, namespace, plan_digest, require_snapshot=require_snapshot)
            yield operation

    @contextmanager
    def application(self, authorization: object | None = None) -> Iterator[None]:
        with self._exclusive(blocking=False):
            try:
                namespace = managed_nodes_from_extensions(self._state_reader().feature_extensions)
                if authorization is None:
                    assert_node_unleased(namespace, self._participant_id)
                else:
                    self._validate_authorization(authorization, namespace)
            except ManagedNodeApplyRejected:
                raise
            except (TypeError, ValueError):
                raise ManagedNodeApplyRejected("managed-node cascade participant is currently leased") from None
            except Exception:
                raise ManagedNodeApplyRejected("persisted managed-node lease state is unavailable") from None
            yield

    def authorize_participant(self, operation_id: str) -> object:
        """Issue an opaque local capability only after checking the authenticated owner."""
        with self._exclusive(blocking=False):
            namespace = managed_nodes_from_extensions(self._state_reader().feature_extensions)
            operation = next((item for item in namespace.operations if item.id == operation_id), None)
            if (
                operation is None
                or operation.kind not in {"cascade_save", "cascade_remove"}
                or not operation_is_active(operation)
                or "snapshot" not in operation.completed_steps
                or self._participant_id not in cascade_participants(operation)
            ):
                raise ValueError("unknown active cascade participant operation")
            if self._authenticated_participant is None:
                raise ValueError("authenticated participant owner is unavailable")
            try:
                authenticated_id = self._authenticated_participant(operation)
            except Exception:
                raise ValueError("authenticated participant validation failed") from None
            if authenticated_id != self._participant_id:
                raise ValueError("authenticated participant does not own this apply")
            return _ApplyAuthorization(self._seal, operation, self._participant_id)

    def _validate_authorization(self, authorization: object, namespace) -> None:
        if (
            not isinstance(authorization, _ApplyAuthorization)
            or authorization._seal is not self._seal
            or authorization.participant_id != self._participant_id
        ):
            raise ManagedNodeApplyRejected("cascade participant apply authorization is invalid")
        operation = next((item for item in namespace.operations if item.id == authorization.operation_id), None)
        if (
            operation is None
            or operation.kind not in {"cascade_save", "cascade_remove"}
            or not operation_is_active(operation)
            or "snapshot" not in operation.completed_steps
            or operation.desired_digest != authorization.plan_digest
            or self._participant_id not in cascade_participants(operation)
        ):
            raise ManagedNodeApplyRejected("cascade participant apply authorization is stale")
        self._validate_authenticated_owner(operation)
        for other in namespace.operations:
            if other.id == operation.id or not operation_is_active(other):
                continue
            if other.kind in {"cascade_save", "cascade_remove"}:
                if self._participant_id in cascade_participants(other):
                    raise ManagedNodeApplyRejected("another cascade operation owns this participant")
            elif other.target_id == self._participant_id:
                raise ManagedNodeApplyRejected("another managed-node operation owns this participant")

    def _validate_owner_operation(self, operation, namespace, plan_digest, *, require_snapshot: bool) -> None:
        if (
            operation is None
            or operation.kind not in {"cascade_save", "cascade_remove"}
            or not operation_is_active(operation)
            or operation.desired_digest != plan_digest
            or self._participant_id not in cascade_participants(operation)
            or (require_snapshot and "snapshot" not in operation.completed_steps)
        ):
            raise ManagedNodeApplyRejected("active frozen cascade participant lease is unavailable")
        self._validate_authenticated_owner(operation)
        for other in namespace.operations:
            if other.id == operation.id or not operation_is_active(other):
                continue
            if other.kind in {"cascade_save", "cascade_remove"}:
                if self._participant_id in cascade_participants(other):
                    raise ManagedNodeApplyRejected("another cascade operation owns this participant")
            elif other.target_id == self._participant_id:
                raise ManagedNodeApplyRejected("another managed-node operation owns this participant")

    def _validate_authenticated_owner(self, operation: Operation) -> None:
        if self._authenticated_participant is None:
            raise ManagedNodeApplyRejected("authenticated participant owner is unavailable")
        try:
            authenticated_id = self._authenticated_participant(operation)
        except Exception:
            raise ManagedNodeApplyRejected("authenticated participant validation failed") from None
        if authenticated_id != self._participant_id:
            raise ManagedNodeApplyRejected("authenticated participant does not own this apply")

    @contextmanager
    def _exclusive(self, *, blocking: bool) -> Iterator[None]:
        if not self._thread_lock.acquire(blocking=blocking):
            raise ManagedNodeApplyRejected("managed-node runtime apply is already in progress")
        descriptor = -1
        locked = False
        try:
            current = self._lock_path
            while current != current.parent:
                if current.is_symlink():
                    raise ManagedNodeApplyRejected("managed-node apply lock path is unsafe")
                current = current.parent
            self._lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self._lock_path.is_symlink():
                raise ManagedNodeApplyRejected("managed-node apply lock path is unsafe")
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._lock_path, flags, 0o600)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ManagedNodeApplyRejected("managed-node apply lock is not a regular file")
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
                import fcntl

                options = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
                try:
                    fcntl.flock(descriptor, options)
                    locked = True
                except BlockingIOError as exc:
                    raise ManagedNodeApplyRejected("managed-node runtime apply is already in progress") from exc
            else:
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
                try:
                    msvcrt.locking(descriptor, mode, 1)
                    locked = True
                except OSError as exc:
                    raise ManagedNodeApplyRejected("managed-node runtime apply is already in progress") from exc
            yield
        finally:
            if descriptor >= 0:
                if locked and os.name != "nt":
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                elif locked:
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                os.close(descriptor)
            self._thread_lock.release()


__all__ = ["ManagedNodeApplyGate", "ManagedNodeApplyRejected"]
