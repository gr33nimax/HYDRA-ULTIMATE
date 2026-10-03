"""Durable node-side apply through the existing user and configuration owners."""

from __future__ import annotations

import copy
import importlib
import os
import threading
from collections.abc import Callable
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any, Iterator, Protocol

from hydra.contracts.managed_node_models import (
    ApplyReceipt,
    NodeDesired,
    Operation,
    canonical_digest,
)
from hydra.contracts.managed_node_observations import ConfirmedProfiles
from hydra.core.state_models import AppState, PluginState, User
from hydra.services.configuration import restore_state_in_place
from hydra.services.managed_nodes.access import user_from_assignment
from hydra.services.managed_nodes.profile_store import ManagedNodeProfileStore
from hydra.services.managed_nodes.profiles import (
    ManagedNodeProfileBuilder,
    expected_profile_pairs,
    expected_profile_users,
)
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.runtime import ManagedNodeRuntime
from hydra.services.managed_nodes.snapshots import ManagedNodeSnapshotStore
from hydra.services.user_access import access_status
from hydra.utils.commands import redact_text


class UserReconciler(Protocol):
    def __call__(self, state: AppState, users: list[User]) -> None: ...


class ManagedNodeApplyService:
    """Persist intent/snapshot before effects and receipt only after runtime proof."""

    def __init__(
        self,
        *,
        node_id: str,
        records: ManagedNodeRecords,
        state_reader: Callable[[], AppState],
        restore_state: Callable[[AppState], AppState],
        reconcile_users: UserReconciler,
        apply_config: Callable[[AppState], bool],
        protocols: Any,
        runtime: ManagedNodeRuntime,
        profile_builder: ManagedNodeProfileBuilder,
        profile_store: ManagedNodeProfileStore,
        snapshots: ManagedNodeSnapshotStore,
        lock_path: Path,
        operation_executor: Any | None = None,
    ) -> None:
        if not lock_path.is_absolute():
            raise ValueError("managed-node apply lock path must be absolute")
        self.node_id = node_id
        self._records = records
        self._state_reader = state_reader
        self._restore_state = restore_state
        self._reconcile_users = reconcile_users
        self._apply_config = apply_config
        self._protocols = protocols
        self._runtime = runtime
        self._profile_builder = profile_builder
        self._profile_store = profile_store
        self._snapshots = snapshots
        self._lock_path = lock_path
        self._lock = threading.Lock()
        self._future_lock = threading.Lock()
        self._futures: dict[str, Any] = {}
        self._executor = operation_executor

    def submit(self, operation_id: str, desired: NodeDesired) -> Operation:
        desired.validate()
        if desired.node_id != self.node_id:
            raise ValueError("apply desired node identity does not match this agent")
        operation = Operation(
            id=operation_id,
            kind="apply",
            target_id=self.node_id,
            desired_digest=desired.digest,
            state="pending",
            plan=desired.to_document(),
        )
        current = self._records.begin_operation(operation)
        if current.state == "succeeded":
            return current
        self._schedule(current.id)
        return self._records.find_operation(current.id) or current

    def operation(self, operation_id: str) -> Operation | None:
        return self._records.find_operation(operation_id)

    def accounting_lock(self) -> AbstractContextManager[None]:
        """Serialize committed counter baselines with config/user apply effects."""
        return self._target_lock()

    def profiles(self) -> ConfirmedProfiles | None:
        return self._profile_store.read(
            self.node_id,
            receipt_is_committed=self._receipt_committed,
        )

    def recover_pending(self) -> None:
        for operation in self._records.list_operations():
            if operation.kind == "apply" and operation.target_id == self.node_id and operation.state in {"pending", "running", "recovery_required"}:
                self._schedule(operation.id)

    def _schedule(self, operation_id: str) -> None:
        with self._future_lock:
            future = self._futures.get(operation_id)
            if future is not None and (
                future.is_alive() if isinstance(future, threading.Thread) else not future.done()
            ):
                return
            if self._executor is None:
                thread = threading.Thread(target=self._run_safely, args=(operation_id,), name=f"managed-node-apply-{self.node_id}", daemon=True)
                self._futures[operation_id] = thread
                thread.start()
            else:
                self._futures[operation_id] = self._executor.submit(self._run_safely, operation_id)

    def _run_safely(self, operation_id: str) -> None:
        try:
            self.apply(operation_id)
        except Exception:
            return
        finally:
            with self._future_lock:
                self._futures.pop(operation_id, None)

    def apply(self, operation_id: str) -> Operation:
        with self._target_lock():
            operation = self._records.find_operation(operation_id)
            if operation is None or operation.kind != "apply" or operation.target_id != self.node_id:
                raise KeyError(f"unknown managed-node apply operation {operation_id}")
            desired = NodeDesired.from_document(operation.plan)
            if operation.desired_digest != desired.digest:
                raise ValueError("durable apply desired digest does not match its operation")
            if operation.state == "succeeded":
                return operation
            current_state = self._state_reader()
            snapshot = self._snapshots.load(operation_id)
            if snapshot is None:
                self._snapshots.save(operation_id, current_state)
                snapshot = copy.deepcopy(current_state)
            self._records.begin_step(operation_id, "apply")
            current_state = self._state_reader()
            effect_attempted = False
            try:
                self._validate_protocols(desired)
                users = self._project_users(desired, current_state)
                self._project_protocols(desired, current_state)
                effect_attempted = True
                self._reconcile_users(current_state, users)
                applied_state = self._state_reader()
                runtime = self._runtime.observe()
                runtime_id = runtime.get("apply_generation")
                if runtime.get("engine_active") is not True or not isinstance(runtime_id, str) or not runtime_id:
                    raise RuntimeError("configured Sing-Box runtime could not be confirmed")
                profiles = self._profile_builder.build(applied_state, self.node_id)
                expected = expected_profile_pairs(applied_state.users, desired.protocols)
                actual = {(profile.user_uuid, profile.protocol) for profile in profiles}
                if actual != expected:
                    raise RuntimeError("confirmed profile export does not cover the applied users and protocols")
                expected_users = expected_profile_users(expected)
                profiles_digest = canonical_digest([item.to_document() for item in profiles])
                receipt = ApplyReceipt(
                    operation_id=operation_id,
                    desired_revision=desired.revision,
                    desired_digest=desired.digest,
                    runtime_id=runtime_id,
                    users_digest=desired.users_digest,
                    profiles_digest=profiles_digest,
                )
                bundle = ConfirmedProfiles(self.node_id, receipt, profiles, profiles_digest)
                bundle.validate()
                self._profile_store.commit(bundle, expected_users=expected_users)
                result = Operation(
                    operation.id, operation.kind, operation.target_id, operation.desired_digest,
                    "succeeded", ["apply"], None, receipt, operation.plan,
                    operation.remote_removal_confirmed, None, operation.existing_reinstall_confirmed,
                )
                self._records.update_operation(result)
                self._snapshots.remove(operation_id)
                return result
            except Exception as exc:
                rollback_reason = ""
                if effect_attempted:
                    try:
                        restored = self._restore_state(snapshot)
                        restore_state_in_place(current_state, restored)
                        if not self._apply_config(current_state):
                            rollback_reason = "previous runtime configuration could not be restored"
                    except Exception as rollback_error:
                        rollback_reason = redact_text(str(rollback_error))[:160] or rollback_error.__class__.__name__
                current = self._records.find_operation(operation_id)
                if current is not None:
                    reason = redact_text(str(exc))[:160] or exc.__class__.__name__
                    result = Operation(
                        current.id, current.kind, current.target_id, current.desired_digest,
                        "recovery_required" if rollback_reason else "failed",
                        list(current.completed_steps),
                        {"stage": "apply", "reason": reason, **({"rollback_reason": rollback_reason} if rollback_reason else {})},
                        current.receipt, current.plan, current.remote_removal_confirmed,
                        "apply" if rollback_reason else None, current.existing_reinstall_confirmed,
                    )
                    self._records.update_operation(result)
                if not rollback_reason:
                    self._snapshots.remove(operation_id)
                raise

    def _project_users(self, desired: NodeDesired, state: AppState) -> list[User]:
        previous = {user.uuid: user for user in state.users}
        users = []
        for assignment in desired.users:
            user = user_from_assignment(
                assignment,
                previous=previous.get(assignment.uuid),
                state_install=state.install,
            )
            user.blocked = user.blocked or not access_status(user)[0]
            users.append(user)
        return users

    def _validate_protocols(self, desired: NodeDesired) -> None:
        available = {plugin.meta.name: plugin for plugin in self._protocols.list()}
        for assignment in desired.protocols:
            plugin = available.get(assignment.name)
            if plugin is None or plugin.meta.category.value != "transport":
                raise ValueError(f"unsupported managed-node transport: {assignment.name}")

    def _project_protocols(self, desired: NodeDesired, state: AppState) -> None:
        assignments = {item.name: item for item in desired.protocols}
        for plugin in self._protocols.list():
            if plugin.meta.category.value != "transport":
                continue
            current = state.protocols.get(plugin.meta.name) or PluginState()
            assignment = assignments.get(plugin.meta.name)
            if assignment is None:
                current.enabled = False
                state.protocols[plugin.meta.name] = current
                continue
            config = _preserve_node_material(current.config, assignment.parameters)
            port = config.get("port", current.port)
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError(f"managed-node transport {plugin.meta.name} has no valid port")
            current.enabled = True
            current.installed = True
            current.port = port
            current.config = config
            state.protocols[plugin.meta.name] = current

    def _receipt_committed(self, bundle: ConfirmedProfiles) -> bool:
        operation = self._records.find_operation(bundle.receipt.operation_id)
        return bool(operation and operation.state == "succeeded" and operation.receipt == bundle.receipt)

    @contextmanager
    def _target_lock(self) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("managed-node apply is already running")
        descriptor: int | None = None
        fcntl_module = importlib.import_module("fcntl") if os.name != "nt" else None
        try:
            self._lock_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            if fcntl_module is not None:
                fcntl_module.flock(descriptor, fcntl_module.LOCK_EX | fcntl_module.LOCK_NB)
            yield
        except BlockingIOError as exc:
            raise RuntimeError("managed-node apply is already running in another process") from exc
        finally:
            if descriptor is not None:
                if fcntl_module is not None:
                    fcntl_module.flock(descriptor, fcntl_module.LOCK_UN)
                os.close(descriptor)
            self._lock.release()


def _preserve_node_material(previous: dict[str, Any], requested: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(requested)
    for key, value in previous.items():
        if _is_private_material_key(key) and key not in result:
            result[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _preserve_node_material(value, result[key])
    return result


def _is_private_material_key(key: str) -> bool:
    lowered = key.casefold().replace("-", "_")
    return any(part in lowered for part in ("private_key", "secret", "password", "token", "credential", "uuid"))


__all__ = ["ManagedNodeApplyService"]
