"""Access and durable lifecycle journal for the managed-node namespace."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import TypeVar

from hydra.contracts.managed_node_models import (
    CascadeDefinition,
    NodeDefinition,
    NodeDesired,
    Operation,
    ProtocolAssignment,
)
from hydra.core.state_managed_nodes import (
    ManagedNodesState,
    managed_nodes_from_extensions,
    store_managed_nodes,
)
from hydra.core.state_models import AppState
from hydra.services.managed_nodes import cascade_leases
from hydra.services.managed_nodes.cascade_participant_records import (
    complete_removal as _complete_removal,
    release_participant_operation as _release_participant_operation,
)
from hydra.services.managed_nodes.removal_records import begin_removal as _begin_removal
from hydra.utils.commands import redact_text

T = TypeVar("T")
StateReader = Callable[[], AppState]
StateUpdater = Callable[[Callable[[AppState], T]], tuple[AppState, T]]


class ManagedNodeRecords:
    """Persist desired definitions and operation receipts through state APIs only."""

    def __init__(self, *, state_reader: StateReader, state_updater: StateUpdater) -> None:
        self._state_reader = state_reader
        self._state_updater = state_updater

    def read_namespace(self) -> ManagedNodesState:
        return managed_nodes_from_extensions(self._state_reader().feature_extensions)

    def list_definitions(self) -> list[NodeDefinition]:
        return copy.deepcopy(self.read_namespace().definitions)

    def find_definition(self, node_id: str) -> NodeDefinition | None:
        return next((copy.deepcopy(item) for item in self.read_namespace().definitions if item.id == node_id), None)

    def find_cascade(self, cascade_id: str):
        return next((copy.deepcopy(item) for item in self.read_namespace().cascades if item.id == cascade_id), None)

    def put_cascade(self, cascade):
        cascade.validate()
        if cascade.id == "base":
            raise ValueError("cascade id 'base' is reserved")

        def mutate(state: AppState):
            namespace = managed_nodes_from_extensions(state.feature_extensions)
            cascade_leases.assert_cascade_definition_unleased(namespace, cascade)
            if cascade.entry_id != "base" and not any(item.id == cascade.entry_id for item in namespace.definitions):
                raise ValueError("cascade entry is not an enrolled managed node")
            if cascade.exit_id != "base" and not any(item.id == cascade.exit_id for item in namespace.definitions):
                raise ValueError("cascade exit is not an enrolled managed node")
            if any(
                item.id != cascade.id and item.name.casefold() == cascade.name.casefold() for item in namespace.cascades
            ):
                raise ValueError("cascade names must be unique in subscriptions")
            existing = next((item for item in namespace.cascades if item.id == cascade.id), None)
            if existing is None:
                namespace.cascades.append(copy.deepcopy(cascade))
            else:
                namespace.cascades[namespace.cascades.index(existing)] = copy.deepcopy(cascade)
            store_managed_nodes(state.feature_extensions, namespace)
            return copy.deepcopy(cascade)

        _, result = self._state_updater(mutate)
        return result

    def rename_cascade(self, cascade_id: str, name: str):
        from dataclasses import replace

        current = self.find_cascade(cascade_id)
        if current is None:
            raise KeyError(f"unknown managed-node cascade {cascade_id}")
        updated = replace(current, name=name)
        updated.validate()
        return self.put_cascade(updated)

    def commit_cascade_operation(self, operation_id: str, cascade) -> Operation:
        """Atomically persist cascade desired state and its confirmed operation."""

        def mutate(state: AppState) -> Operation:
            namespace = managed_nodes_from_extensions(state.feature_extensions)
            operation = next((item for item in namespace.operations if item.id == operation_id), None)
            if operation is None or operation.kind not in {"cascade_save", "cascade_remove"}:
                raise KeyError(f"unknown managed-node cascade operation {operation_id}")
            candidate = cascade_leases.cascade_candidate(operation)
            if candidate != cascade:
                raise ValueError("cascade commit differs from its immutable operation intent")
            cascade_leases.assert_cascade_commit_ready(operation)
            if cascade is None:
                namespace.cascades[:] = [item for item in namespace.cascades if item.id != operation.target_id]
            else:
                existing = next((item for item in namespace.cascades if item.id == cascade.id), None)
                if existing is None:
                    namespace.cascades.append(copy.deepcopy(cascade))
                else:
                    namespace.cascades[namespace.cascades.index(existing)] = copy.deepcopy(cascade)
            result = Operation(
                operation.id,
                operation.kind,
                operation.target_id,
                operation.desired_digest,
                "succeeded",
                list(operation.completed_steps) + ["confirmed"],
                None,
                operation.receipt,
                operation.plan,
                operation.remote_removal_confirmed,
                None,
                operation.existing_reinstall_confirmed,
            )
            namespace.operations[namespace.operations.index(operation)] = result
            store_managed_nodes(state.feature_extensions, namespace)
            return copy.deepcopy(result)

        _, result = self._state_updater(mutate)
        return result

    def put_definition(self, definition: NodeDefinition) -> NodeDefinition:
        definition.validate()

        def mutate(state: AppState) -> NodeDefinition:
            namespace = managed_nodes_from_extensions(state.feature_extensions)
            cascade_leases.assert_node_unleased(namespace, definition.id)
            existing = next((item for item in namespace.definitions if item.id == definition.id), None)
            if existing is None:
                namespace.definitions.append(copy.deepcopy(definition))
            else:
                namespace.definitions[namespace.definitions.index(existing)] = copy.deepcopy(definition)
            store_managed_nodes(state.feature_extensions, namespace)
            return copy.deepcopy(definition)

        _, result = self._state_updater(mutate)
        return result

    def begin_apply_operation(self, operation_id: str, desired: NodeDesired) -> Operation:
        """Atomically persist a frozen apply operation and its desired payload."""
        desired.validate()
        operation = Operation(
            operation_id,
            "apply",
            desired.node_id,
            desired.digest,
            "pending",
            plan=desired.to_document(),
        )
        operation.validate()

        def mutate(state: AppState) -> Operation:
            namespace = managed_nodes_from_extensions(state.feature_extensions)
            self._store_apply_operation(namespace, operation, desired)
            store_managed_nodes(state.feature_extensions, namespace)
            return copy.deepcopy(operation)

        _, result = self._state_updater(mutate)
        return result

    def begin_protocol_apply(
        self,
        node_id: str,
        assignment: ProtocolAssignment,
        operation_id: str,
    ) -> tuple[NodeDefinition, NodeDesired, Operation]:
        """CAS node protocol, current user projection and apply intent together."""
        assignment.validate()

        def mutate(state: AppState) -> tuple[NodeDefinition, NodeDesired, Operation]:
            from dataclasses import replace

            from hydra.services.managed_nodes.access import assignment_from_user
            from hydra.services.managed_nodes.accounting import traffic_reset_epoch

            namespace = managed_nodes_from_extensions(state.feature_extensions)
            definition = next((item for item in namespace.definitions if item.id == node_id), None)
            if definition is None:
                raise KeyError(f"unknown managed node {node_id}")
            if any(node_id in {item.entry_id, item.exit_id} for item in namespace.cascades):
                raise ValueError("remove or reconfigure affected cascades before changing this node")
            if any(
                item.target_id == node_id
                and (item.state in {"pending", "running", "recovery_required"} or item.active_step is not None)
                for item in namespace.operations
            ):
                raise ValueError("managed-node target already has an active operation")

            protocols = [item for item in definition.protocols if item.name != assignment.name]
            protocols.append(copy.deepcopy(assignment))
            updated = replace(definition, protocols=protocols)
            updated.validate()
            previous = next(
                (
                    item.receipt
                    for item in reversed(namespace.operations)
                    if item.target_id == node_id and item.state == "succeeded" and item.receipt is not None
                ),
                None,
            )
            revision = previous.desired_revision if previous is not None else 1
            users = [assignment_from_user(user, reset_epoch=traffic_reset_epoch(state, user)) for user in state.users]
            desired = NodeDesired(node_id, revision, users, list(updated.protocols))
            if previous is not None and desired.digest != previous.desired_digest:
                desired = NodeDesired(node_id, revision + 1, users, list(updated.protocols))
            desired.validate()
            operation = Operation(
                operation_id,
                "apply",
                node_id,
                desired.digest,
                "pending",
                plan=desired.to_document(),
            )
            operation.validate()
            self._store_apply_operation(namespace, operation, desired)
            namespace.definitions[namespace.definitions.index(definition)] = copy.deepcopy(updated)
            store_managed_nodes(state.feature_extensions, namespace)
            return copy.deepcopy((updated, desired, operation))

        _, result = self._state_updater(mutate)
        return result

    @staticmethod
    def _store_apply_operation(
        namespace: ManagedNodesState,
        operation: Operation,
        desired: NodeDesired,
    ) -> None:
        existing = next((item for item in namespace.operations if item.id == operation.id), None)
        if existing is not None:
            if existing != operation or namespace.apply_intents.get(operation.id) != desired:
                raise ValueError("same operation id cannot be reused with different apply content")
            return
        cascade_leases.assert_operation_unleased(namespace, operation)
        if any(
            item.target_id == operation.target_id
            and (item.state in {"pending", "running", "recovery_required"} or item.active_step is not None)
            for item in namespace.operations
        ):
            raise ValueError("managed-node target already has an active operation")
        namespace.operations.append(copy.deepcopy(operation))
        namespace.apply_intents[operation.id] = copy.deepcopy(desired)

    def begin_operation(self, operation: Operation) -> Operation:
        operation.validate()

        def mutate(state: AppState) -> Operation:
            namespace = managed_nodes_from_extensions(state.feature_extensions)
            existing = next((item for item in namespace.operations if item.id == operation.id), None)
            if existing is not None:
                if (
                    existing.kind != operation.kind
                    or existing.target_id != operation.target_id
                    or existing.desired_digest != operation.desired_digest
                    or existing.plan != operation.plan
                ):
                    raise ValueError("same operation id cannot be reused with different content")
                return copy.deepcopy(existing)
            cascade_leases.assert_operation_unleased(namespace, operation)
            if any(
                item.target_id == operation.target_id
                and (item.state in {"pending", "running", "recovery_required"} or item.active_step is not None)
                for item in namespace.operations
            ):
                raise ValueError("managed-node target already has an active operation")
            namespace.operations.append(copy.deepcopy(operation))
            store_managed_nodes(state.feature_extensions, namespace)
            return copy.deepcopy(operation)

        _, result = self._state_updater(mutate)
        return result

    def release_participant_operation(
        self, operation_id: str, plan_digest: str, participant_id: str, *, terminal_state: str
    ) -> None:
        _release_participant_operation(self._state_updater, operation_id, plan_digest, participant_id, terminal_state)

    def begin_removal(self, operation: Operation, *, installation: Operation) -> Operation:
        return _begin_removal(self._state_updater, operation, installation=installation)

    def find_operation(self, operation_id: str) -> Operation | None:
        return next((copy.deepcopy(item) for item in self.read_namespace().operations if item.id == operation_id), None)

    def find_apply_intent(self, operation_id: str) -> NodeDesired | None:
        desired = self.read_namespace().apply_intents.get(operation_id)
        return copy.deepcopy(desired) if desired is not None else None

    def store_apply_intent(self, operation_id: str, desired: NodeDesired) -> NodeDesired:
        desired.validate()

        def mutate(state: AppState) -> NodeDesired:
            namespace = managed_nodes_from_extensions(state.feature_extensions)
            operation = next((item for item in namespace.operations if item.id == operation_id), None)
            if (
                operation is None
                or operation.kind not in {"install", "apply"}
                or operation.target_id != desired.node_id
            ):
                raise ValueError("apply intent must match an install or apply operation")
            if operation.state not in {"pending", "running", "recovery_required"}:
                raise ValueError("managed-node apply operation is not active")
            cascade_leases.assert_node_unleased(namespace, desired.node_id)
            current = namespace.apply_intents.get(operation_id)
            if current is not None and current != desired:
                raise ValueError("install apply intent is immutable")
            namespace.apply_intents[operation_id] = copy.deepcopy(desired)
            store_managed_nodes(state.feature_extensions, namespace)
            return copy.deepcopy(desired)

        _, result = self._state_updater(mutate)
        return result

    def list_operations(self) -> list[Operation]:
        return copy.deepcopy(self.read_namespace().operations)

    def update_operation(self, operation: Operation) -> Operation:
        operation.validate()

        def mutate(state: AppState) -> Operation:
            namespace = managed_nodes_from_extensions(state.feature_extensions)
            existing = next((item for item in namespace.operations if item.id == operation.id), None)
            if existing is None:
                raise KeyError(f"unknown managed-node operation {operation.id}")
            self._validate_operation_progress(existing, operation)
            cascade_leases.assert_cascade_transition(existing, operation)
            namespace.operations[namespace.operations.index(existing)] = copy.deepcopy(operation)
            store_managed_nodes(state.feature_extensions, namespace)
            return copy.deepcopy(operation)

        _, result = self._state_updater(mutate)
        return result

    @staticmethod
    def _validate_operation_progress(current: Operation, updated: Operation) -> None:
        if current.error and current.error.get("stage") == "removal" and updated != current:
            raise ValueError("managed-node operation was superseded by removal")
        if (current.kind, current.target_id, current.desired_digest, current.plan) != (
            updated.kind,
            updated.target_id,
            updated.desired_digest,
            updated.plan,
        ):
            raise ValueError("managed-node operation identity and plan are immutable")
        if current.state == "succeeded" and updated != current:
            raise ValueError("succeeded managed-node operations are immutable")
        if (
            updated.state
            not in {
                "pending": {"pending", "running", "failed", "recovery_required"},
                "running": {"running", "succeeded", "failed", "recovery_required"},
                "failed": {"failed", "running", "recovery_required"},
                "recovery_required": {"recovery_required", "running", "succeeded", "failed"},
                "succeeded": {"succeeded"},
            }[current.state]
        ):
            raise ValueError(f"invalid managed-node operation transition {current.state} -> {updated.state}")
        if updated.completed_steps[: len(current.completed_steps)] != current.completed_steps:
            raise ValueError("completed operation steps cannot be removed or reordered")
        if current.remote_removal_confirmed and not updated.remote_removal_confirmed:
            raise ValueError("remote removal confirmation cannot be cleared")
        if current.receipt is not None and updated.receipt != current.receipt:
            raise ValueError("confirmed apply receipt is immutable")
        if current.existing_reinstall_confirmed and not updated.existing_reinstall_confirmed:
            raise ValueError("existing-installation consent cannot be cleared")

    def begin_step(self, operation_id: str, step: str) -> Operation:
        current = self.find_operation(operation_id)
        if current is None:
            raise KeyError(f"unknown managed-node operation {operation_id}")
        if step in current.completed_steps:
            return current
        if current.active_step is not None and current.active_step != step:
            raise ValueError("managed-node operation has an unresolved active step")
        updated = copy.deepcopy(current)
        updated = Operation(
            updated.id,
            updated.kind,
            updated.target_id,
            updated.desired_digest,
            "running",
            list(updated.completed_steps),
            None,
            updated.receipt,
            updated.plan,
            updated.remote_removal_confirmed,
            step,
            updated.existing_reinstall_confirmed,
        )
        return self.update_operation(updated)

    def fail_operation(self, operation_id: str, *, stage: str, reason: str, recovery_required: bool) -> Operation:
        current = self.find_operation(operation_id)
        if current is None:
            raise KeyError(f"unknown managed-node operation {operation_id}")
        updated = Operation(
            current.id,
            current.kind,
            current.target_id,
            current.desired_digest,
            "recovery_required" if recovery_required else "failed",
            list(current.completed_steps),
            {"stage": stage[:64], "reason": _safe_reason(reason)},
            current.receipt,
            current.plan,
            current.remote_removal_confirmed,
            current.active_step,
            current.existing_reinstall_confirmed,
        )
        return self.update_operation(updated)

    def confirm_remote_removal(self, operation_id: str) -> Operation:
        current = self.find_operation(operation_id)
        if current is None or current.kind != "remove":
            raise KeyError(f"unknown managed-node removal operation {operation_id}")
        if current.remote_removal_confirmed:
            return current
        return self.update_operation(
            Operation(
                current.id,
                current.kind,
                current.target_id,
                current.desired_digest,
                "recovery_required",
                list(current.completed_steps),
                current.error,
                current.receipt,
                current.plan,
                True,
                current.active_step,
                current.existing_reinstall_confirmed,
            )
        )

    def complete_step(self, operation_id: str, step: str) -> Operation:
        current = self.find_operation(operation_id)
        if current is None:
            raise KeyError(f"unknown managed-node operation {operation_id}")
        if step in current.completed_steps:
            return current
        if current.active_step is not None and current.active_step != step:
            raise ValueError("completed step does not match the active operation step")
        completed = list(current.completed_steps) + [step]
        updated = Operation(
            current.id,
            current.kind,
            current.target_id,
            current.desired_digest,
            "running",
            completed,
            None,
            current.receipt,
            current.plan,
            current.remote_removal_confirmed,
            None,
            current.existing_reinstall_confirmed,
        )
        return self.update_operation(updated)

    def complete_removal(self, operation_id: str) -> bool:
        return _complete_removal(self._state_updater, operation_id)


def _safe_reason(reason: str) -> str:
    text = redact_text(str(reason))
    return "".join(char for char in text if char.isprintable())[:256]


__all__ = ["ManagedNodeRecords", "StateReader", "StateUpdater"]
