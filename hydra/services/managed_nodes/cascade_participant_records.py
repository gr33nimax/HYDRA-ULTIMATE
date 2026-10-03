"""Atomic state transitions for participant-only recovery and confirmed removal."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from hydra.contracts.managed_node_models import Operation
from hydra.core.state_managed_nodes import (
    ManagedNodesState,
    managed_nodes_from_extensions,
    store_managed_nodes,
)
from hydra.core.state_models import AppState
from hydra.services.managed_nodes import cascade_leases

T = TypeVar("T")
StateUpdater = Callable[[Callable[[AppState], T]], tuple[AppState, T]]


def release_participant_operation(
    state_updater: StateUpdater,
    operation_id: str,
    plan_digest: str,
    participant_id: str,
    terminal_state: str,
) -> None:
    """Release an exact local participant lease after confirmed rollback/finalize."""
    if terminal_state not in {"rolled_back", "finalized"}:
        raise ValueError("cascade participant lease release is not confirmed")

    def mutate(state: AppState) -> None:
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        operation = next((item for item in namespace.operations if item.id == operation_id), None)
        if operation is None:
            return
        if (
            operation.kind not in {"cascade_save", "cascade_remove"}
            or operation.desired_digest != plan_digest
            or participant_id not in cascade_leases.cascade_participants(operation)
            or not cascade_leases.operation_is_active(operation)
        ):
            raise ValueError("cascade participant lease differs from its confirmed transaction")
        namespace.operations.remove(operation)
        store_managed_nodes(state.feature_extensions, namespace)

    state_updater(mutate)


def complete_removal(state_updater: StateUpdater, operation_id: str) -> bool:
    """Finish local deletion only after a durable remote-uninstall receipt."""

    def mutate(state: AppState) -> bool:
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        operation = next((item for item in namespace.operations if item.id == operation_id), None)
        if operation is None or operation.kind != "remove" or not operation.remote_removal_confirmed:
            return False
        if operation.state == "succeeded":
            return not any(item.id == operation.target_id for item in namespace.definitions)
        if any(operation.target_id in {item.entry_id, item.exit_id} for item in namespace.cascades):
            raise ValueError("managed-node cascade cleanup must complete before local removal")
        updated = ManagedNodesState(
            definitions=[item for item in namespace.definitions if item.id != operation.target_id],
            cascades=namespace.cascades,
            operations=list(namespace.operations),
            apply_intents=dict(namespace.apply_intents),
        )
        updated.operations[updated.operations.index(operation)] = Operation(
            operation.id,
            operation.kind,
            operation.target_id,
            operation.desired_digest,
            "succeeded",
            operation.completed_steps,
            operation.error,
            operation.receipt,
            operation.plan,
            True,
            None,
            operation.existing_reinstall_confirmed,
        )
        store_managed_nodes(state.feature_extensions, updated)
        return True

    _, result = state_updater(mutate)
    return result


__all__ = ["complete_removal", "release_participant_operation"]
