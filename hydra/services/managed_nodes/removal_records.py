"""Atomic takeover of incomplete node work by confirmed remote removal."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import replace

from hydra.contracts.managed_node_installation import InstallPlan
from hydra.contracts.managed_node_models import Operation, canonical_digest
from hydra.core.state_managed_nodes import managed_nodes_from_extensions, store_managed_nodes
from hydra.core.state_models import AppState
from hydra.services.managed_nodes import cascade_leases


def begin_removal(
    state_updater: Callable[[Callable[[AppState], Operation]], tuple[AppState, Operation]],
    operation: Operation,
    *,
    installation: Operation,
) -> Operation:
    """Atomically replace unfinished install/apply work with confirmed removal."""
    operation.validate()
    plan = InstallPlan.from_document(installation.plan)
    if (
        operation.kind != "remove" or operation.state != "pending"
        or installation.kind != "install"
        or installation.target_id != operation.target_id
        or plan.definition.id != operation.target_id
        or operation.plan != {"installation": plan.to_document()}
        or installation.desired_digest != canonical_digest(plan.to_document())
        or operation.desired_digest != installation.desired_digest
        or not plan.host_key_fingerprint
    ):
        raise ValueError("removal must use the node's pinned installation plan")

    def mutate(state: AppState) -> Operation:
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        definition = next((item for item in namespace.definitions if item.id == operation.target_id), None)
        if definition is None:
            raise KeyError(f"unknown managed node {operation.target_id}")
        if any(operation.target_id in {item.entry_id, item.exit_id} for item in namespace.cascades):
            raise ValueError("managed-node cascades must be removed before deleting a participant")
        cascade_leases.assert_operation_unleased(namespace, operation)
        latest_install = next(
            (item for item in reversed(namespace.operations)
             if item.kind == "install" and item.target_id == operation.target_id), None,
        )
        if latest_install != installation:
            raise ValueError("installation changed while preparing removal; retry with current state")
        for name in ("id", "address", "ssh_user", "ssh_port", "identity_ref"):
            if getattr(definition, name) != getattr(plan.definition, name):
                raise ValueError("removal plan does not match the registered node identity")
        if any(item.id == operation.id for item in namespace.operations):
            raise ValueError("removal operation id is already in use")
        for index, current in enumerate(namespace.operations):
            if current.target_id != operation.target_id or current.state == "succeeded":
                continue
            if current.kind not in {"install", "apply"}:
                raise ValueError("managed-node target already has another operation; resume it first")
            namespace.operations[index] = replace(
                current, state="failed", active_step=None,
                error={"stage": "removal", "reason": f"superseded by removal {operation.id}"},
            )
        namespace.operations.append(copy.deepcopy(operation))
        store_managed_nodes(state.feature_extensions, namespace)
        return copy.deepcopy(operation)

    _, result = state_updater(mutate)
    return result

