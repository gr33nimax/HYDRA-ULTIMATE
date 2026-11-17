"""Atomic takeover and local completion of confirmed node removal intents."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import replace

from hydra.contracts.managed_node_installation import InstallPlan
from hydra.contracts.managed_node_models import NodeDefinition, Operation, canonical_digest
from hydra.core.state_managed_nodes import managed_nodes_from_extensions, store_managed_nodes
from hydra.core.state_models import AppState
from hydra.services.managed_nodes import cascade_leases

StateUpdater = Callable[[Callable[[AppState], Operation]], tuple[AppState, Operation]]


def forget_definition(operation: Operation) -> NodeDefinition:
    """Validate a local-only removal intent without claiming remote cleanup."""
    if (
        operation.kind != "forget" or not isinstance(operation.plan, dict)
        or set(operation.plan) != {"definition"}
        or operation.desired_digest != canonical_digest(operation.plan)
        or operation.remote_removal_confirmed
    ):
        raise ValueError("invalid local node removal intent")
    definition = NodeDefinition.from_document(operation.plan["definition"])
    if definition.id != operation.target_id:
        raise ValueError("local removal target differs from its definition")
    return definition


def begin_forget(state_updater: StateUpdater, operation: Operation) -> Operation:
    operation.validate()
    definition = forget_definition(operation)
    if operation.state != "pending":
        raise ValueError("local node removal must start pending")

    def mutate(state: AppState) -> Operation:
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        current = next((item for item in namespace.definitions if item.id == definition.id), None)
        if current != definition:
            raise ValueError("node changed while preparing local removal; retry with current state")
        if any(definition.id in {item.entry_id, item.exit_id} for item in namespace.cascades):
            raise ValueError("managed-node cascades must be removed before deleting a participant")
        cascade_leases.assert_node_unleased(namespace, definition.id)
        if any(item.id == operation.id for item in namespace.operations):
            raise ValueError("removal operation id is already in use")
        for index, current in enumerate(namespace.operations):
            if current.target_id != definition.id or current.state == "succeeded":
                continue
            if current.kind not in {"install", "apply", "remove"}:
                raise ValueError("managed-node target already has another operation; resume it first")
            namespace.operations[index] = replace(
                current, state="failed", active_step=None,
                error={"stage": "removal", "reason": f"superseded by local removal {operation.id}"},
            )
        namespace.operations.append(copy.deepcopy(operation))
        store_managed_nodes(state.feature_extensions, namespace)
        return copy.deepcopy(operation)

    _, result = state_updater(mutate)
    return result


def complete_forget(state_updater: StateUpdater, operation_id: str) -> Operation:
    def mutate(state: AppState) -> Operation:
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        operation = next((item for item in namespace.operations if item.id == operation_id), None)
        if operation is None:
            raise KeyError(operation_id)
        definition = forget_definition(operation)
        if operation.state == "succeeded":
            return copy.deepcopy(operation)
        if "credential_cleanup" not in operation.completed_steps or operation.active_step is not None:
            raise ValueError("local credential cleanup must complete before forgetting a node")
        current = next((item for item in namespace.definitions if item.id == definition.id), None)
        if current != definition:
            raise ValueError("node changed during local removal")
        if any(definition.id in {item.entry_id, item.exit_id} for item in namespace.cascades):
            raise ValueError("managed-node cascades must be removed before deleting a participant")
        cascade_leases.assert_node_unleased(namespace, definition.id)
        namespace.definitions.remove(current)
        for key, desired in list(namespace.apply_intents.items()):
            if desired.node_id == definition.id:
                del namespace.apply_intents[key]
        result = replace(operation, state="succeeded", error=None)
        namespace.operations[namespace.operations.index(operation)] = result
        store_managed_nodes(state.feature_extensions, namespace)
        return copy.deepcopy(result)

    _, result = state_updater(mutate)
    return result


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

