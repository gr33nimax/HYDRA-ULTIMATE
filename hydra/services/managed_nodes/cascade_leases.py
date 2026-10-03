"""Derive participant exclusion from immutable active cascade operation plans."""

from __future__ import annotations

from hydra.contracts.managed_node_models import CascadeDefinition, Operation, canonical_digest
from hydra.core.state_managed_nodes import ManagedNodesState


_ACTIVE = frozenset({"pending", "running", "recovery_required"})
_CASCADE_KINDS = frozenset({"cascade_save", "cascade_remove"})


def operation_is_active(operation: Operation) -> bool:
    return operation.state in _ACTIVE or operation.active_step is not None


def cascade_routes(operation: Operation) -> tuple[CascadeDefinition, ...]:
    """Decode and verify participant topology from a frozen cascade operation."""
    if operation.kind not in _CASCADE_KINDS or not isinstance(operation.plan, dict):
        raise ValueError("cascade lease has no immutable plan")
    if operation.desired_digest != canonical_digest(operation.plan):
        raise ValueError("cascade lease plan digest is invalid")
    plan = operation.plan
    if set(plan) != {"cascade_id", "previous", "cascade"}:
        raise ValueError("cascade lease plan has an invalid shape")
    if plan.get("cascade_id") != operation.target_id:
        raise ValueError("cascade lease target does not match its plan")
    routes = []
    for key in ("previous", "cascade"):
        raw = plan.get(key)
        if raw is None:
            continue
        route = CascadeDefinition.from_document(raw)
        if route.id != operation.target_id:
            raise ValueError("cascade lease route does not match its target")
        routes.append(route)
    if not routes:
        raise ValueError("cascade lease has no participant topology")
    if operation.kind == "cascade_save" and plan.get("cascade") is None:
        raise ValueError("cascade save lease has no candidate")
    if operation.kind == "cascade_remove" and plan.get("cascade") is not None:
        raise ValueError("cascade removal lease unexpectedly has a candidate")
    return tuple(routes)


def cascade_candidate(operation: Operation) -> CascadeDefinition | None:
    plan = operation.plan
    cascade_routes(operation)
    if not isinstance(plan, dict):
        raise ValueError("cascade lease has no immutable plan")
    raw = plan["cascade"]
    return CascadeDefinition.from_document(raw) if raw is not None else None


def cascade_participants(operation: Operation) -> frozenset[str]:
    return frozenset(
        participant for route in cascade_routes(operation) for participant in (route.entry_id, route.exit_id)
    )


def assert_node_unleased(namespace: ManagedNodesState, node_id: str) -> None:
    for operation in namespace.operations:
        if operation.kind in _CASCADE_KINDS and operation_is_active(operation):
            if node_id in cascade_participants(operation):
                raise ValueError(f"managed-node participant {node_id!r} is leased by an active cascade")


def assert_cascade_unleased(
    namespace: ManagedNodesState,
    operation: Operation,
) -> None:
    candidate_participants = cascade_participants(operation)
    for current in namespace.operations:
        if current.id == operation.id or not operation_is_active(current):
            continue
        if current.kind in _CASCADE_KINDS:
            if current.target_id == operation.target_id or candidate_participants & cascade_participants(current):
                raise ValueError("cascade participants or route are already leased by an active operation")
        elif current.target_id == operation.target_id or current.target_id in candidate_participants:
            raise ValueError("cascade participant is already leased by an active operation")


def assert_cascade_definition_unleased(namespace: ManagedNodesState, cascade: CascadeDefinition) -> None:
    for participant_id in (cascade.entry_id, cascade.exit_id):
        assert_node_unleased(namespace, participant_id)
    if any(
        operation.kind in _CASCADE_KINDS and operation.target_id == cascade.id and operation_is_active(operation)
        for operation in namespace.operations
    ):
        raise ValueError("cascade route is leased by an active operation")


def assert_cascade_commit_ready(operation: Operation) -> None:
    if (
        operation.kind not in _CASCADE_KINDS
        or not operation_is_active(operation)
        or "profiles" not in operation.completed_steps
    ):
        raise ValueError("cascade commit requires an active operation with completed profile verification")


def assert_cascade_transition(current: Operation, updated: Operation) -> None:
    if current.kind in _CASCADE_KINDS and updated.state == "succeeded":
        raise ValueError("cascade operations can succeed only through atomic cascade commit")


def assert_operation_unleased(namespace: ManagedNodesState, operation: Operation) -> None:
    if operation.kind in _CASCADE_KINDS:
        assert_cascade_unleased(namespace, operation)
    else:
        assert_node_unleased(namespace, operation.target_id)


__all__ = [
    "assert_cascade_commit_ready",
    "assert_cascade_definition_unleased",
    "assert_cascade_transition",
    "assert_node_unleased",
    "assert_operation_unleased",
    "cascade_candidate",
    "cascade_participants",
    "cascade_routes",
    "operation_is_active",
]
