"""Build the complete per-node projection from current base users and definition."""

from __future__ import annotations

from hydra.contracts.managed_node_models import NodeDefinition, NodeDesired
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.access import assignment_from_user
from hydra.services.managed_nodes.accounting import traffic_reset_epoch
from hydra.services.managed_nodes.records import ManagedNodeRecords


def build_node_desired(
    definition: NodeDefinition,
    state: AppState,
    records: ManagedNodeRecords,
) -> NodeDesired:
    previous = next(
        (
            operation.receipt
            for operation in reversed(records.list_operations())
            if operation.target_id == definition.id and operation.state == "succeeded" and operation.receipt is not None
        ),
        None,
    )
    revision = previous.desired_revision if previous is not None else 1
    users = [
        assignment_from_user(user, reset_epoch=traffic_reset_epoch(state, user))
        for user in state.users
    ]
    cascades = [route for route in records.read_namespace().cascades if definition.id in {route.entry_id, route.exit_id}]
    candidate = NodeDesired(
        node_id=definition.id,
        revision=revision,
        users=users,
        protocols=list(definition.protocols),
        cascades=cascades,
    )
    if previous is not None and candidate.digest != previous.desired_digest:
        candidate = NodeDesired(
            node_id=definition.id,
            revision=revision + 1,
            users=users,
            protocols=list(definition.protocols),
            cascades=cascades,
        )
    candidate.validate()
    return candidate


__all__ = ["build_node_desired"]
