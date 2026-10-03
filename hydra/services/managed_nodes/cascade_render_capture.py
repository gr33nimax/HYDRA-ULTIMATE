"""Capture one confirmed route contribution for a participant recovery artifact."""

from __future__ import annotations

from collections.abc import Callable

from hydra.contracts import ConfigFragment, RuntimeSubject
from hydra.contracts.managed_node_cascade import CascadeParticipantRequest
from hydra.contracts.managed_node_models import CascadeDefinition
from hydra.core.state_managed_nodes import managed_nodes_from_extensions
from hydra.core.state_models import AppState
from hydra.services.user_access import access_status
from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext


def capture_cascade_scope(
    state: AppState,
    request: CascadeParticipantRequest,
    route: CascadeDefinition | None,
    *,
    role_for: Callable[[CascadeDefinition], str | None],
    render_confirmed: Callable[..., None],
) -> CascadeRestoreContext:
    """Capture only the previous route/protocol contribution through its canonical renderer."""
    request.validate()
    if route is None:
        return CascadeRestoreContext.empty(request)
    if route.id != request.target_id:
        raise ValueError("cascade restore route differs from the frozen participant operation")
    if request.protocol not in route.protocols:
        return CascadeRestoreContext.empty(request)
    namespace = managed_nodes_from_extensions(state.feature_extensions)
    users: list[RuntimeSubject] = []
    fragment = ConfigFragment()
    if role_for(route) is not None:
        render_confirmed(
            state,
            (route,),
            {item.id for item in namespace.definitions},
            users,
            fragment,
            protocols={request.protocol},
        )
    business_user_uuids = (
        tuple(
            user.uuid
            for user in state.users
            if access_status(user)[0] and request.protocol not in user.disabled_protocols
        )
        if users
        else ()
    )
    if len(business_user_uuids) != len(users):
        raise ValueError("captured cascade subjects differ from current business users")
    context = CascadeRestoreContext(
        route.id,
        route.entry_id,
        route.exit_id,
        request.operation_id,
        request.plan_digest,
        request.participant_id,
        request.protocol,
        business_user_uuids,
        tuple(users),
        fragment,
    )
    context.validate_for(request)
    return context


__all__ = ["capture_cascade_scope"]
