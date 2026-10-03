"""Read-only relay of already prepared, route-scoped participant material."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from hydra.contracts.managed_node_cascade import CascadeParticipantRequest, CascadeTechnicalMaterial
from hydra.core.state_models import AppState, User
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_preparation import CascadeTechnicalPreparation
from hydra.services.managed_nodes.cascade_rendering import CascadeTechnicalPeerMaterial


def transit_request(request: CascadeParticipantRequest) -> CascadeParticipantRequest:
    if request.participant_id == request.route.exit_id:
        return request
    return CascadeParticipantRequest(
        request.operation_id,
        request.kind,
        request.target_id,
        request.plan_digest,
        request.plan,
        request.route.exit_id,
        "transit",
        request.route,
        request.protocol,
    )


def technical_peer_provider(
    store: CascadeParticipantStore,
    participant_id: str,
) -> Callable[[AppState, CascadeTechnicalPreparation, User], CascadeTechnicalPeerMaterial | None]:
    """Read only protected exit material already relayed through the coordinator."""

    def provide(_state: AppState, preparation: CascadeTechnicalPreparation, transit_user: User):
        request = store.request_for(preparation.operation_id, participant_id, preparation.protocol)
        if request is None or request.role != "entry":
            return None
        try:
            record = store.record(request)
            if record is None or record["phase"] not in {"prepared", "applying", "applied"}:
                return None
            material = CascadeTechnicalMaterial.from_document(record["material"])
            material.validate_for(transit_request(request))
            peer = CascadeTechnicalPeerMaterial(
                preparation.route.id,
                preparation.route.entry_id,
                preparation.route.exit_id,
                preparation.route.exit_id,
                "transit",
                preparation.protocol,
                preparation.operation_id,
                preparation.plan_digest,
                material.receipt.engine_identity,
                material.receipt.config_identity,
                material.outbound,
            )
            peer.validate_for(preparation, transit_user)
            return peer
        except (KeyError, OSError, TypeError, ValueError):
            return None

    return provide


__all__ = ["technical_peer_provider"]
