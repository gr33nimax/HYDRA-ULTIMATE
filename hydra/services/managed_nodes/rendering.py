"""Production adapters for ephemeral managed-node render contributions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from hydra.contracts import RuntimeRenderContributions, RuntimeSubject
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.contracts.managed_node_cascade import CascadeParticipantRequest
from hydra.contracts.managed_node_models import CascadeDefinition
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext
from hydra.services.managed_nodes.cascade_preparation import ManagedNodeCascadePreparationOwner
from hydra.services.managed_nodes.cascade_rendering import (
    ManagedNodeCascadeRenderer,
    TechnicalPeerMaterialProvider,
)
from hydra.services.managed_nodes.probe_clients import ManagedNodeProbeIdentityStore

_PROBE_PROTOCOLS = ("vless", "anytls")


@dataclass(frozen=True)
class ProductionRuntimeContributions:
    """Canonical transient renderer with a route-scoped pre-effect capture port."""

    cascades: ManagedNodeCascadeRenderer
    probe_identity: ManagedNodeProbeIdentityStore | None = None

    def __call__(self, state: AppState) -> RuntimeRenderContributions:
        cascade = self.cascades.render(state)
        probes = tuple(
            RuntimeSubject(user.email, user.uuid, _PROBE_PROTOCOLS)
            for user in (self.probe_identity.runtime_users() if self.probe_identity is not None else ())
        )
        return RuntimeRenderContributions(probes + cascade.users, cascade.fragments)

    def capture_cascade_scope(
        self,
        state: AppState,
        request: CascadeParticipantRequest,
        previous: CascadeDefinition | None,
    ) -> CascadeRestoreContext:
        return self.cascades.capture_scope(state, request, previous)


def production_runtime_contributions(
    *,
    host: HostBackend,
    root: Path,
    probe_identity: ManagedNodeProbeIdentityStore | None = None,
    preparation_owner: ManagedNodeCascadePreparationOwner | None = None,
    technical_peer_material_provider: TechnicalPeerMaterialProvider | None = None,
    participant_store: CascadeParticipantStore | None = None,
) -> Callable[[AppState], RuntimeRenderContributions]:
    """Wire read-only cascade rendering and technical probes into production."""
    credentials = CascadeCredentialStore(host=host, root=root / "cascade-credentials")
    cascades = ManagedNodeCascadeRenderer(
        participant_id=probe_identity.node_id if probe_identity is not None else "base",
        credentials=credentials,
        technical_preparation_provider=(
            preparation_owner.preparations_for_render if preparation_owner is not None else None
        ),
        technical_peer_material_provider=technical_peer_material_provider,
        restore_context_provider=(participant_store.restoration_contexts if participant_store is not None else None),
    )
    return ProductionRuntimeContributions(cascades, probe_identity)


__all__ = ["production_runtime_contributions"]
