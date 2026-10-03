"""Managed-node and plugin assembly helpers used only by the production root."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any, Callable

from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.plugins.container import PluginContainer
from hydra.plugins.defaults import PluginFactory, default_plugins
from hydra.services.managed_nodes import cascade_preparation
from hydra.services.managed_nodes.apply_gate import AuthenticatedParticipant, ManagedNodeApplyGate
from hydra.services.managed_nodes.cascade_participant import technical_peer_provider
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_preparation import ManagedNodeCascadePreparationOwner
from hydra.services.managed_nodes.cascade_rendering import TechnicalPeerMaterialProvider
from hydra.services.managed_nodes.probe_clients import ManagedNodeProbeIdentityStore
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.rendering import production_runtime_contributions
from hydra.services.security_intel import notification_fields
from hydra.services.security_notifications import notify_security_event


def preparation_owner(
    *,
    host: HostBackend,
    root: Path,
    records: ManagedNodeRecords,
    state_reader: Callable[[], AppState],
    participant_id: str,
    evidence_provider: cascade_preparation.EvidenceProvider | None,
    participant_store: CascadeParticipantStore | None = None,
) -> ManagedNodeCascadePreparationOwner:
    return ManagedNodeCascadePreparationOwner(
        records=records,
        state_reader=state_reader,
        credentials=cascade_preparation.CascadeCredentialStore(host=host, root=root / "cascade-credentials"),
        store=cascade_preparation.CascadePreparationStore(host=host, root=root / "cascade-preparations"),
        participant_id=participant_id,
        authenticated_participant=lambda _operation, _route: participant_id,
        evidence_provider=evidence_provider,
        renderable_operation=participant_store.can_render if participant_store is not None else None,
    )


def production_plugins(
    *,
    host: HostBackend,
    log_error: Callable[[str], None],
    root: Path,
    calls_runtime: Any,
    extra_plugin_factories: Iterable[PluginFactory],
    probe_identity: ManagedNodeProbeIdentityStore | None,
    preparation: ManagedNodeCascadePreparationOwner,
    participant_store: CascadeParticipantStore,
    participant_id: str,
    technical_peer_material_provider: TechnicalPeerMaterialProvider | None,
) -> PluginContainer:
    return PluginContainer(
        default_plugins(
            notifier=notify_security_event,
            security_context=notification_fields,
            extra_factories=extra_plugin_factories,
            call_config_source=calls_runtime,
        ),
        host=host,
        log_error=log_error,
        runtime_contributions=production_runtime_contributions(
            host=host,
            root=root,
            probe_identity=probe_identity,
            preparation_owner=preparation,
            technical_peer_material_provider=technical_peer_material_provider
            or technical_peer_provider(participant_store, participant_id),
            participant_store=participant_store,
        ),
    )


def production_managed_node_runtime(
    *,
    host: HostBackend,
    root: Path,
    state_reader: Callable[[], AppState],
    state_updater: Callable,
    participant_id: str,
    evidence_provider: cascade_preparation.EvidenceProvider | None,
    authenticated_participant: AuthenticatedParticipant | None,
    technical_peer_material_provider: TechnicalPeerMaterialProvider | None,
    calls_runtime: Any,
    extra_plugin_factories: Iterable[PluginFactory],
    probe_identity: ManagedNodeProbeIdentityStore | None,
    log_error: Callable[[str], None],
) -> tuple[
    PluginContainer,
    ManagedNodeRecords,
    ManagedNodeCascadePreparationOwner,
    ManagedNodeApplyGate,
    CascadeParticipantStore,
]:
    gate = ManagedNodeApplyGate(
        state_reader=state_reader,
        participant_id=participant_id,
        lock_path=root / "apply-gate.lock",
        authenticated_participant=authenticated_participant,
    )
    records = ManagedNodeRecords(
        state_reader=state_reader,
        state_updater=gate.wrap_state_updater(state_updater),
    )
    participant_store = CascadeParticipantStore(host=host, root=root / "cascade-transactions")
    preparation = preparation_owner(
        host=host,
        root=root,
        records=records,
        state_reader=state_reader,
        participant_id=participant_id,
        evidence_provider=evidence_provider,
        participant_store=participant_store,
    )
    plugins = production_plugins(
        host=host,
        log_error=log_error,
        root=root,
        calls_runtime=calls_runtime,
        extra_plugin_factories=extra_plugin_factories,
        probe_identity=probe_identity,
        preparation=preparation,
        participant_store=participant_store,
        participant_id=participant_id,
        technical_peer_material_provider=technical_peer_material_provider,
    )
    return plugins, records, preparation, gate, participant_store


__all__ = ["preparation_owner", "production_managed_node_runtime", "production_plugins"]
