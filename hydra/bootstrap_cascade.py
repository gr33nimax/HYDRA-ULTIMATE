"""Production composition for authenticated cascade participant transactions."""

from __future__ import annotations

import json
import hashlib
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from hydra.core.host import HostBackend
from hydra.core import singbox
from hydra.core import state as state_backend
from hydra.core.state_managed_nodes import managed_nodes_from_extensions, store_managed_nodes
from hydra.services.managed_nodes.apply_gate import ManagedNodeApplyGate
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.cascade_participant import ManagedNodeCascadeParticipant, installed_context_reader
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_preparation import ManagedNodeCascadePreparationOwner
from hydra.services.managed_nodes.client import ManagedNodeClient, client_from_credentials
from hydra.services.managed_nodes.credentials import ManagementCredentialStore
from hydra.services.managed_nodes.cascade_runtime_service import ManagedNodeCascadeRuntime
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.cascade_deployment import CascadeDeploymentStore
from hydra.services.managed_nodes.cascade_production_participant import ProductionCascadeParticipant
from hydra.services.managed_nodes.cascade_capabilities import InstalledCascadeCapabilities
from hydra.services.managed_nodes.cascade_publication import CascadePublicationStore, CascadePathPublisher
from hydra.services.managed_nodes.cascade_stats import user_counters
from hydra.services.managed_nodes.cascade_accounting import scoped_samples
from hydra.services.managed_nodes.accounting import apply_traffic_samples
from hydra.services.managed_nodes.runtime import ManagedNodeRuntime
from hydra.services.managed_nodes.probe_clients import ManagedNodeProbeClient


def production_cascade_components(
    *,
    host: HostBackend,
    root: Path,
    participant_id: str,
    records: ManagedNodeRecords,
    gate: ManagedNodeApplyGate,
    preparation: ManagedNodeCascadePreparationOwner,
    participant_store: CascadeParticipantStore,
    orchestration: Any,
    protocols: Any,
) -> tuple[ManagedNodeCascadeParticipant, ManagedNodeCascadeRuntime]:
    credentials = CascadeCredentialStore(host=host, root=root / "cascade-credentials")
    management_credentials = ManagementCredentialStore(host=host, root=root / "credentials")

    def client_factory(node_id: str) -> ManagedNodeClient:
        definition = records.find_definition(node_id)
        if definition is None:
            raise ValueError("cascade participant is not enrolled")
        return client_from_credentials(management_credentials, definition)

    def client_material(state, protocol: str, user) -> dict[str, Any]:
        try:
            document = json.loads(protocols.singbox_client_config(state, protocol, user))
            outbound = next(
                item
                for item in document.get("outbounds", [])
                if isinstance(item, dict) and item.get("type") == protocol
            )
            return outbound
        except (AttributeError, KeyError, StopIteration, TypeError, ValueError):
            raise RuntimeError("cascade technical client material is unavailable") from None

    deployments = CascadeDeploymentStore(host=host, root=root / "cascade-deployments", participant_id=participant_id,
                                          credentials=credentials, transactions=participant_store)
    process = ManagedNodeRuntime(host=host, config_path=singbox.SINGBOX_CONFIG)
    source = production_scoped_counter_source(host=host, deployments=deployments, config_path=singbox.SINGBOX_CONFIG)

    def preview(state):
        config = singbox.generate_config(state, orchestration.plugins.collect_fragments(state))
        return hashlib.sha256(json.dumps(config, indent=2, ensure_ascii=False).replace("\n", os.linesep).encode()).hexdigest()

    def finalize_state(request):
        def mutate(state):
            namespace = managed_nodes_from_extensions(state.feature_extensions)
            routes = [item for item in namespace.cascades if item.id != request.target_id]
            if request.kind == "cascade_save":
                routes.append(request.route)
            store_managed_nodes(state.feature_extensions, replace(namespace, cascades=routes))
        gate.wrap_state_updater(state_backend.update_state)(mutate)

    def final_accounting():
        state = preparation.state_reader()
        bindings, raw, epoch = source(state)
        def mutate(latest):
            samples = scoped_samples(latest, bindings, raw, epoch)
            if participant_id == "base":
                apply_traffic_samples(latest, "base-cascades", samples)
        gate.wrap_state_updater(state_backend.update_state)(mutate)

    local = ProductionCascadeParticipant(
        deployments=deployments, preview=preview, observe=process.observe,
        capability_probe=InstalledCascadeCapabilities(host=host, binary=str(singbox._find_singbox())),
        final_accounting=final_accounting, protocols=protocols, finalize_state=finalize_state,
        stats_reader=lambda: user_counters(preparation.state_reader().install.get("cascade_stats_port", 19091)),
        participant_id=participant_id,
        records=records,
        state_reader=preparation.state_reader,
        gate=gate,
        store=participant_store,
        preparation=preparation,
        credentials=credentials,
        context_reader=installed_context_reader(host, singbox._find_singbox(), singbox.SINGBOX_CONFIG),
        apply_config=orchestration.apply_cascade_participant_config,
        client_material=client_material,
        capture_restore_context=orchestration.capture_cascade_restore_context,
        capture_remove_config_identity=orchestration.capture_cascade_remove_config_identity,
    )
    publication_store = CascadePublicationStore(host=host, root=root / "cascade-publications")
    runtime = ManagedNodeCascadeRuntime(
        records=records,
        local=local,
        credentials=credentials,
        client_factory=client_factory,
        publication_store=publication_store,
        path_publisher_factory=lambda invoke, request: CascadePathPublisher(
            records=records, state_reader=preparation.state_reader, invoke=invoke, request=request,
            probe_client=ManagedNodeProbeClient(host=host, binary=str(singbox._find_singbox())), store=publication_store,
        ),
    )
    return local, runtime


def production_scoped_counter_source(*, host, deployments, config_path):
    process = ManagedNodeRuntime(host=host, config_path=config_path)
    def collect(state):
        bindings = deployments.counter_bindings(state)
        if not bindings:
            return {}, {}, ""
        config = json.loads(host.read_bytes(config_path, max_bytes=8 * 1024 * 1024))
        if "v2ray_api" not in config.get("experimental", {}):
            return {}, {}, ""
        before = process.observe()
        if before.get("engine_active") is not True:
            raise RuntimeError("cascade accounting engine is unavailable")
        raw = user_counters(state.install.get("cascade_stats_port", 19091))
        after = process.observe()
        if before["runtime_id"] != after["runtime_id"]:
            raise RuntimeError("cascade accounting process changed while sampling")
        return bindings, raw, before["runtime_id"]
    return collect


__all__ = ["production_cascade_components"]
