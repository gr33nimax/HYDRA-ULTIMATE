"""Production composition for authenticated cascade participant transactions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hydra.core.host import HostBackend
from hydra.core import singbox
from hydra.services.managed_nodes.apply_gate import ManagedNodeApplyGate
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.cascade_participant import ManagedNodeCascadeParticipant, installed_context_reader
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_preparation import ManagedNodeCascadePreparationOwner
from hydra.services.managed_nodes.client import ManagedNodeClient, client_from_credentials
from hydra.services.managed_nodes.credentials import ManagementCredentialStore
from hydra.services.managed_nodes.cascade_runtime_service import ManagedNodeCascadeRuntime
from hydra.services.managed_nodes.records import ManagedNodeRecords


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

    local = ManagedNodeCascadeParticipant(
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
    runtime = ManagedNodeCascadeRuntime(
        records=records,
        local=local,
        credentials=credentials,
        client_factory=client_factory,
    )
    return local, runtime


__all__ = ["production_cascade_components"]
