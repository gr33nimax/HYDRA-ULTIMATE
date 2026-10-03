"""Freeze canonical removal evidence before a scoped participant runtime effect."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from hydra.contracts.managed_node_cascade import CascadeParticipantReceipt, CascadeParticipantRequest
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.apply_gate import ManagedNodeApplyGate
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore

RemovalConfigIdentity = Callable[[AppState, CascadeParticipantRequest], str]


def prepare_removal(
    request: CascadeParticipantRequest,
    *,
    store: CascadeParticipantStore,
    gate: ManagedNodeApplyGate,
    state_reader: Callable[[], AppState],
    context_reader: Callable[[], tuple[str, str]],
    capture_target: RemovalConfigIdentity | None,
) -> dict[str, Any]:
    """Use the normal prepared phase; a baseline digest is never a removal target."""
    request.validate()
    if request.kind != "cascade_remove":
        raise ValueError("cascade removal target requires a frozen removal request")
    if capture_target is None:
        raise ValueError("canonical cascade removal target evidence is unavailable")
    with gate.participant_mutation(request.operation_id, request.plan_digest, require_snapshot=True):
        record = store.record(request)
        snapshot = store.snapshot_data(request)
        if record is None or snapshot is None or record["phase"] not in {"snapshotted", "prepared"}:
            raise ValueError("cascade removal snapshot or prepared phase is unavailable")
        engine, config = context_reader()
        if engine != snapshot["engine_identity"]:
            raise ValueError("cascade participant engine changed before removal")
        allowed_configs = {snapshot["config_identity"]}
        applied_targets = set()
        for protocol in request.route.protocols:
            sibling = store.request_for(request.operation_id, request.participant_id, protocol)
            if (
                sibling is None
                or sibling != replace(request, protocol=protocol)
                or store.snapshot_data(sibling) is None
            ):
                raise ValueError("all local cascade protocol snapshots are required before removal")
            peer = store.record(sibling)
            if peer is not None and peer["phase"] == "applied" and peer["after_engine_identity"] == engine:
                allowed_configs.add(peer["after_config_identity"])
                applied_targets.add(peer["after_config_identity"])
        if config not in allowed_configs:
            raise ValueError("cascade participant configuration changed before removal")
        target = capture_target(state_reader(), request)
        if not isinstance(target, str) or not re.fullmatch(r"[0-9a-f]{64}", target):
            raise ValueError("canonical cascade removal target identity is invalid")
        if applied_targets and target not in applied_targets:
            raise ValueError("shared cascade removal target changed before apply")
        if record["phase"] == "prepared":
            if record["receipt"]["config_identity"] != target:
                raise ValueError("canonical cascade removal target changed before apply")
            return record
        receipt = CascadeParticipantReceipt(
            request.operation_id,
            request.plan_digest,
            request.target_id,
            request.participant_id,
            request.role,
            request.protocol,
            "prepared",
            engine,
            target,
        )
        receipt.validate_for(request)
        return store.update(
            request,
            phase="prepared",
            receipt=receipt.to_document(),
            preparation_receipt=receipt.to_document(),
        )
