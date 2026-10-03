"""Production coordinator for local and pinned-HTTPS cascade participants."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from hydra.contracts.managed_node_cascade import CascadeParticipantRequest, CascadeTechnicalMaterial
from hydra.contracts.managed_node_models import CascadeDefinition, Operation, canonical_digest
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.cascade_participant import ManagedNodeCascadeParticipant
from hydra.services.managed_nodes.cascade_preparation import cascade_candidate
from hydra.services.managed_nodes.client import ManagedNodeClient
from hydra.services.managed_nodes.records import ManagedNodeRecords


class ManagedNodeCascadeRuntime:
    """Route only typed operation-bound calls; missing path/publication gates stay closed."""

    def __init__(
        self,
        *,
        records: ManagedNodeRecords,
        local: ManagedNodeCascadeParticipant,
        credentials: CascadeCredentialStore,
        client_factory: Callable[[str], ManagedNodeClient],
        deadline_seconds: float = 20.0,
    ) -> None:
        self._records = records
        self._local = local
        self._credentials = credentials
        self._client_factory = client_factory
        self._deadline_seconds = deadline_seconds

    def capabilities(self, participant_id: str) -> dict[str, dict[str, bool]]:
        # No authenticated installed-engine capability evidence is wired yet.
        del participant_id
        return {}

    def ensure_snapshot(
        self,
        operation_id: str,
        participant_id: str,
        previous: CascadeDefinition | None,
    ) -> None:
        del previous
        operation = self._operation(operation_id)
        for request in self._requests(operation, participant_id):
            if participant_id == self._local.participant_id:
                receipt = self._local.ensure_snapshot(request)
            else:
                receipt = self._client(participant_id).cascade_snapshot(request, self._deadline())
            receipt.validate_for(request)
            if receipt.state != "snapshotted":
                raise RuntimeError("cascade participant did not confirm its immutable snapshot")

    def prepare_participants(self, operation_id: str, definition: CascadeDefinition) -> None:
        operation = self._operation(operation_id)
        if cascade_candidate(operation) != definition:
            raise ValueError("cascade preparation differs from the frozen candidate")
        transfer = self._credentials.export_transfer(definition.id)
        for protocol in definition.protocols:
            exit_request = self._request(operation, definition.exit_id, definition, protocol)
            entry_request = self._request(operation, definition.entry_id, definition, protocol)
            if definition.exit_id == self._local.participant_id:
                exit_receipt = self._local.prepare(exit_request, transfer)
                material = self._local.technical_material(exit_request)
            else:
                client = self._client(definition.exit_id)
                exit_receipt = client.cascade_prepare(exit_request, transfer, None, self._deadline())
                material = client.cascade_material(exit_request, self._deadline())
            exit_receipt.validate_for(exit_request)
            material.validate_for(exit_request)
            if exit_receipt != material.receipt:
                raise ValueError("cascade transit material does not match its preparation receipt")
            if definition.entry_id == self._local.participant_id:
                entry_receipt = self._local.prepare(entry_request, transfer, material)
            else:
                entry_receipt = self._client(definition.entry_id).cascade_prepare(
                    entry_request, transfer, material, self._deadline()
                )
            entry_receipt.validate_for(entry_request)
            if entry_receipt.state != "prepared":
                raise RuntimeError("cascade entry preparation was not confirmed")

    def participant_status(self, operation_id: str, participant_id: str) -> str:
        operation = self._operation(operation_id)
        states = []
        for request in self._requests(operation, participant_id):
            if participant_id == self._local.participant_id:
                state, receipt = self._local.query(request)
            else:
                status = self._client(participant_id).cascade_status(request, self._deadline())
                state, receipt = status.state, status.receipt
            if state == "applied":
                if receipt is None:
                    return "unknown"
                receipt.validate_for(request)
            states.append(state)
        if states and all(state == "applied" for state in states):
            return "applied"
        if states and all(state == "not_applied" for state in states):
            return "not_applied"
        return "unknown"

    def apply_participant(
        self,
        operation_id: str,
        participant_id: str,
        definition: CascadeDefinition | None,
    ) -> None:
        operation = self._operation(operation_id)
        if cascade_candidate(operation) != definition:
            raise ValueError("cascade participant apply differs from the frozen candidate")
        for request in self._requests(operation, participant_id):
            if participant_id == self._local.participant_id:
                receipt = self._local.apply(request)
            else:
                receipt = self._client(participant_id).cascade_apply(request, self._deadline())
            receipt.validate_for(request)
            if receipt.state != "applied":
                raise RuntimeError("cascade participant apply receipt is not confirmed")

    def verify_path(self, operation_id: str, definition: CascadeDefinition) -> bool:
        del operation_id, definition
        return False

    def commit_profiles(self, operation_id: str, definition: CascadeDefinition | None) -> None:
        del operation_id, definition
        raise RuntimeError("cascade final profile publication and billing are not wired")

    def rollback_participant(self, operation_id: str, participant_id: str) -> bool:
        operation = self._operation(operation_id)
        ok = True
        for request in self._requests(operation, participant_id):
            try:
                if participant_id == self._local.participant_id:
                    receipt = self._local.rollback(request)
                else:
                    receipt = self._client(participant_id).cascade_rollback(request, self._deadline())
                receipt.validate_for(request)
                ok = ok and receipt.state == "rolled_back"
            except Exception:
                ok = False
        return ok

    def finalize_participant(
        self, operation_id: str, participant_id: str, definition: CascadeDefinition | None
    ) -> bool:
        operation = self._operation(operation_id)
        if operation.state != "succeeded":
            raise ValueError("cascade coordinator has not committed the operation")
        if cascade_candidate(operation) != definition:
            raise ValueError("cascade finalization differs from the committed candidate")
        commit_digest = canonical_digest(operation.to_document())
        ok = True
        for request in self._requests(operation, participant_id):
            try:
                if participant_id == self._local.participant_id:
                    receipt = self._local.finalize(request, commit_digest)
                else:
                    receipt = self._client(participant_id).cascade_finalize(request, commit_digest, self._deadline())
                receipt.validate_for(request)
                ok = ok and receipt.state == "finalized"
            except Exception:
                ok = False
        return ok

    def _requests(self, operation: Operation, participant_id: str) -> tuple[CascadeParticipantRequest, ...]:
        plan = operation.plan
        if not isinstance(plan, dict):
            raise ValueError("cascade participant operation has no immutable plan")
        candidate = CascadeDefinition.from_document(plan["cascade"]) if plan.get("cascade") is not None else None
        previous = CascadeDefinition.from_document(plan["previous"]) if plan.get("previous") is not None else None
        selected = (
            candidate
            if candidate is not None and participant_id in {candidate.entry_id, candidate.exit_id}
            else previous
        )
        if selected is None or participant_id not in {selected.entry_id, selected.exit_id}:
            raise ValueError("cascade participant is outside the frozen operation topology")
        if not isinstance(operation.plan, dict):
            raise ValueError("cascade participant operation has no immutable plan")
        return tuple(self._request(operation, participant_id, selected, protocol) for protocol in selected.protocols)

    @staticmethod
    def _request(
        operation: Operation, participant_id: str, route: CascadeDefinition, protocol: str
    ) -> CascadeParticipantRequest:
        role = "entry" if participant_id == route.entry_id else "transit"
        request = CascadeParticipantRequest(
            operation.id,
            operation.kind,
            operation.target_id,
            operation.desired_digest,
            operation.plan,
            participant_id,
            role,
            route,
            protocol,
        )
        request.validate()
        return request

    def _operation(self, operation_id: str) -> Operation:
        operation = self._records.find_operation(operation_id)
        if operation is None or operation.kind not in {"cascade_save", "cascade_remove"}:
            raise KeyError(f"unknown cascade operation {operation_id}")
        return operation

    def _client(self, participant_id: str) -> ManagedNodeClient:
        return self._client_factory(participant_id)

    def _deadline(self) -> float:
        return time.monotonic() + self._deadline_seconds


__all__ = ["ManagedNodeCascadeRuntime"]
