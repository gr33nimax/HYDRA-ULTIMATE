"""Authenticated local owner for scoped cascade participant effects and recovery."""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Callable
from typing import Any

from hydra.contracts.managed_node_cascade import (
    CascadeParticipantReceipt,
    CascadeParticipantRequest,
    CascadeTechnicalMaterial,
)
from hydra.contracts.managed_node_models import CascadeDefinition, Operation, canonical_digest
from hydra.contracts.managed_node_probe import ProbeMaterial
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.apply_gate import ManagedNodeApplyGate
from hydra.services.managed_nodes.cascade_credentials import (
    CascadeCredentialStore,
    CascadeCredentialTransfer,
)
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_participant_removal import RemovalConfigIdentity, prepare_removal
from hydra.services.managed_nodes.cascade_participant_material import technical_peer_provider, transit_request
from hydra.services.managed_nodes.cascade_preparation import ManagedNodeCascadePreparationOwner
from hydra.services.managed_nodes.cascade_rendering import CascadeTechnicalPeerMaterial
from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext
from hydra.services.managed_nodes.cascade_leases import cascade_participants, operation_is_active
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.utils.commands import redact_text
from hydra.utils.crypto import derive_hex_key

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
ContextReader = Callable[[], tuple[str, str]]
ApplyConfig = Callable[[AppState, object], bool]
ClientMaterial = Callable[[AppState, str, Any], dict[str, Any]]
RestoreContextCapture = Callable[[AppState, Operation, CascadeParticipantRequest], CascadeRestoreContext]


def installed_context_reader(host, engine_path, config_path) -> ContextReader:
    """Hash the actual installed executable and config through HostBackend reads."""

    def read() -> tuple[str, str]:
        for path in (engine_path, config_path):
            if path is None or path.is_symlink() or not path.is_file():
                raise RuntimeError("cascade participant engine or configuration is unavailable")
        engine = host.read_bytes(engine_path, max_bytes=256 * 1024 * 1024)
        config = host.read_bytes(config_path, max_bytes=8 * 1024 * 1024)
        return hashlib.sha256(engine).hexdigest(), hashlib.sha256(config).hexdigest()

    return read


class ManagedNodeCascadeParticipant:
    """Own only the local participant's immutable operation scope and staged overlay."""

    def __init__(
        self,
        *,
        participant_id: str,
        records: ManagedNodeRecords,
        state_reader: Callable[[], AppState],
        gate: ManagedNodeApplyGate,
        store: CascadeParticipantStore,
        preparation: ManagedNodeCascadePreparationOwner,
        credentials: CascadeCredentialStore,
        context_reader: ContextReader,
        apply_config: ApplyConfig,
        client_material: ClientMaterial | None = None,
        capture_restore_context: RestoreContextCapture | None = None,
        capture_remove_config_identity: RemovalConfigIdentity | None = None,
    ) -> None:
        self.participant_id = participant_id
        self._records = records
        self._state_reader = state_reader
        self._gate = gate
        self._store = store
        self._preparation = preparation
        self._credentials = credentials
        self._context = context_reader
        self._apply_config = apply_config
        self._client_material = client_material
        self._capture_restore_context = capture_restore_context
        self._capture_remove_config_identity = capture_remove_config_identity
        self._transaction_lock = threading.RLock()

    def ensure_snapshot(self, request: CascadeParticipantRequest) -> CascadeParticipantReceipt:
        self._validate_local(request)
        with self._transaction_lock:
            prior = self._store.record(request)
            if prior is not None and prior["phase"] in {"rolled_back", "finalized"}:
                raise ValueError("cascade participant transaction is already terminal")
            operation = Operation(
                request.operation_id, request.kind, request.target_id, request.plan_digest, "pending", plan=request.plan
            )
            current = self._records.begin_operation(operation)
            if (current.kind, current.target_id, current.desired_digest, current.plan) != (
                request.kind,
                request.target_id,
                request.plan_digest,
                request.plan,
            ):
                raise ValueError("cascade participant operation differs from its frozen plan")
            with self._gate.participant_mutation(request.operation_id, request.plan_digest):
                existing = self._store.snapshot_data(request)
                if existing is None:
                    restore_context = self._capture_scope(self._state_reader(), current, request)
                    engine, config = self._context()
                else:
                    restore_context = CascadeRestoreContext.from_document(existing["restore_context"])
                    engine, config = existing["engine_identity"], existing["config_identity"]
                snapshot = self._store.snapshot(request, engine, config, restore_context)
                record = self._store.record(request)
                if record is None:
                    raise ValueError("cascade participant snapshot record is unavailable")
                if record["receipt"] is None:
                    receipt = self._receipt(
                        request, "snapshotted", snapshot["engine_identity"], snapshot["config_identity"]
                    )
                    self._store.update(request, phase=record["phase"], receipt=receipt.to_document())
            if self.participant_id != "base" and "snapshot" not in current.completed_steps:
                self._records.begin_step(request.operation_id, "snapshot")
                self._records.complete_step(request.operation_id, "snapshot")
            return self._receipt(request, "snapshotted", snapshot["engine_identity"], snapshot["config_identity"])

    def prepare(
        self,
        request: CascadeParticipantRequest,
        transfer: CascadeCredentialTransfer,
        material: CascadeTechnicalMaterial | None = None,
    ) -> CascadeParticipantReceipt:
        self._validate_local(request)
        if (
            request.kind != "cascade_save"
            or not isinstance(transfer, CascadeCredentialTransfer)
            or transfer.cascade_id != request.target_id
        ):
            raise ValueError("cascade technical preparation does not match its frozen save route")
        transfer.validate()
        if (request.role == "entry") != (material is not None):
            raise ValueError("cascade transit material does not match the authenticated participant role")
        if material is not None:
            material.validate_for(transit_request(request))
        with (
            self._transaction_lock,
            self._gate.participant_mutation(request.operation_id, request.plan_digest, require_snapshot=True),
        ):
            return self._prepare_owned(request, transfer, material)

    def _prepare_owned(
        self,
        request: CascadeParticipantRequest,
        transfer: CascadeCredentialTransfer,
        material: CascadeTechnicalMaterial | None,
    ) -> CascadeParticipantReceipt:
        self._require_operation(request)
        record = self._require_record(request)
        if record["phase"] in {"prepared", "applying", "applied"}:
            self._credentials.validate_transfer(transfer)
            if request.role == "entry" and (material is None or record["material"] != material.to_document()):
                raise ValueError("cascade entry retry differs from its protected transit material")
            return CascadeParticipantReceipt.from_document(record["preparation_receipt"])
        if record["phase"] != "snapshotted":
            raise ValueError("cascade participant is not available for preparation")
        scope = self._credentials.import_transfer(transfer)
        prep = self._preparation.prepare(request.operation_id, request.protocol)
        if prep.route != request.route or prep.role != request.role or prep.plan_digest != request.plan_digest:
            raise ValueError("cascade preparation is bound to another participant request")
        receipt_material = self._preparation_material(request, material, scope, prep)
        engine, config = self._context()
        if engine != prep.engine_identity or config not in {
            prep.baseline_config_identity,
            prep.prepared_config_identity,
        }:
            raise ValueError("cascade participant engine or configuration context changed")
        config = prep.prepared_config_identity
        material_digest = canonical_digest(receipt_material["outbound"]) if request.role == "transit" else None
        receipt = self._receipt(request, "prepared", engine, config, material_digest)
        self._store.update(
            request,
            phase="prepared",
            receipt=receipt.to_document(),
            preparation_receipt=receipt.to_document(),
            material=receipt_material,
        )
        return receipt

    def _preparation_material(self, request, material, scope, prep) -> dict[str, Any]:
        if request.role == "entry":
            if material is None:
                raise ValueError("authenticated transit material is required for the entry participant")
            transit = scope.technical_subject(request.route.exit_id, request.protocol, "transit", request.operation_id)
            peer = CascadeTechnicalPeerMaterial(
                request.target_id,
                request.route.entry_id,
                request.route.exit_id,
                request.route.exit_id,
                "transit",
                request.protocol,
                request.operation_id,
                request.plan_digest,
                material.receipt.engine_identity,
                material.receipt.config_identity,
                material.outbound,
            )
            peer.validate_for(prep, transit)
            return material.to_document()
        if self._client_material is None:
            raise RuntimeError("authenticated cascade client material provider is unavailable")
        transit = scope.technical_subject(self.participant_id, request.protocol, "transit", request.operation_id)
        outbound = self._client_material(self._state_reader(), request.protocol, transit)
        ProbeMaterial(request.protocol, outbound).validate()
        expected = transit.uuid if request.protocol == "vless" else derive_hex_key("anytls-pass", transit.uuid)
        secret_key = "uuid" if request.protocol == "vless" else "password"
        if outbound.get(secret_key) != expected:
            raise ValueError("cascade client material does not match its scoped transit identity")
        return {"outbound": outbound}

    def technical_material(self, request: CascadeParticipantRequest) -> CascadeTechnicalMaterial:
        self._validate_local(request)
        record = self._require_record(request)
        if request.role != "transit" or record["phase"] not in {"prepared", "applying", "applied"}:
            raise ValueError("cascade transit material is not prepared")
        receipt = CascadeParticipantReceipt.from_document(record["preparation_receipt"])
        outbound = record["material"]
        if not isinstance(outbound, dict) or set(outbound) != {"outbound"}:
            raise ValueError("cascade transit material is unavailable")
        result = CascadeTechnicalMaterial(receipt, outbound["outbound"])
        result.validate_for(request)
        return result

    def apply(self, request: CascadeParticipantRequest) -> CascadeParticipantReceipt:
        self._validate_local(request)
        with self._transaction_lock:
            return self._apply_owned(request)

    def _apply_owned(self, request: CascadeParticipantRequest) -> CascadeParticipantReceipt:
        self._require_operation(request)
        record = self._require_record(request)
        if record["phase"] == "applied":
            return self._current_applied_receipt(request, record)
        if request.kind == "cascade_remove" and record["phase"] in {"snapshotted", "prepared"}:
            record = prepare_removal(
                request,
                store=self._store,
                gate=self._gate,
                state_reader=self._state_reader,
                context_reader=self._context,
                capture_target=self._capture_remove_config_identity,
            )
        if record["phase"] != "prepared":
            raise ValueError("cascade participant apply outcome is not safely replayable")
        engine, config = self._context()
        if engine != record["receipt"]["engine_identity"]:
            raise ValueError("cascade participant engine changed after preparation")
        if request.kind == "cascade_save":
            preparation = self._preparation.store.load(
                request.operation_id, request.target_id, request.participant_id, request.protocol
            )
            if (
                preparation.plan_digest != request.plan_digest
                or preparation.role != request.role
                or preparation.engine_identity != engine
                or config not in {preparation.baseline_config_identity, preparation.prepared_config_identity}
            ):
                raise ValueError("cascade participant configuration or material changed after preparation")
        self._store.update(request, phase="applying")
        try:
            authorization = self._gate.authorize_participant(request.operation_id)
            applied = self._apply_config(self._state_reader(), authorization)
            if not isinstance(applied, bool) or not applied:
                raise RuntimeError("canonical cascade configuration apply did not confirm")
            current_engine, current_config = self._context()
            if current_engine != engine:
                raise RuntimeError("cascade participant engine changed during apply")
            expected_config = record["receipt"]["config_identity"]
            if current_config != expected_config:
                raise RuntimeError("cascade participant configuration does not match prepared evidence")
            receipt = self._receipt(
                request, "applied", current_engine, current_config, record["receipt"].get("material_digest")
            )
            self._store.update(
                request,
                phase="applied",
                after_engine_identity=current_engine,
                after_config_identity=current_config,
                receipt=receipt.to_document(),
            )
            return receipt
        except Exception as exc:
            self._store.update(request, phase="recovery_required")
            raise RuntimeError(_bounded_reason(exc)) from None

    def query(self, request: CascadeParticipantRequest) -> tuple[str, CascadeParticipantReceipt | None]:
        self._validate_local(request)
        record = self._store.record(request)
        if record is None:
            return "unknown", None
        phase = record["phase"]
        if phase == "applied":
            try:
                return "applied", self._current_applied_receipt(request, record)
            except (OSError, TypeError, ValueError):
                return "unknown", None
        if phase in {"snapshotted", "prepared"}:
            return "not_applied", None
        return "unknown", None

    def status(self, request: CascadeParticipantRequest) -> str:
        return self.query(request)[0]

    def rollback(self, request: CascadeParticipantRequest) -> CascadeParticipantReceipt:
        self._validate_local(request)
        with self._transaction_lock:
            record = self._require_record(request)
            if record["phase"] == "rolled_back":
                self._store.remove_snapshot(request)
                self._finish_terminal(request, "rolled_back")
                return CascadeParticipantReceipt.from_document(record["receipt"])
            if record["phase"] == "finalized":
                raise ValueError("finalized cascade participant cannot be rolled back")
            with self._gate.participant_mutation(request.operation_id, request.plan_digest, require_snapshot=True):
                record = self._require_record(request)
                if record["phase"] not in {
                    "snapshotted",
                    "prepared",
                    "applying",
                    "applied",
                    "recovery_required",
                    "rolling_back",
                }:
                    raise ValueError("cascade participant rollback phase is invalid")
                self._store.update(request, phase="rolling_back", rollback_requested=True)
            try:
                if record["phase"] in {"prepared", "applying", "applied", "recovery_required", "rolling_back"}:
                    authorization = self._gate.authorize_participant(request.operation_id)
                    applied = self._apply_config(self._state_reader(), authorization)
                    if not isinstance(applied, bool) or not applied:
                        raise RuntimeError("canonical cascade rollback apply did not confirm")
                engine, config = self._context()
                receipt = self._receipt(request, "rolled_back", engine, config)
                self._store.update(
                    request,
                    phase="rolled_back",
                    after_engine_identity=engine,
                    after_config_identity=config,
                    receipt=receipt.to_document(),
                    material=None,
                )
                self._store.remove_snapshot(request)
                self._finish_terminal(request, "rolled_back")
                return receipt
            except Exception as exc:
                current = self._store.record(request)
                if current is not None and current["phase"] not in {"rolled_back", "finalized"}:
                    self._store.update(request, phase="recovery_required")
                raise RuntimeError(_bounded_reason(exc)) from None

    def finalize(self, request: CascadeParticipantRequest, commit_digest: str) -> CascadeParticipantReceipt:
        self._validate_local(request)
        if not isinstance(commit_digest, str) or not _SHA256.fullmatch(commit_digest):
            raise ValueError("cascade coordinator commit receipt is invalid")
        operation = self._records.find_operation(request.operation_id)
        if self.participant_id == "base" and (
            operation is None
            or operation.state != "succeeded"
            or canonical_digest(operation.to_document()) != commit_digest
        ):
            raise ValueError("cascade coordinator has not durably committed this operation")
        record = self._require_record(request)
        if record["phase"] == "finalized":
            self._store.remove_snapshot(request)
            self._finish_terminal(request, "finalized")
            return CascadeParticipantReceipt.from_document(record["receipt"])
        if record["phase"] != "applied":
            raise ValueError("cascade participant cannot finalize before confirmed apply")
        receipt = self._receipt(request, "finalized", record["after_engine_identity"], record["after_config_identity"])
        self._store.update(request, phase="finalized", receipt=receipt.to_document(), material=None)
        self._store.remove_snapshot(request)
        self._finish_terminal(request, "finalized")
        return receipt

    def _current_applied_receipt(self, request, record) -> CascadeParticipantReceipt:
        engine, config = self._context()
        if engine != record["after_engine_identity"] or config != record["after_config_identity"]:
            raise ValueError("cascade participant context changed after apply")
        receipt = CascadeParticipantReceipt.from_document(record["receipt"])
        receipt.validate_for(request)
        return receipt

    def _receipt(self, request, state, engine, config, material_digest=None) -> CascadeParticipantReceipt:
        receipt = CascadeParticipantReceipt(
            request.operation_id,
            request.plan_digest,
            request.target_id,
            request.participant_id,
            request.role,
            request.protocol,
            state,
            engine,
            config,
            material_digest,
        )
        receipt.validate_for(request)
        return receipt

    def _validate_local(self, request: CascadeParticipantRequest) -> None:
        request.validate()
        if request.participant_id != self.participant_id:
            raise ValueError("cascade participant receiver identity does not match this node")

    def _capture_scope(
        self,
        state: AppState,
        operation: Operation,
        request: CascadeParticipantRequest,
    ) -> CascadeRestoreContext:
        if self._capture_restore_context is not None:
            context = self._capture_restore_context(state, operation, request)
        else:
            previous = operation.plan.get("previous") if isinstance(operation.plan, dict) else None
            if previous is not None:
                route = CascadeDefinition.from_document(previous)
                if request.participant_id in {route.entry_id, route.exit_id} and request.protocol in route.protocols:
                    raise RuntimeError("previous cascade runtime context cannot be captured")
            context = CascadeRestoreContext.empty(request)
        if not isinstance(context, CascadeRestoreContext):
            raise RuntimeError("cascade participant restore context is unavailable")
        context.validate_for(request)
        return context

    def _require_operation(self, request: CascadeParticipantRequest) -> Operation:
        operation = self._records.find_operation(request.operation_id)
        if (
            operation is None
            or not operation_is_active(operation)
            or (operation.kind, operation.target_id, operation.desired_digest, operation.plan)
            != (request.kind, request.target_id, request.plan_digest, request.plan)
            or self.participant_id not in cascade_participants(operation)
            or "snapshot" not in operation.completed_steps
        ):
            raise ValueError("cascade participant has no matching active persisted operation lease")
        return operation

    def _require_record(self, request):
        record = self._store.record(request)
        if record is None:
            raise ValueError("cascade participant snapshot is unavailable")
        return record

    def _finish_terminal(self, request: CascadeParticipantRequest, terminal_state: str) -> None:
        if not self._store.all_terminal(request.operation_id, self.participant_id, terminal_state):
            return
        cleanup_credentials = (
            terminal_state == "rolled_back" and request.kind == "cascade_save" and request.plan["previous"] is None
        ) or (terminal_state == "finalized" and request.kind == "cascade_remove")
        if cleanup_credentials:
            try:
                self._credentials.remove(request.target_id, cleanup_confirmed=True)
            except (OSError, ValueError):
                # A protected orphan is safer than retaining a finished participant lease.
                pass
        self._release_remote_lease(request, terminal_state)

    def _release_remote_lease(self, request: CascadeParticipantRequest, terminal_state: str) -> None:
        if (
            self.participant_id != "base"
            and self._records.find_operation(request.operation_id) is not None
            and self._store.all_terminal(request.operation_id, self.participant_id, terminal_state)
        ):
            self._records.release_participant_operation(
                request.operation_id, request.plan_digest, self.participant_id, terminal_state=terminal_state
            )


def _bounded_reason(error: Exception) -> str:
    text = redact_text(str(error))
    return "".join(char for char in text if char.isprintable())[:160] or type(error).__name__


__all__ = ["ManagedNodeCascadeParticipant"]
