"""Durable two-participant cascade orchestration and capability gates."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping
from threading import RLock
from typing import Any

from hydra.contracts.managed_node_models import CascadeDefinition, Operation, canonical_digest
from hydra.contracts.managed_node_observations import ProtocolOption
from hydra.services.managed_nodes.cascade_runtime import CascadeRuntime
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.records import ManagedNodeRecords

_REQUIRED_CAPABILITIES = frozenset({"client", "server", "probe"})
_PROTOCOLS = ("vless", "anytls")


class ManagedNodeCascadeService:
    """Keep cascade effects behind a snapshot/apply/probe/profile-commit runtime port."""

    def __init__(
        self,
        *,
        records: ManagedNodeRecords,
        runtime: CascadeRuntime | None,
        credentials: CascadeCredentialStore | None = None,
        preparation_owner: Any | None = None,
        operation_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        self._records = records
        self._runtime = runtime
        self._credentials = credentials
        self._preparation_owner = preparation_owner
        self._new_operation_id = operation_id_factory
        self._lock = RLock()

    @staticmethod
    def validate_node_id(node_id: str) -> None:
        if not isinstance(node_id, str) or not node_id or node_id == "base":
            raise ValueError("node id is invalid or reserved for the base server")

    @staticmethod
    def validate_protocol_pair(entry_protocol: str, exit_protocol: str) -> None:
        if not isinstance(entry_protocol, str) or not isinstance(exit_protocol, str):
            raise ValueError("cascade protocol names are invalid")
        if entry_protocol != exit_protocol:
            raise ValueError("cascade participants must use the same protocol")
        if entry_protocol not in _PROTOCOLS:
            raise ValueError("cascade protocol is not supported")

    @classmethod
    def options_for_capabilities(
        cls,
        entry: Mapping[str, Mapping[str, bool]],
        exit: Mapping[str, Mapping[str, bool]],
    ) -> list[ProtocolOption]:
        """Require client, server and real-path probe evidence on both participants."""
        result = []
        for name in _PROTOCOLS:
            left, right = entry.get(name), exit.get(name)
            supported = _proven(left) and _proven(right)
            reason = "" if supported else "transport client, server and probe support is not proven on both hops"
            result.append(ProtocolOption(name, supported, reason))
        return result

    @classmethod
    def validate_definition(cls, definition: CascadeDefinition) -> None:
        definition.validate()
        if definition.id == "base":
            raise ValueError("cascade id 'base' is reserved")
        if definition.entry_id != "base":
            cls.validate_node_id(definition.entry_id)
        if definition.exit_id != "base":
            cls.validate_node_id(definition.exit_id)
        if not definition.protocols:
            raise ValueError("cascade must select at least one protocol")
        for protocol in definition.protocols:
            cls.validate_protocol_pair(protocol, protocol)

    def cascade_options(self, entry_id: str, exit_id: str) -> list[ProtocolOption]:
        self._validate_participants(entry_id, exit_id)
        if self._runtime is None:
            return self.options_for_capabilities({}, {})
        return self.options_for_capabilities(
            self._runtime.capabilities(entry_id),
            self._runtime.capabilities(exit_id),
        )

    def save_cascade(
        self,
        definition: CascadeDefinition,
        *,
        confirmed: bool,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        self.validate_definition(definition)
        if type(confirmed) is not bool or not confirmed:
            raise ValueError("cascade changes require explicit confirmation")
        self._validate_participants(definition.entry_id, definition.exit_id)
        self._require_capabilities(definition)
        previous = self._records.find_cascade(definition.id)
        plan = _plan(definition.id, previous, definition)
        operation = self._begin("cascade_save", definition.id, plan)
        return self._execute(operation, previous, definition, progress)

    def rename_cascade(self, cascade_id: str, name: str) -> None:
        """Rename only the subscription label; keep IDs and route materials stable."""
        self._records.rename_cascade(cascade_id, name)

    def remove_cascade(
        self,
        cascade_id: str,
        *,
        confirmed: bool,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        if type(confirmed) is not bool or not confirmed:
            raise ValueError("cascade removal requires explicit confirmation")
        previous = self._records.find_cascade(cascade_id)
        if previous is None:
            raise KeyError(f"unknown managed-node cascade {cascade_id}")
        self._require_runtime()
        plan = _plan(cascade_id, previous, None)
        operation = self._begin("cascade_remove", cascade_id, plan)
        return self._execute(operation, previous, None, progress)

    def resume_cascade(
        self,
        operation_id: str,
        *,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        operation = self._records.find_operation(operation_id)
        if operation is None or operation.kind not in {"cascade_save", "cascade_remove"}:
            raise KeyError(f"unknown managed-node cascade operation {operation_id}")
        if operation.state == "succeeded":
            self._finalize_participants(operation, _from_plan(operation, "previous"), _from_plan(operation, "cascade"))
            return operation
        if operation.state == "failed":
            return operation
        if not isinstance(operation.plan, dict):
            raise ValueError("cascade operation has no immutable plan")
        previous_raw, candidate_raw = operation.plan.get("previous"), operation.plan.get("cascade")
        previous = CascadeDefinition.from_document(previous_raw) if previous_raw is not None else None
        candidate = CascadeDefinition.from_document(candidate_raw) if candidate_raw is not None else None
        return self._execute(operation, previous, candidate, progress)

    def _execute(self, operation, previous, candidate, progress):
        runtime = self._require_runtime()
        participants = _participants(previous, candidate)
        applied: list[str] = []
        created_credentials = False
        try:
            self._step(operation.id, "snapshot", "started", progress)
            for participant in participants:
                runtime.ensure_snapshot(operation.id, participant, previous)
            self._step(operation.id, "snapshot", "succeeded", progress)
            if candidate is not None and self._credentials is not None:
                created_credentials = not self._credentials.exists(candidate.id)
                self._credentials.prepare(candidate.id)
            if candidate is not None:
                prepare_participants = getattr(runtime, "prepare_participants", None)
                if callable(prepare_participants):
                    prepare_participants(operation.id, candidate)
                elif self._preparation_owner is not None and self._preparation_owner.should_prepare(candidate):
                    for protocol in candidate.protocols:
                        self._preparation_owner.prepare(operation.id, protocol)
            self._step(operation.id, "apply", "started", progress)
            for participant in participants:
                status = runtime.participant_status(operation.id, participant)
                if status == "applied":
                    applied.append(participant)
                    continue
                if status != "not_applied":
                    raise _CascadeRecoveryError(f"{participant}: apply result is unknown; refusing request replay")
                try:
                    runtime.apply_participant(operation.id, participant, candidate)
                except Exception:
                    outcome = runtime.participant_status(operation.id, participant)
                    if outcome == "applied":
                        applied.append(participant)
                    if outcome == "unknown":
                        raise _CascadeRecoveryError(f"{participant}: apply result is unknown; refusing request replay")
                    raise
                if runtime.participant_status(operation.id, participant) != "applied":
                    raise _CascadeRecoveryError(f"{participant}: apply receipt was not confirmed")
                applied.append(participant)
            self._step(operation.id, "apply", "succeeded", progress)
            if candidate is not None:
                self._step(operation.id, "probe", "started", progress)
                if runtime.verify_path(operation.id, candidate) is not True:
                    raise RuntimeError("whole-path client verification failed")
                self._step(operation.id, "probe", "succeeded", progress)
            self._step(operation.id, "profiles", "started", progress)
            runtime.commit_profiles(operation.id, candidate)
            self._step(operation.id, "profiles", "succeeded", progress)
            result = self._records.commit_cascade_operation(operation.id, candidate)
            self._finalize_participants(result, previous, candidate)
            if candidate is None and previous is not None and self._credentials is not None:
                try:
                    self._credentials.remove(previous.id, cleanup_confirmed=True)
                except (OSError, ValueError):
                    # A protected orphan is safer than failing after durable route removal.
                    pass
            return result
        except Exception as exc:
            rollback_failures = []
            if not isinstance(exc, _CascadeRecoveryError):
                for participant in reversed(participants):
                    try:
                        if runtime.rollback_participant(operation.id, participant) is not True:
                            rollback_failures.append(participant)
                    except Exception:
                        rollback_failures.append(participant)
            recovery = isinstance(exc, _CascadeRecoveryError) or bool(rollback_failures)
            if (
                created_credentials
                and candidate is not None
                and previous is None
                and not recovery
                and self._credentials is not None
            ):
                try:
                    self._credentials.remove(candidate.id, cleanup_confirmed=True)
                except (OSError, ValueError):
                    pass
            current = self._records.find_operation(operation.id)
            if current is None:
                raise
            error = {"stage": current.active_step or "cascade", "reason": _bounded(str(exc))}
            if rollback_failures:
                error["rollback_reason"] = _bounded("rollback failed for " + ", ".join(rollback_failures))
            result = Operation(
                current.id,
                current.kind,
                current.target_id,
                current.desired_digest,
                "recovery_required" if recovery else "failed",
                list(current.completed_steps),
                error,
                current.receipt,
                current.plan,
                current.remote_removal_confirmed,
                current.active_step if recovery else None,
                current.existing_reinstall_confirmed,
            )
            self._records.update_operation(result)
            _notify(progress, operation.id, current.active_step or "cascade", result.state, error["reason"])
            return result

    def _begin(self, kind: str, cascade_id: str, plan: dict[str, Any]) -> Operation:
        operation = Operation(
            self._new_operation_id(),
            kind,
            cascade_id,
            canonical_digest(plan),
            "pending",
            plan=plan,
        )
        return self._records.begin_operation(operation)

    def _step(self, operation_id, step, state, progress):
        current = self._records.find_operation(operation_id)
        if current is None:
            raise KeyError(operation_id)
        if state == "started":
            if step not in current.completed_steps:
                self._records.begin_step(operation_id, step)
        elif step not in current.completed_steps:
            self._records.complete_step(operation_id, step)
        _notify(progress, operation_id, step, state)

    def _validate_participants(self, entry_id: str, exit_id: str) -> None:
        if entry_id == exit_id:
            raise ValueError("cascade participants must be different")
        for node_id in (entry_id, exit_id):
            if node_id != "base" and self._records.find_definition(node_id) is None:
                raise ValueError(f"cascade participant {node_id!r} is not enrolled")

    def _require_capabilities(self, definition: CascadeDefinition) -> None:
        options = {item.name: item for item in self.cascade_options(definition.entry_id, definition.exit_id)}
        for protocol in definition.protocols:
            option = options.get(protocol)
            if option is None or not option.supported:
                raise ValueError(option.reason if option is not None else f"unsupported cascade protocol: {protocol}")

    def _finalize_participants(self, operation, previous, candidate) -> None:
        runtime = self._runtime
        finalize = getattr(runtime, "finalize_participant", None) if runtime is not None else None
        if not callable(finalize):
            return
        for participant in reversed(_participants(previous, candidate)):
            try:
                finalize(operation.id, participant, candidate)
            except Exception:
                # The durable coordinator commit is already authoritative; leave failed
                # participant leases and snapshots for resume to finalize idempotently.
                continue

    def _require_runtime(self) -> CascadeRuntime:
        if self._runtime is None:
            raise RuntimeError("cascade apply, real-path probe and profile commit are not wired")
        return self._runtime


def _from_plan(operation: Operation, key: str) -> CascadeDefinition | None:
    if not isinstance(operation.plan, dict):
        return None
    raw = operation.plan.get(key)
    return CascadeDefinition.from_document(raw) if raw is not None else None


def _plan(cascade_id: str, previous, candidate) -> dict[str, Any]:
    return {
        "cascade_id": cascade_id,
        "previous": previous.to_document() if previous else None,
        "cascade": candidate.to_document() if candidate else None,
    }


def _participants(previous, candidate) -> list[str]:
    values = set()
    for definition in (previous, candidate):
        if definition is not None:
            values.update((definition.entry_id, definition.exit_id))
    return sorted(values)


def _proven(capabilities: Mapping[str, bool] | None) -> bool:
    return isinstance(capabilities, Mapping) and all(capabilities.get(name) is True for name in _REQUIRED_CAPABILITIES)


def _bounded(value: str) -> str:
    return "".join(char for char in value if char.isprintable())[:256] or "cascade operation failed"


def _notify(callback, operation_id: str, step: str, state: str, reason: str = "") -> None:
    if callback is None:
        return
    event = {"operation_id": operation_id, "step": step, "state": state}
    if reason:
        event["reason"] = _bounded(reason)
    try:
        callback(event)
    except Exception:
        return


class _CascadeRecoveryError(RuntimeError):
    """An uncertain remote result cannot be replayed safely."""


__all__ = ["ManagedNodeCascadeService"]
