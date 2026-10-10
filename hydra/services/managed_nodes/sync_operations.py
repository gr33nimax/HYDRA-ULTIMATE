"""Durable per-node apply operation state and receipt recovery."""

from __future__ import annotations

import secrets
from collections.abc import Callable

from hydra.contracts.managed_node_models import ApplyReceipt, NodeDesired, Operation
from hydra.services.managed_nodes.client import ManagedNodeError
from hydra.services.managed_nodes.observations import ManagedNodeObservationStore
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.utils.commands import redact_text

_ACTIVE = {"pending", "running", "recovery_required"}


class ManagedNodeSyncOperations:
    """Own immutable apply-intent lookup and remote operation transitions."""

    def __init__(
        self,
        *,
        records: ManagedNodeRecords,
        observations: ManagedNodeObservationStore,
        operation_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        self._records = records
        self._observations = observations
        self._new_operation_id = operation_id_factory

    def operation_desired(self, operation: Operation, current: NodeDesired) -> NodeDesired:
        if operation.kind == "install":
            desired = self._records.find_apply_intent(operation.id)
            if desired is None:
                desired = self._records.store_apply_intent(operation.id, current)
        elif operation.kind == "apply" and operation.plan is not None:
            frozen = NodeDesired.from_document(operation.plan)
            desired = self._records.find_apply_intent(operation.id)
            if desired is None:
                desired = self._records.store_apply_intent(operation.id, frozen)
            if desired != frozen:
                raise ValueError("active apply intent differs from its immutable operation plan")
        else:
            raise ValueError("active managed-node operation has no immutable apply intent")
        if (
            desired.node_id != operation.target_id
            or operation.kind == "apply"
            and desired.digest != operation.desired_digest
        ):
            raise ValueError("active operation does not match its immutable apply intent")
        return desired

    def operation_for(self, node_id: str, desired: NodeDesired) -> Operation | None:
        operations = [item for item in self._records.list_operations() if item.target_id == node_id]
        active = next(
            (item for item in reversed(operations) if item.state in _ACTIVE or item.active_step is not None),
            None,
        )
        if active is not None:
            if (
                active.kind == "install"
                and active.state == "running"
                and active.active_step is None
                and (
                    active.error and active.error.get("stage") == "apply"
                    or {"bootstrap", "management_identity", "management_verified"}.issubset(active.completed_steps)
                    and self._records.find_apply_intent(active.id) is not None
                )
            ):
                return active
            if active.kind == "apply":
                return active
            raise RuntimeError(f"node operation {active.id} ({active.kind}, {active.state}) is unresolved; resume it first")
        previous = next(
            (item.receipt for item in reversed(operations) if item.state == "succeeded" and item.receipt is not None),
            None,
        )
        observation = self._observations.read(node_id)
        if (
            previous
            and previous.desired_digest == desired.digest
            and observation
            and observation.sample
            and observation.sample.receipt == previous
            and observation.sample.runtime.get("apply_generation") == previous.runtime_id
        ):
            return None
        return self.new_operation(node_id, desired)

    def new_operation(self, node_id: str, desired: NodeDesired) -> Operation:
        if desired.node_id != node_id:
            raise ValueError("apply desired state identifies another node")
        return self._records.begin_apply_operation(self._new_operation_id(), desired)

    def remote_apply(
        self,
        client,
        node_id: str,
        operation: Operation,
        desired: NodeDesired,
        *,
        deadline: float,
        progress=None,
    ) -> tuple[Operation | None, str]:
        try:
            try:
                result = client.operation(operation.id, deadline)
            except ManagedNodeError as exc:
                if exc.kind != "not_found":
                    self.mark_pending(operation.id, bounded_error(exc))
                    return None, bounded_error(exc)
                result = client.submit(operation.id, desired, deadline)
            if (
                result.id != operation.id
                or result.target_id != node_id
                or result.desired_digest != desired.digest
                or result.kind != "apply"
            ):
                raise ValueError("remote operation identity does not match")
            if result.state in {"pending", "running", "recovery_required"}:
                self.mark_running(operation.id, result.error)
                notify_progress(progress, operation.id, "apply", "pending")
                result = client.operation(operation.id, deadline)
            if result.state == "failed":
                reason = bounded_error(result.error.get("reason", "remote apply failed") if result.error else "remote apply failed")
                self.mark_failed(
                    operation.id,
                    reason,
                )
                return result, reason
            if result.state == "recovery_required":
                self._update_operation(
                    operation.id,
                    "recovery_required",
                    {"stage": "apply", "reason": "remote apply requires recovery"},
                    None,
                )
                return result, "remote apply requires recovery"
            if result.state == "succeeded":
                return result, ""
            self.mark_running(operation.id, result.error)
            return result, ""
        except Exception as exc:
            reason = bounded_error(exc)
            self.mark_pending(operation.id, reason)
            return None, reason

    def mark_running(self, operation_id: str, remote_error) -> None:
        current = self._records.find_operation(operation_id)
        active_step = None if current and current.kind == "install" else "remote_apply"
        if current and current.kind == "install":
            # This marker transfers ownership from SSH enrollment to apply.
            # A pending remote operation with no error must not erase it.
            remote_error = {
                **(remote_error if isinstance(remote_error, dict) else {}),
                "stage": "apply",
                "reason": bounded_error(remote_error.get("reason", "remote apply is pending"))
                if isinstance(remote_error, dict) else "remote apply is pending",
            }
        self._update_operation(operation_id, "running", remote_error, active_step)

    def mark_pending(self, operation_id: str, reason: str) -> None:
        current = self._records.find_operation(operation_id)
        active_step = None if current and current.kind == "install" else "remote_apply"
        self._update_operation(operation_id, "running", {"stage": "apply", "reason": reason}, active_step)

    def mark_failed(self, operation_id: str, reason: str) -> None:
        self._update_operation(operation_id, "failed", {"stage": "apply", "reason": bounded_error(reason)}, None)

    def complete_operation(self, operation_id: str, receipt: ApplyReceipt) -> None:
        current = self._records.find_operation(operation_id)
        if current is None:
            raise KeyError(operation_id)
        steps = list(current.completed_steps)
        if "apply" not in steps:
            steps.append("apply")
        self._records.update_operation(
            Operation(
                current.id,
                current.kind,
                current.target_id,
                current.desired_digest,
                "succeeded",
                steps,
                None,
                receipt,
                current.plan,
                current.remote_removal_confirmed,
                None,
                current.existing_reinstall_confirmed,
            )
        )

    def _update_operation(self, operation_id: str, state: str, error, active_step: str | None) -> None:
        current = self._records.find_operation(operation_id)
        if current is None or current.state == "succeeded":
            return
        if isinstance(error, str):
            error_document = {"stage": "apply", "reason": bounded_error(error)}
        elif isinstance(error, dict):
            error_document = error
        else:
            error_document = None
        self._records.update_operation(
            Operation(
                current.id,
                current.kind,
                current.target_id,
                current.desired_digest,
                state,
                list(current.completed_steps),
                error_document,
                current.receipt,
                current.plan,
                current.remote_removal_confirmed,
                active_step,
                current.existing_reinstall_confirmed,
            )
        )


def notify_progress(callback, operation_id: str, step: str, state: str) -> None:
    if callback is None:
        return
    try:
        callback({"operation_id": operation_id, "step": step, "state": state})
    except Exception:
        return


def bounded_error(value: object) -> str:
    if isinstance(value, Exception):
        value = getattr(value, "reason", str(value))
    result = "".join(char for char in redact_text(str(value)) if char.isprintable())
    return result[:160] or "managed-node operation failed"


__all__ = ["ManagedNodeSyncOperations", "bounded_error", "notify_progress"]
