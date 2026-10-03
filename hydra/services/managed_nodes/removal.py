"""Confirmed remote uninstall with durable receipt-gated local cleanup."""

from __future__ import annotations

import secrets
from collections.abc import Callable

from hydra.contracts.managed_node_installation import InstallPlan
from hydra.contracts.managed_node_models import Operation, canonical_digest
from hydra.services.managed_nodes.credentials import ManagementCredentialStore, SshPasswordChannel
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.ssh import ManagedNodeSSH, SshOperationError
from hydra.utils.commands import redact_text


class NodeRemovalService:
    def __init__(
        self,
        *,
        records: ManagedNodeRecords,
        ssh: ManagedNodeSSH,
        credentials: ManagementCredentialStore,
        operation_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        self._records = records
        self._ssh = ssh
        self._credentials = credentials
        self._new_operation_id = operation_id_factory

    def remove(
        self,
        node_id: str,
        *,
        confirmed: bool,
        ssh_auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        if type(confirmed) is not bool or not confirmed:
            raise ValueError("node removal requires explicit confirmation")
        definition = self._records.find_definition(node_id)
        if definition is None:
            raise KeyError(f"unknown managed node {node_id}")
        namespace = self._records.read_namespace()
        if any(node_id in {item.entry_id, item.exit_id} for item in namespace.cascades):
            raise ValueError("managed-node cascades must be removed before deleting a participant")
        install_operation = next(
            (
                item for item in reversed(namespace.operations)
                if item.kind == "install" and item.target_id == node_id and item.state == "succeeded"
            ),
            None,
        )
        if install_operation is None:
            raise ValueError("node does not have a completed pinned installation plan")
        install_plan = InstallPlan.from_document(install_operation.plan)
        operation = Operation(
            id=self._new_operation_id(),
            kind="remove",
            target_id=node_id,
            desired_digest=canonical_digest(install_plan.to_document()),
            state="pending",
            plan={"installation": install_plan.to_document()},
        )
        operation = self._records.begin_operation(operation)
        return self._run_remote(operation, install_plan, ssh_auth, progress)

    def resume(
        self,
        operation_id: str,
        *,
        ssh_auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        operation = self._records.find_operation(operation_id)
        if operation is None or operation.kind != "remove":
            raise KeyError(f"unknown managed-node removal operation {operation_id}")
        if operation.state == "succeeded":
            return operation
        install_plan = _plan_from_operation(operation)
        if operation.remote_removal_confirmed:
            return self._finish_local(operation, progress)
        if operation.active_step is not None:
            try:
                outcome = self._ssh.reconcile_remove(install_plan, operation, ssh_auth)
            except Exception as exc:
                return self._fail(operation.id, exc, recovery_required=True, progress=progress)
            if outcome == "done":
                operation = self._remote_removed(operation.id)
                return self._finish_local(operation, progress)
            if outcome == "unknown":
                return self._records.fail_operation(
                    operation.id,
                    stage=operation.active_step,
                    reason="remote uninstall result is unknown; local record is retained",
                    recovery_required=True,
                )
        return self._run_remote(operation, install_plan, ssh_auth, progress)

    def _run_remote(
        self,
        operation: Operation,
        plan: InstallPlan,
        auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None,
    ) -> Operation:
        current = self._records.find_operation(operation.id)
        if current is None:
            raise KeyError(operation.id)
        self._records.begin_step(operation.id, "remote_uninstall")
        _notify(progress, operation.id, "remote_uninstall", "started")
        try:
            self._ssh.remove_node(plan, auth)
        except Exception as exc:
            unknown = exc.outcome_unknown if isinstance(exc, SshOperationError) else True
            return self._fail(operation.id, exc, recovery_required=unknown, progress=progress)
        _notify(progress, operation.id, "remote_uninstall", "succeeded")
        self._remote_removed(operation.id)
        current = self._records.find_operation(operation.id)
        if current is None:
            raise KeyError(operation.id)
        return self._finish_local(current, progress)

    def _remote_removed(self, operation_id: str) -> Operation:
        self._records.confirm_remote_removal(operation_id)
        return self._records.complete_step(operation_id, "remote_uninstall")

    def _finish_local(
        self,
        operation: Operation,
        progress: Callable[[dict[str, str]], None] | None,
    ) -> Operation:
        install_plan = _plan_from_operation(operation)
        if "credential_cleanup" not in operation.completed_steps:
            self._records.begin_step(operation.id, "credential_cleanup")
            _notify(progress, operation.id, "credential_cleanup", "started")
            try:
                self._credentials.cleanup(install_plan.definition.identity_ref)
            except Exception as exc:
                return self._fail(operation.id, exc, recovery_required=True, progress=progress)
            self._records.complete_step(operation.id, "credential_cleanup")
        if not self._records.complete_removal(operation.id):
            return self._records.fail_operation(
                operation.id,
                stage="local-cleanup",
                reason="remote uninstall is confirmed but local record cleanup did not complete",
                recovery_required=True,
            )
        _notify(progress, operation.id, "credential_cleanup", "succeeded")
        return self._records.find_operation(operation.id) or operation

    def _fail(
        self,
        operation_id: str,
        error: Exception,
        *,
        recovery_required: bool,
        progress: Callable[[dict[str, str]], None] | None,
    ) -> Operation:
        stage = str(getattr(error, "stage", "node-removal"))
        reason = redact_text(str(error))[:256]
        operation = self._records.fail_operation(
            operation_id, stage=stage, reason=reason,
            recovery_required=recovery_required,
        )
        _notify(progress, operation_id, stage, operation.state, reason)
        return operation


def _notify(
    callback: Callable[[dict[str, str]], None] | None,
    operation_id: str,
    step: str,
    state: str,
    reason: str = "",
) -> None:
    if callback is None:
        return
    event = {"operation_id": operation_id, "step": step, "state": state}
    if reason:
        event["reason"] = redact_text(reason)[:160]
    try:
        callback(event)
    except Exception:
        return


def _plan_from_operation(operation: Operation) -> InstallPlan:
    if not isinstance(operation.plan, dict) or set(operation.plan) != {"installation"}:
        raise ValueError("removal operation has an invalid installation plan")
    return InstallPlan.from_document(operation.plan["installation"])


__all__ = ["NodeRemovalService"]
