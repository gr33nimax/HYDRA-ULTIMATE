"""Confirmed install planning, durable enrollment steps and restart recovery."""

from __future__ import annotations

import ipaddress
import re
import secrets
from collections.abc import Callable
from typing import Any

from hydra.contracts.managed_node_installation import InstallPlan, InstallRequest
from hydra.contracts.managed_node_models import NodeDefinition, Operation, canonical_digest
from hydra.core.host import HostBackend
from hydra.services.managed_nodes.credentials import SshPasswordChannel
from hydra.services.managed_nodes.enrollment import NodeEnrollmentService
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.ssh import ManagedNodeSSH, SshFacts, SshOperationError
from hydra.utils.commands import redact_text

_SHA1 = re.compile(r"^[0-9a-f]{40}$")


def resolve_managed_node_revision(host: HostBackend, branch: str, repository: str) -> str:
    if branch not in {"main", "dev"}:
        raise ValueError("managed-node source branch must be main or dev")
    result = host.run(
        ["git", "ls-remote", "--exit-code", repository, f"refs/heads/{branch}"],
        timeout=20,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("selected managed-node source branch could not be resolved")
    fields = result.stdout.split()
    if len(fields) != 2 or not _SHA1.fullmatch(fields[0]) or fields[1] != f"refs/heads/{branch}":
        raise RuntimeError("selected managed-node source branch returned an invalid revision")
    return fields[0]


class InstallationService:
    def __init__(
        self,
        *,
        records: ManagedNodeRecords,
        ssh: ManagedNodeSSH,
        enrollment: NodeEnrollmentService,
        revision_resolver: Callable[[str], str],
        operation_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        self._records = records
        self._ssh = ssh
        self._enrollment = enrollment
        self._resolve_revision = revision_resolver
        self._new_operation_id = operation_id_factory

    def plan(self, request: InstallRequest, ssh_auth: SshPasswordChannel | None = None) -> InstallPlan:
        request.validate()
        revision = self._resolve_revision(request.branch)
        if not isinstance(revision, str) or not _SHA1.fullmatch(revision):
            raise ValueError("branch resolver did not return a full source revision")
        facts = self._ssh.inspect(request, ssh_auth)
        facts.validate()
        self._validate_os(facts)
        if facts.host_key_fingerprint != request.host_key_fingerprint:
            raise ValueError("SSH host identity changed after the operator pin")
        blocked = facts.used_ports | request.protocol_ports() | {request.ssh_port}
        control_port = request.control_port
        if control_port is None:
            candidates = [port for port in range(1024, 65536) if port not in blocked]
            if not candidates:
                raise ValueError("no unoccupied management port is available")
            control_port = secrets.choice(candidates)
        elif control_port in blocked:
            raise ValueError("management port conflicts with SSH, a selected protocol or a listening service")
        definition = NodeDefinition(
            id=request.id,
            name=request.name,
            address=str(ipaddress.ip_address(request.address)),
            ssh_user=request.ssh_user,
            branch=request.branch,
            revision=revision,
            control_port=control_port,
            protocols=request.protocols,
            identity_ref=f"managed-node/{request.id}",
            ssh_port=request.ssh_port,
        )
        warnings = (
            ["existing HYDRA installation requires separate reinstall confirmation"]
            if facts.existing_installation
            else []
        )
        plan = InstallPlan(
            definition=definition,
            existing_installation=facts.existing_installation,
            steps=[
                "remote-preflight",
                "bootstrap",
                "management-identity",
                "management-check",
                "protocol-and-user-apply",
            ],
            warnings=warnings,
            host_key_fingerprint=facts.host_key_fingerprint,
            source_address=str(ipaddress.ip_address(facts.source_address)),
            use_sudo=facts.uid != 0,
        )
        plan.validate()
        return plan

    def install(
        self,
        plan: InstallPlan,
        *,
        ssh_auth: SshPasswordChannel | None,
        confirmed: bool,
        reinstall_confirmed: bool = False,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        plan.validate()
        if type(confirmed) is not bool or type(reinstall_confirmed) is not bool:
            raise ValueError("installation confirmations must be booleans")
        if not confirmed:
            raise ValueError("installation requires explicit confirmation")
        operation = Operation(
            id=self._new_operation_id(),
            kind="install",
            target_id=plan.definition.id,
            desired_digest=canonical_digest(plan.to_document()),
            state="pending",
            plan=plan.to_document(),
            existing_reinstall_confirmed=reinstall_confirmed,
        )
        operation = self._records.begin_operation(operation)
        if plan.existing_installation and not reinstall_confirmed:
            return self._records.fail_operation(
                operation.id,
                stage="consent",
                reason="separate confirmation is required to uninstall the existing HYDRA installation",
                recovery_required=False,
            )
        current_definition = self._records.find_definition(plan.definition.id)
        if current_definition is not None and current_definition != plan.definition:
            return self._records.fail_operation(
                operation.id,
                stage="registration",
                reason="a different managed-node definition already uses this id",
                recovery_required=False,
            )
        self._records.put_definition(plan.definition)
        return self._continue(operation.id, plan, ssh_auth, progress)

    def resume(
        self,
        operation_id: str,
        *,
        ssh_auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        operation = self._records.find_operation(operation_id)
        if operation is None or operation.kind != "install":
            raise KeyError(f"unknown managed-node installation operation {operation_id}")
        if operation.state == "succeeded":
            return operation
        if operation.error and operation.error.get("stage") == "removal":
            return operation
        if operation.error and operation.error.get("stage") == "consent" and not operation.existing_reinstall_confirmed:
            return operation
        plan = InstallPlan.from_document(operation.plan)
        if operation.active_step is not None:
            try:
                if operation.active_step == "management_identity":
                    status = self._enrollment.recover_provision(plan, ssh_auth)
                else:
                    status = self._ssh.reconcile_install_step(plan, operation, ssh_auth)
            except Exception as exc:
                return self._fail(operation.id, exc, recovery_required=True, progress=progress)
            if status == "done":
                self._records.complete_step(operation.id, operation.active_step)
            elif status == "unknown":
                return self._records.fail_operation(
                    operation.id,
                    stage=operation.active_step,
                    reason="remote result is unknown; refusing to repeat the side effect",
                    recovery_required=True,
                )
        return self._continue(operation.id, plan, ssh_auth, progress)

    def _continue(
        self,
        operation_id: str,
        plan: InstallPlan,
        auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None,
    ) -> Operation:
        operation = self._records.find_operation(operation_id)
        if operation is None:
            raise KeyError(operation_id)
        if plan.existing_installation and "existing_uninstall" not in operation.completed_steps:
            if not operation.existing_reinstall_confirmed:
                return self._records.fail_operation(
                    operation_id,
                    stage="consent",
                    reason="separate reinstall consent is required",
                    recovery_required=False,
                )
            operation = self._step(
                operation_id, "existing_uninstall", lambda: self._ssh.uninstall_existing(plan, auth), progress
            )
            if operation.state in {"failed", "recovery_required"}:
                return operation
            operation = self._records.complete_step(operation_id, "existing_uninstall")
        if "bootstrap" not in operation.completed_steps:
            operation = self._step(operation_id, "bootstrap", lambda: self._ssh.bootstrap(plan, auth), progress)
            if operation.state in {"failed", "recovery_required"}:
                return operation
            operation = self._records.complete_step(operation_id, "bootstrap")
        if "management_identity" not in operation.completed_steps:
            operation = self._step(
                operation_id, "management_identity", lambda: self._enrollment.provision(plan, auth), progress
            )
            if operation.state in {"failed", "recovery_required"}:
                return operation
            operation = self._records.complete_step(operation_id, "management_identity")
        if "management_verified" not in operation.completed_steps:
            operation = self._step(operation_id, "management_verified", lambda: self._enrollment.verify(plan), progress)
            if operation.state in {"failed", "recovery_required"}:
                return operation
            operation = self._records.complete_step(operation_id, "management_verified")
        return self._finish(operation_id, progress)

    def _step(
        self,
        operation_id: str,
        step: str,
        action: Callable[[], Any],
        progress: Callable[[dict[str, str]], None] | None,
    ) -> Operation:
        operation = self._records.find_operation(operation_id)
        if operation is None:
            raise KeyError(operation_id)
        if step in operation.completed_steps:
            return operation
        operation = self._records.begin_step(operation_id, step)
        _notify(progress, operation_id, step, "started")
        try:
            action()
        except Exception as exc:
            if isinstance(exc, SshOperationError):
                unknown = exc.outcome_unknown
            else:
                unknown = step in {"bootstrap", "management_identity"} and not isinstance(exc, (ValueError, TypeError))
            failed = self._fail(operation_id, exc, recovery_required=unknown, progress=progress)
            return failed
        _notify(progress, operation_id, step, "succeeded")
        return self._records.find_operation(operation_id) or operation

    def _finish(
        self,
        operation_id: str,
        progress: Callable[[dict[str, str]], None] | None,
    ) -> Operation:
        operation = self._records.find_operation(operation_id)
        if operation is None:
            raise KeyError(operation_id)
        pending = Operation(
            operation.id,
            operation.kind,
            operation.target_id,
            operation.desired_digest,
            "running",
            list(operation.completed_steps),
            {"stage": "apply", "reason": "protocol and user apply is pending its owner"},
            operation.receipt,
            operation.plan,
            operation.remote_removal_confirmed,
            None,
            operation.existing_reinstall_confirmed,
        )
        result = self._records.update_operation(pending)
        _notify(progress, operation_id, "apply", "pending")
        return result

    def _fail(
        self,
        operation_id: str,
        error: Exception,
        *,
        recovery_required: bool,
        progress: Callable[[dict[str, str]], None] | None,
    ) -> Operation:
        stage = getattr(error, "stage", "installation")
        reason = redact_text(str(error))[:256]
        operation = self._records.fail_operation(
            operation_id,
            stage=str(stage),
            reason=reason,
            recovery_required=recovery_required,
        )
        _notify(progress, operation_id, str(stage), operation.state, reason)
        return operation

    @staticmethod
    def _validate_os(facts: SshFacts) -> None:
        match = re.match(r"^(\d+)\.(\d+)", facts.os_version)
        if match is None:
            raise ValueError("remote OS version could not be verified")
        version = tuple(map(int, match.groups()))
        minimum = (22, 4) if facts.os_id == "ubuntu" else (12, 0)
        if version < minimum:
            raise ValueError("remote OS is older than the supported Ubuntu 22.04/Debian 12 baseline")


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


__all__ = ["InstallationService"]
