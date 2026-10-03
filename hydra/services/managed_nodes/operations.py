"""Application operations port and production composition for managed nodes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from hydra.contracts.managed_node_installation import InstallPlan, InstallRequest
from hydra.contracts.managed_node_models import CascadeDefinition, Operation, ProtocolAssignment
from hydra.contracts.managed_node_observations import ProtocolOption
from hydra.core.state_models import AppState, User
from hydra.contracts.managed_node_observations import DiagnosticReport, NodeView, SyncReport
from hydra.services.managed_nodes.cascade_runtime import CascadeRuntime
from hydra.services.managed_nodes.cascades import ManagedNodeCascadeService
from hydra.services.managed_nodes.credentials import ManagementCredentialStore, SshPasswordChannel
from hydra.services.managed_nodes.enrollment import ManagementStateClient, NodeEnrollmentService
from hydra.services.managed_nodes.installation import InstallationService
from hydra.services.managed_nodes.identity import ManagementIdentity
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.removal import NodeRemovalService
from hydra.services.managed_nodes.ssh import ManagedNodeSSH
from hydra.services.managed_nodes.status import ManagedNodeStatusService
from hydra.services.managed_nodes.sync import ManagedNodeSyncService


class ManagedNodeOperations(Protocol):
    def profiles_for_user(self, user: User, state: AppState) -> tuple[Any, ...]: ...
    def local_identity(self) -> ManagementIdentity | None: ...
    def discover_host_key(self, address: str, port: int) -> str: ...
    def cascade_options(self, entry_id: str, exit_id: str) -> list[ProtocolOption]: ...
    def save_cascade(self, definition: CascadeDefinition, confirmed: bool, progress=None) -> Operation: ...
    def configure_protocol(self, node_id: str, assignment: ProtocolAssignment, confirmed: bool) -> None: ...
    def rename_cascade(self, cascade_id: str, name: str) -> None: ...
    def remove_cascade(self, cascade_id: str, confirmed: bool, progress=None) -> Operation: ...
    def resume_cascade(self, operation_id: str, progress=None) -> Operation: ...
    def list_cascades(self) -> list[CascadeDefinition]: ...
    def plan(self, request: InstallRequest, ssh_auth: SshPasswordChannel | None) -> InstallPlan: ...
    def install(
        self,
        plan: InstallPlan,
        ssh_auth: SshPasswordChannel | None,
        confirmed: bool,
        reinstall_confirmed: bool,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation: ...
    def resume(
        self,
        operation_id: str,
        ssh_auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation: ...
    def list(self) -> list[NodeView]: ...
    def sync(
        self, node_id: str | None = None, progress: Callable[[dict[str, str]], None] | None = None
    ) -> SyncReport: ...
    def check(
        self, node_id: str, deep: bool, progress: Callable[[dict[str, str]], None] | None = None
    ) -> DiagnosticReport: ...
    def run_cycle(
        self, local_sync: Callable[[], tuple[AppState, dict[str, str], list[str]]]
    ) -> tuple[AppState, dict[str, str], list[str]]: ...
    def remove(
        self,
        node_id: str,
        confirmed: bool,
        ssh_auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation: ...


class UnavailableManagedNodeOperations:
    def profiles_for_user(self, user: User, state: AppState) -> tuple[Any, ...]:
        del user, state
        return ()

    def local_identity(self) -> ManagementIdentity | None:
        raise RuntimeError("managed-node identity is unavailable")

    def discover_host_key(self, address: str, port: int) -> str:
        raise RuntimeError("managed-node SSH operations are unavailable")

    def cascade_options(self, entry_id: str, exit_id: str) -> list[ProtocolOption]:
        raise RuntimeError("managed-node cascades are unavailable")

    def save_cascade(self, definition: CascadeDefinition, confirmed: bool, progress=None) -> Operation:
        raise RuntimeError("managed-node cascades are unavailable")

    def configure_protocol(self, node_id: str, assignment: ProtocolAssignment, confirmed: bool) -> None:
        raise RuntimeError("managed-node protocol operations are unavailable")

    def rename_cascade(self, cascade_id: str, name: str) -> None:
        raise RuntimeError("managed-node cascades are unavailable")

    def remove_cascade(self, cascade_id: str, confirmed: bool, progress=None) -> Operation:
        raise RuntimeError("managed-node cascades are unavailable")

    def resume_cascade(self, operation_id: str, progress=None) -> Operation:
        raise RuntimeError("managed-node cascades are unavailable")

    def list_cascades(self) -> list[CascadeDefinition]:
        raise RuntimeError("managed-node cascades are unavailable")

    def plan(self, request: InstallRequest, ssh_auth: SshPasswordChannel | None) -> InstallPlan:
        raise RuntimeError("managed-node operations are unavailable")

    def install(
        self,
        plan: InstallPlan,
        ssh_auth: SshPasswordChannel | None,
        confirmed: bool,
        reinstall_confirmed: bool,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        raise RuntimeError("managed-node operations are unavailable")

    def resume(
        self,
        operation_id: str,
        ssh_auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        raise RuntimeError("managed-node operations are unavailable")

    def list(self) -> list[NodeView]:
        raise RuntimeError("managed-node operations are unavailable")

    def sync(self, node_id: str | None = None, progress: Callable[[dict[str, str]], None] | None = None) -> SyncReport:
        raise RuntimeError("managed-node operations are unavailable")

    def check(
        self, node_id: str, deep: bool, progress: Callable[[dict[str, str]], None] | None = None
    ) -> DiagnosticReport:
        raise RuntimeError("managed-node operations are unavailable")

    def run_cycle(
        self, local_sync: Callable[[], tuple[AppState, dict[str, str], list[str]]]
    ) -> tuple[AppState, dict[str, str], list[str]]:
        return local_sync()

    def remove(
        self,
        node_id: str,
        confirmed: bool,
        ssh_auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        raise RuntimeError("managed-node operations are unavailable")


class ManagedNodeOperationsService:
    def __init__(
        self,
        *,
        records: ManagedNodeRecords,
        ssh: ManagedNodeSSH,
        credentials: ManagementCredentialStore,
        revision_resolver: Callable[[str], str],
        operation_id_factory: Callable[[], str],
        client_factory: Callable[..., ManagementStateClient] | None = None,
        sync_service: ManagedNodeSyncService | None = None,
        status_service: ManagedNodeStatusService | None = None,
        cascade_service: ManagedNodeCascadeService | None = None,
        local_identity_reader: Callable[[], ManagementIdentity | None] | None = None,
        profile_reader: Callable[[User, AppState], tuple[Any, ...]] | None = None,
        cascade_participant_owner: Any | None = None,
    ) -> None:
        self._records = records
        self._ssh = ssh
        self._new_operation_id = operation_id_factory
        self._installation = InstallationService(
            records=records,
            ssh=ssh,
            enrollment=NodeEnrollmentService(
                ssh=ssh,
                credentials=credentials,
                client_factory=client_factory,
            ),
            revision_resolver=revision_resolver,
            operation_id_factory=operation_id_factory,
        )
        self._sync_service = sync_service
        self._status_service = status_service
        self._cascade_service = cascade_service or ManagedNodeCascadeService(records=records, runtime=None)
        self._cascade_participant_owner = cascade_participant_owner
        self._local_identity_reader = local_identity_reader
        self._profile_reader = profile_reader
        self._removal = NodeRemovalService(
            records=records,
            ssh=ssh,
            credentials=credentials,
            operation_id_factory=operation_id_factory,
        )

    def profiles_for_user(self, user: User, state: AppState) -> tuple[Any, ...]:
        if self._profile_reader is None:
            return ()
        return self._profile_reader(user, state)

    def management_agent_cascade_owner(self) -> Any | None:
        """Expose the typed participant owner only to the production management adapter."""
        return self._cascade_participant_owner

    def local_identity(self) -> ManagementIdentity | None:
        if self._local_identity_reader is None:
            return None
        return self._local_identity_reader()

    def discover_host_key(self, address: str, port: int) -> str:
        return self._ssh.discover_host_key(address, port)

    def cascade_options(self, entry_id: str, exit_id: str) -> list[ProtocolOption]:
        return self._cascade_service.cascade_options(entry_id, exit_id)

    def list_cascades(self) -> list[CascadeDefinition]:
        return list(self._records.read_namespace().cascades)

    def save_cascade(self, definition: CascadeDefinition, confirmed: bool, progress=None) -> Operation:
        return self._cascade_service.save_cascade(definition, confirmed=confirmed, progress=progress)

    def configure_protocol(self, node_id: str, assignment: ProtocolAssignment, confirmed: bool) -> None:
        if type(confirmed) is not bool or not confirmed:
            raise ValueError("managed-node protocol changes require confirmation")
        self._records.begin_protocol_apply(node_id, assignment, self._new_operation_id())
        self.sync(node_id)
        return None

    def rename_cascade(self, cascade_id: str, name: str) -> None:
        self._cascade_service.rename_cascade(cascade_id, name)

    def remove_cascade(self, cascade_id: str, confirmed: bool, progress=None) -> Operation:
        return self._cascade_service.remove_cascade(cascade_id, confirmed=confirmed, progress=progress)

    def resume_cascade(self, operation_id: str, progress=None) -> Operation:
        return self._cascade_service.resume_cascade(operation_id, progress=progress)

    def plan(self, request: InstallRequest, ssh_auth: SshPasswordChannel | None) -> InstallPlan:
        return self._installation.plan(request, ssh_auth)

    def install(
        self,
        plan: InstallPlan,
        ssh_auth: SshPasswordChannel | None,
        confirmed: bool,
        reinstall_confirmed: bool,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        operation = self._installation.install(
            plan,
            ssh_auth=ssh_auth,
            confirmed=confirmed,
            reinstall_confirmed=reinstall_confirmed,
            progress=progress,
        )
        return self._finish_install_apply(operation, progress)

    def resume(
        self,
        operation_id: str,
        ssh_auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        operation = self._records.find_operation(operation_id)
        if operation is None:
            raise KeyError(f"unknown managed-node operation {operation_id}")
        if operation.kind == "install":
            operation = self._installation.resume(operation_id, ssh_auth=ssh_auth, progress=progress)
            return self._finish_install_apply(operation, progress)
        if operation.kind == "remove":
            return self._removal.resume(operation_id, ssh_auth=ssh_auth, progress=progress)
        raise ValueError("managed-node operation kind is unsupported")

    def list(self) -> list[NodeView]:
        if self._status_service is not None:
            return self._status_service.list()
        operations = self._records.list_operations()
        views: list[NodeView] = []
        for definition in self._records.list_definitions():
            related = [operation for operation in operations if operation.target_id == definition.id]
            latest = related[-1] if related else None
            sub_state = (
                "wait"
                if latest is not None and latest.state in {"pending", "running", "recovery_required"}
                else "error"
                if latest is not None and latest.state == "failed"
                else "unknown"
            )
            views.append(NodeView(definition=definition, sub_state=sub_state, operation=latest))
        return views

    def sync(self, node_id: str | None = None, progress: Callable[[dict[str, str]], None] | None = None) -> SyncReport:
        if self._sync_service is None:
            raise RuntimeError("managed-node sync is unavailable")
        return self._sync_service.sync(node_id, progress)

    def check(
        self, node_id: str, deep: bool, progress: Callable[[dict[str, str]], None] | None = None
    ) -> DiagnosticReport:
        if self._sync_service is None:
            raise RuntimeError("managed-node checks are unavailable")
        return self._sync_service.check(node_id, deep=deep, progress=progress)

    def run_cycle(
        self, local_sync: Callable[[], tuple[AppState, dict[str, str], list[str]]]
    ) -> tuple[AppState, dict[str, str], list[str]]:
        if self._sync_service is None:
            return local_sync()
        return self._sync_service.run_cycle(local_sync)

    def _finish_install_apply(self, operation: Operation, progress) -> Operation:
        if (
            self._sync_service is not None
            and operation.kind == "install"
            and operation.state == "running"
            and operation.error
            and operation.error.get("stage") == "apply"
        ):
            self._sync_service.sync(operation.target_id, progress)
            return self._records.find_operation(operation.id) or operation
        return operation

    def remove(
        self,
        node_id: str,
        confirmed: bool,
        ssh_auth: SshPasswordChannel | None,
        progress: Callable[[dict[str, str]], None] | None = None,
    ) -> Operation:
        return self._removal.remove(
            node_id,
            confirmed=confirmed,
            ssh_auth=ssh_auth,
            progress=progress,
        )


__all__ = [
    "ManagedNodeOperations",
    "ManagedNodeOperationsService",
    "UnavailableManagedNodeOperations",
]
