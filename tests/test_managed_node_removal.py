from __future__ import annotations

from pathlib import Path

from hydra.contracts.managed_node_installation import InstallPlan
from hydra.contracts.managed_node_models import NodeDefinition, Operation, ProtocolAssignment, canonical_digest
from hydra.core import state as state_backend
from hydra.core.host import HostBackend
from hydra.services.managed_nodes.credentials import ManagementCredentialStore
from hydra.services.managed_nodes.operations import ManagedNodeOperationsService
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.ssh import SshOperationError

_SHA = "a" * 40
_FINGERPRINT = "SHA256:" + "A" * 43


class RemovalRemote:
    def __init__(self, *, online: bool):
        self.online = online
        self.removed = False
        self.calls = 0

    def discover_host_key(self, address, port):
        assert address and port == 22
        return _FINGERPRINT

    def remove_node(self, plan, auth):
        self.calls += 1
        if not self.online:
            raise SshOperationError("ssh-connect", "node is offline", outcome_unknown=True)
        self.removed = True

    def reconcile_remove(self, plan, operation, auth):
        return "done" if self.removed else "unknown"

    def inspect(self, request, auth):
        raise AssertionError("removal must not run installation preflight")

    def uninstall_existing(self, plan, auth):
        raise AssertionError("removal must not re-install")

    def bootstrap(self, plan, auth):
        raise AssertionError("removal must not bootstrap")

    def provision_management(self, plan, base_certificate, auth):
        raise AssertionError("removal must not enroll")

    def read_public_certificate(self, plan, auth):
        raise AssertionError("removal must not read a new identity")

    def reconcile_install_step(self, plan, operation, auth):
        raise AssertionError("removal must not reconcile installation")


def installed_node(records: ManagedNodeRecords) -> InstallPlan:
    definition = NodeDefinition(
        "de-1", "DE-1", "203.0.113.4", "operator", "dev", _SHA, 25555,
        [ProtocolAssignment("vless", {"port": 443})], "managed-node/de-1", 22,
    )
    plan = InstallPlan(
        definition, False, ["bootstrap", "management-identity", "management-check"],
        host_key_fingerprint=_FINGERPRINT, source_address="198.51.100.8", use_sudo=True,
    )
    operation = Operation(
        "install-done", "install", definition.id, canonical_digest(plan.to_document()),
        "pending", plan=plan.to_document(),
    )
    records.begin_operation(operation)
    records.put_definition(definition)
    for step in ("bootstrap", "management_identity", "management_verified", "apply"):
        records.begin_step(operation.id, step)
        records.complete_step(operation.id, step)
    current = records.find_operation(operation.id)
    assert current is not None
    records.update_operation(Operation(
        current.id, current.kind, current.target_id, current.desired_digest,
        "succeeded", current.completed_steps, None, current.receipt, current.plan,
        current.remote_removal_confirmed, None, current.existing_reinstall_confirmed,
    ))
    return plan


def make_service(tmp_path: Path, remote: RemovalRemote, *, cleanup=None):
    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    installed_node(records)
    credentials = cleanup or ManagementCredentialStore(host=HostBackend(), root=tmp_path / "credentials")
    service = ManagedNodeOperationsService(
        records=records,
        ssh=remote,
        credentials=credentials,
        revision_resolver=lambda _branch: _SHA,
        operation_id_factory=lambda: "remove-1",
    )
    return service, records


def test_offline_remove_keeps_definition_and_resume_does_not_repeat_unknown_uninstall(tmp_path: Path):
    remote = RemovalRemote(online=False)
    service, records = make_service(tmp_path, remote)
    operation = service.remove("de-1", True, None)

    assert operation.state == "recovery_required"
    assert operation.active_step == "remote_uninstall"
    assert records.find_definition("de-1") is not None
    assert remote.calls == 1

    resumed = service.resume(operation.id, None)
    assert resumed.state == "recovery_required"
    assert records.find_definition("de-1") is not None
    assert remote.calls == 1


def test_remote_uninstall_receipt_allows_local_retry_without_second_remote_call(tmp_path: Path):
    class FailCleanupOnce(ManagementCredentialStore):
        def __init__(self):
            super().__init__(host=HostBackend(), root=tmp_path / "credentials")
            self.cleanup_calls = 0

        def cleanup(self, identity_ref):
            self.cleanup_calls += 1
            if self.cleanup_calls == 1:
                raise OSError("local credential store temporarily unavailable")
            return super().cleanup(identity_ref)

    remote = RemovalRemote(online=True)
    credentials = FailCleanupOnce()
    service, records = make_service(tmp_path, remote, cleanup=credentials)
    pending = service.remove("de-1", True, None)
    assert pending.state == "recovery_required"
    assert pending.remote_removal_confirmed is True
    assert pending.active_step == "credential_cleanup"
    assert records.find_definition("de-1") is not None
    assert remote.calls == 1

    result = service.resume(pending.id, None)
    assert result.state == "succeeded"
    assert result.remote_removal_confirmed is True
    assert records.find_definition("de-1") is None
    assert remote.calls == 1
    assert credentials.cleanup_calls == 2


def test_unconfirmed_remove_has_no_journal_or_remote_effect(tmp_path: Path):
    remote = RemovalRemote(online=True)
    service, records = make_service(tmp_path, remote)
    try:
        service.remove("de-1", False, None)
    except ValueError as exc:
        assert "confirmation" in str(exc)
    else:
        raise AssertionError("unconfirmed removal must be rejected")
    assert remote.calls == 0
    assert records.find_definition("de-1") is not None
    assert [item for item in records.list_operations() if item.kind == "remove"] == []
