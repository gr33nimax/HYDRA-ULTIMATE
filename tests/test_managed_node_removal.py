from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from hydra.contracts.managed_node_installation import InstallPlan
from hydra.contracts.managed_node_models import CascadeDefinition, NodeDefinition, Operation, ProtocolAssignment, canonical_digest
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


def installed_node(records: ManagedNodeRecords, *, complete: bool = True) -> InstallPlan:
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
    if not complete:
        return plan
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


def make_service(tmp_path: Path, remote: RemovalRemote, *, cleanup=None, complete=True):
    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    installed_node(records, complete=complete)
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


@pytest.mark.parametrize("state", ["pending", "running", "failed", "recovery_required"])
@pytest.mark.parametrize("step", ["bootstrap", "management_identity", "management_verified", "apply"])
def test_remove_incomplete_install_and_prevent_its_resume(tmp_path: Path, state, step):
    remote = RemovalRemote(online=True)
    service, records = make_service(tmp_path, remote, complete=False)
    if state != "pending":
        records.begin_step("install-done", step)
        if state != "running":
            records.fail_operation("install-done", stage=step, reason="injected failure",
                                   recovery_required=state == "recovery_required")
    installation = records.find_operation("install-done")
    result = service.remove("de-1", True, None)
    assert result.state == "succeeded" and result.remote_removal_confirmed
    assert records.find_definition("de-1") is None
    cancelled = records.find_operation("install-done")
    assert cancelled.state == "failed" and cancelled.active_step is None
    assert cancelled.plan == installation.plan
    assert cancelled.completed_steps == installation.completed_steps
    assert service.resume(cancelled.id, None) == cancelled
    with pytest.raises(ValueError, match="superseded by removal"):
        records.begin_step(cancelled.id, "bootstrap")
    assert remote.calls == 1


def test_repeat_remove_resumes_local_cleanup_without_another_uninstall(tmp_path: Path):
    class FailCleanupOnce(ManagementCredentialStore):
        def cleanup(self, identity_ref):
            if not getattr(self, "attempted", False):
                self.attempted = True
                raise OSError("temporary failure")
            super().cleanup(identity_ref)

    remote = RemovalRemote(online=True)
    cleanup = FailCleanupOnce(host=HostBackend(), root=tmp_path / "credentials")
    service, records = make_service(tmp_path, remote, cleanup=cleanup, complete=False)
    first = service.remove("de-1", True, None)
    assert first.state == "recovery_required" and first.remote_removal_confirmed
    second = service.remove("de-1", True, None)
    assert second.id == first.id and second.state == "succeeded"
    assert records.find_definition("de-1") is None and remote.calls == 1


def test_offline_incomplete_node_is_retained_and_repeat_remove_reconciles(tmp_path: Path):
    remote = RemovalRemote(online=False)
    service, records = make_service(tmp_path, remote, complete=False)
    first = service.remove("de-1", True, None)
    assert first.state == "recovery_required" and records.find_definition("de-1") is not None
    second = service.remove("de-1", True, None)
    assert second.id == first.id and remote.calls == 1
    remote.online = True
    remote.reconcile_remove = lambda *_args: "retry"
    third = service.remove("de-1", True, None)
    assert third.id == first.id and third.state == "succeeded"
    assert records.find_definition("de-1") is None and remote.calls == 2


def test_removal_supersedes_pending_apply_and_preserves_successful_install(tmp_path: Path):
    remote = RemovalRemote(online=True)
    service, records = make_service(tmp_path, remote)
    install = records.find_operation("install-done")
    apply = records.begin_operation(Operation("apply-1", "apply", "de-1", "b" * 64, "pending"))
    records.begin_step(apply.id, "remote_apply")
    assert service.remove("de-1", True, None).state == "succeeded"
    assert records.find_operation(install.id) == install
    assert records.find_operation(apply.id).active_step is None
    with pytest.raises(ValueError, match="superseded by removal"):
        records.update_operation(replace(apply, state="running"))


def test_missing_plan_rejects_removal_without_ssh_or_state_changes(tmp_path: Path):
    remote = RemovalRemote(online=True)
    service, records = make_service(tmp_path, remote, complete=False)
    # A definition may survive a lost journal; never invent a remote identity.
    state_backend.update_state(lambda state: state.feature_extensions["managed_nodes"].update(operations=[]))
    before = state_backend.load_state()
    with pytest.raises(ValueError, match="pinned installation plan"):
        service.remove("de-1", True, None)
    assert state_backend.load_state() == before and remote.calls == 0


def test_removal_takeover_is_atomic_if_install_changed(tmp_path: Path):
    remote = RemovalRemote(online=True)
    service, records = make_service(tmp_path, remote, complete=False)
    original_begin = records.begin_removal

    def advance_install(operation, *, installation):
        records.begin_step(installation.id, "bootstrap")
        return original_begin(operation, installation=installation)

    records.begin_removal = advance_install
    with pytest.raises(ValueError, match="installation changed"):
        service.remove("de-1", True, None)
    assert records.find_operation("install-done").state == "running"
    assert not any(op.kind == "remove" for op in records.list_operations())
    assert records.find_definition("de-1") is not None and remote.calls == 0


def test_remove_install_waiting_for_initial_apply(tmp_path: Path):
    remote = RemovalRemote(online=True)
    service, records = make_service(tmp_path, remote, complete=False)
    for step in ("bootstrap", "management_identity", "management_verified"):
        records.begin_step("install-done", step)
        records.complete_step("install-done", step)
    current = records.find_operation("install-done")
    records.update_operation(replace(current, error={"stage": "apply", "reason": "apply pending"}))
    assert service.remove("de-1", True, None).state == "succeeded"
    assert remote.calls == 1


def test_cascade_blocks_incomplete_node_removal_without_cancelling_install(tmp_path: Path):
    remote = RemovalRemote(online=True)
    service, records = make_service(tmp_path, remote, complete=False)
    records.put_cascade(CascadeDefinition("route-1", "route", "base", "de-1", []))
    before = state_backend.load_state()
    with pytest.raises(ValueError, match="cascades must be removed"):
        service.remove("de-1", True, None)
    assert state_backend.load_state() == before and remote.calls == 0


def test_incomplete_node_removal_does_not_change_sibling_node_or_users(tmp_path: Path):
    remote = RemovalRemote(online=True)
    service, records = make_service(tmp_path, remote, complete=False)
    sibling = replace(records.find_definition("de-1"), id="uk-1", name="UK-1", address="203.0.113.5",
                      identity_ref="managed-node/uk-1")
    records.put_definition(sibling)
    sibling_install = records.begin_operation(Operation("install-uk", "install", "uk-1", "b" * 64, "pending"))
    before = state_backend.load_state()
    assert service.remove("de-1", True, None).state == "succeeded"
    assert records.find_definition(sibling.id) == sibling
    assert records.find_operation(sibling_install.id) == sibling_install
    after = state_backend.load_state()
    assert after.users == before.users and after.install == before.install
