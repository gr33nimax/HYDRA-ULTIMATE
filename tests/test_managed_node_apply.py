from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from typing import Any, cast

import pytest

from hydra.contracts.managed_node_models import NodeDesired, Operation, ProtocolAssignment, UserAssignment
from hydra.contracts.managed_node_observations import ConfirmedProfile
from hydra.core import state as state_backend
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.base import PluginCategory
from hydra.services.managed_nodes.apply import ManagedNodeApplyService
from hydra.services.managed_nodes.profile_store import ManagedNodeProfileStore
from hydra.services.managed_nodes.profiles import ManagedNodeProfileBuilder
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.runtime import ManagedNodeRuntime
from hydra.services.managed_nodes.snapshots import ManagedNodeSnapshotStore


class SystemdHost(HostBackend):
    active = True

    def run(self, args, **kwargs):
        if args[0] == "systemctl":
            output = (
                "ActiveState=active\nMainPID=123\nActiveEnterTimestampMonotonic=1000000\n"
                if self.active
                else "ActiveState=inactive\nMainPID=0\nActiveEnterTimestampMonotonic=\n"
            )
            return CompletedProcess(args, 0, output, "")
        raise AssertionError(f"unexpected host command: {args!r}")


class TransportOwner:
    def __init__(self):
        category = SimpleNamespace(value="transport")
        self.plugin = SimpleNamespace(meta=SimpleNamespace(name="vless", category=category))

    def list(self):
        return [self.plugin]


class ProfileBuilder:
    def build(self, state, node_id):
        return [
            ConfirmedProfile(f"profile-{user.uuid}", user.uuid, "vless", "direct")
            for user in state.users
            if not user.blocked
        ]


def desired() -> NodeDesired:
    return NodeDesired(
        "de-1",
        1,
        [UserAssignment("user-1", "one@example.test")],
        [ProtocolAssignment("vless", {"port": 443})],
    )


def setup_service(
    tmp_path: Path,
    *,
    host: SystemdHost | None = None,
    initial_state: AppState | None = None,
    fail_runtime: bool = False,
    fail_rollback: bool = False,
    desired_state: NodeDesired | None = None,
):
    host = host or SystemdHost()
    config = tmp_path / "sing-box.json"
    config.write_text("{}", encoding="utf-8")
    state_backend.save_state(initial_state or AppState(protocols={"vless": PluginState(enabled=False, port=443)}))
    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    plan = desired_state if desired_state is not None else desired()
    operation = Operation("apply-1", "apply", "de-1", plan.digest, "pending", plan=plan.to_document())
    records.begin_operation(operation)
    snapshots = ManagedNodeSnapshotStore(host=host, root=tmp_path / "snapshots")
    profiles = ManagedNodeProfileStore(host=host, root=tmp_path / "profiles")
    effects = []

    def apply_config(state):
        effects.append("config")
        state_backend.save_state(state)
        if fail_runtime:
            host.active = len(effects) > 1
        return not (fail_rollback and len(effects) > 1)

    def restore(snapshot):
        return state_backend.restore_desired_state(snapshot)

    def reconcile_users(state, users):
        assert snapshots.load("apply-1") is not None, "snapshot must be durable before user effects"
        state.users = users
        apply_config(state)

    service = ManagedNodeApplyService(
        node_id="de-1",
        records=records,
        state_reader=state_backend.load_state,
        restore_state=restore,
        reconcile_users=reconcile_users,
        apply_config=apply_config,
        protocols=cast(Any, TransportOwner()),
        runtime=ManagedNodeRuntime(host=host, config_path=config),
        profile_builder=cast(Any, ProfileBuilder()),
        profile_store=profiles,
        snapshots=snapshots,
        lock_path=tmp_path / "apply.lock",
    )
    return service, records, profiles, snapshots, host, effects


def test_apply_snapshots_before_effects_and_returns_receipt_only_after_runtime_proof(tmp_path: Path):
    service, records, profiles, snapshots, _host, effects = setup_service(tmp_path)

    result = service.apply("apply-1")

    assert result.state == "succeeded"
    assert result.receipt is not None and result.receipt.runtime_id
    stored = records.find_operation("apply-1")
    assert stored is not None
    assert stored.receipt == result.receipt
    assert profiles.read("de-1", receipt_is_committed=lambda bundle: bundle.receipt == result.receipt) is not None
    assert snapshots.load("apply-1") is None
    assert effects == ["config"]
    assert [user.uuid for user in state_backend.load_state().users] == ["user-1"]


def test_removing_last_protocol_disables_runtime_assignment_and_commits_empty_profiles(tmp_path):
    state = AppState(protocols={"vless": PluginState(enabled=True, installed=True, port=443,
                                                     config={"server_private_key": "keep-local-material"})})
    empty = NodeDesired("de-1", 2, [UserAssignment("user-1", "one@example.test")], [])
    service, records, profiles, snapshots, _host, effects = setup_service(tmp_path, initial_state=state, desired_state=empty)
    service._profile_builder = ManagedNodeProfileBuilder(protocols=SimpleNamespace(get=lambda name: None))
    result = service.apply("apply-1")
    persisted = state_backend.load_state()
    assert result.state == "succeeded" and result.receipt is not None
    assert persisted.protocols["vless"].enabled is False
    assert persisted.protocols["vless"].config["server_private_key"] == "keep-local-material"
    bundle = profiles.read("de-1", receipt_is_committed=lambda item: item.receipt == result.receipt)
    assert bundle is not None and bundle.profiles == []
    assert records.find_operation("apply-1").receipt == bundle.receipt
    assert snapshots.load("apply-1") is None and effects == ["config"]


def test_apply_keeps_node_local_material_and_user_accounting_by_identity(tmp_path: Path):
    user = User(
        email="before@example.test",
        uuid="user-1",
        traffic_used_bytes=37,
        credentials={"vless": {"private_key": "node-private", "traffic_used_bytes": 37}},
        devices={"device-1": {"first_seen": "local"}},
    )
    state = AppState(
        users=[user],
        protocols={
            "vless": PluginState(
                enabled=True,
                installed=True,
                port=443,
                config={"server_private_key": "node-private"},
            )
        },
    )
    service, _records, _profiles, _snapshots, _host, _effects = setup_service(tmp_path, initial_state=state)

    result = service.apply("apply-1")

    persisted = state_backend.load_state()
    assert result.state == "succeeded"
    assert persisted.users[0].email == "one@example.test"
    assert persisted.users[0].traffic_used_bytes == 37
    assert persisted.users[0].credentials["vless"]["private_key"] == "node-private"
    assert persisted.users[0].devices == {"device-1": {"first_seen": "local"}}
    assert persisted.protocols["vless"].config["server_private_key"] == "node-private"


def test_failed_runtime_proof_rolls_back_persisted_users_without_receipt(tmp_path: Path):
    service, records, profiles, snapshots, host, effects = setup_service(tmp_path, fail_runtime=True)

    with pytest.raises(RuntimeError, match="runtime could not be confirmed"):
        service.apply("apply-1")

    failed = records.find_operation("apply-1")
    assert failed is not None
    restored = state_backend.load_state()
    assert failed.state == "failed" and failed.receipt is None
    assert restored.users == []
    assert restored.protocols["vless"].enabled is False
    assert host.active is True
    assert effects == ["config", "config"]
    assert snapshots.load("apply-1") is None
    assert profiles.read("de-1") is None


def test_failed_apply_records_a_bounded_redacted_reason(tmp_path: Path):
    service, records, _profiles, _snapshots, _host, _effects = setup_service(tmp_path)

    def fail_with_secret(state: AppState, users: list[User]) -> None:
        raise RuntimeError("password=supersecret " + "x" * 300)

    service._reconcile_users = fail_with_secret
    with pytest.raises(RuntimeError, match="password="):
        service.apply("apply-1")

    failed = records.find_operation("apply-1")
    assert failed is not None and failed.error is not None
    reason = failed.error["reason"]
    assert "supersecret" not in reason
    assert "<redacted>" in reason
    assert len(reason) <= 160


def test_failed_rollback_keeps_snapshot_and_marks_operation_for_recovery(tmp_path: Path):
    service, records, profiles, snapshots, _host, effects = setup_service(
        tmp_path, fail_runtime=True, fail_rollback=True
    )

    with pytest.raises(RuntimeError, match="runtime could not be confirmed"):
        service.apply("apply-1")

    failed = records.find_operation("apply-1")
    assert failed is not None
    assert failed.state == "recovery_required"
    assert failed.error is not None
    assert failed.error["rollback_reason"] == "previous runtime configuration could not be restored"
    assert state_backend.load_state().users == []
    assert snapshots.load("apply-1") is not None
    assert profiles.read("de-1") is None
    assert effects == ["config", "config"]
