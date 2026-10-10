from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable, cast

import pytest

from hydra.contracts.managed_node_models import CascadeDefinition, NodeDefinition, Operation, ProtocolAssignment
from hydra.contracts.managed_node_observations import SyncReport
from hydra.core.errors import StateConflictError
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState, User
from hydra.services.managed_nodes.credentials import ManagementCredentialStore
from hydra.services.managed_nodes.operations import ManagedNodeOperationsService
from hydra.services.managed_nodes.records import ManagedNodeRecords

_SHA = "a" * 40


def _fixture(tmp_path: Path, *, fail_update: bool = False):
    state = [AppState(users=[User("alice@example.test", "alice", expiry_date="2099-01-01")])]
    updates = []
    update_conflict = [False]

    def read_state():
        return copy.deepcopy(state[0])

    def update_state(mutate: Callable[[AppState], Any]):
        updates.append("update")
        if update_conflict[0]:
            raise StateConflictError("concurrent state revision")
        candidate = copy.deepcopy(state[0])
        result = mutate(candidate)
        candidate.revision = state[0].revision + 1
        state[0] = candidate
        return copy.deepcopy(candidate), copy.deepcopy(result)

    records = ManagedNodeRecords(state_reader=read_state, state_updater=update_state)
    definition = NodeDefinition(
        "de-1",
        "Germany",
        "203.0.113.4",
        "operator",
        "dev",
        _SHA,
        25555,
        [ProtocolAssignment("vless", {"port": 443})],
        "managed-node/de-1",
    )
    records.put_definition(definition)
    updates.clear()
    update_conflict[0] = fail_update
    service = ManagedNodeOperationsService(
        records=records,
        ssh=cast(Any, object()),  # This operation has no SSH/bootstrap effects.
        credentials=ManagementCredentialStore(host=HostBackend(), root=tmp_path / "credentials"),
        revision_resolver=lambda _branch: _SHA,
        operation_id_factory=lambda: "protocol-apply-1",
    )
    return state, records, service, updates


def test_protocol_definition_and_frozen_apply_intent_commit_before_sync(tmp_path: Path, monkeypatch):
    state, records, service, updates = _fixture(tmp_path)
    state[0].users[0].blocked = True
    state[0].users[0].expiry_date = "2099-12-31T23:59:59+00:00"
    state[0].users[0].disabled_protocols = ["anytls"]
    network_snapshots = []

    def sync(node_id):
        assert node_id == "de-1"
        namespace = records.read_namespace()
        operation = namespace.operations[-1]
        desired = namespace.apply_intents[operation.id]
        network_snapshots.append((operation, desired, namespace.definitions[0]))

    monkeypatch.setattr(service, "sync", sync)
    service.configure_protocol("de-1", ProtocolAssignment("vless", {"port": 8443}), confirmed=True)

    assert updates == ["update"]
    assert len(network_snapshots) == 1
    operation, desired, definition = network_snapshots[0]
    assert operation == Operation(
        "protocol-apply-1",
        "apply",
        "de-1",
        desired.digest,
        "pending",
        plan=desired.to_document(),
    )
    assert desired.users[0].blocked is True
    assert desired.users[0].expiry_date == "2099-12-31T23:59:59+00:00"
    assert desired.users[0].disabled_protocols == ["anytls"]
    assert definition.protocols == [ProtocolAssignment("vless", {"port": 8443})]


def test_state_conflict_before_protocol_commit_preserves_definition_and_never_syncs(tmp_path: Path, monkeypatch):
    _state, records, service, updates = _fixture(tmp_path, fail_update=True)
    network_calls = []
    monkeypatch.setattr(service, "sync", lambda _node_id: network_calls.append("sync"))
    original = records.find_definition("de-1")

    with pytest.raises(StateConflictError, match="concurrent state revision"):
        service.configure_protocol("de-1", ProtocolAssignment("vless", {"port": 8443}), confirmed=True)

    assert len(updates) == 1
    assert records.find_definition("de-1") == original
    assert records.list_operations() == []
    assert network_calls == []


def test_failure_after_atomic_protocol_commit_keeps_same_pending_intent_for_resume(tmp_path: Path, monkeypatch):
    _state, records, service, updates = _fixture(tmp_path)
    observed = []

    def fail_before_send(node_id):
        assert node_id == "de-1"
        namespace = records.read_namespace()
        operation = namespace.operations[-1]
        intent = namespace.apply_intents[operation.id]
        observed.append((operation.id, intent.to_document()))
        raise TimeoutError("injected before network send")

    monkeypatch.setattr(service, "sync", fail_before_send)
    with pytest.raises(TimeoutError, match="before network send"):
        service.configure_protocol("de-1", ProtocolAssignment("vless", {"port": 8443}), confirmed=True)

    assert updates == ["update"]
    assert len(observed) == 1
    operation_id, payload = observed[0]
    namespace = records.read_namespace()
    assert namespace.operations[-1].id == operation_id
    assert namespace.operations[-1].plan == payload
    assert namespace.apply_intents[operation_id].to_document() == payload


@pytest.mark.parametrize("keep_other", [False, True])
def test_protocol_removal_commits_remaining_protocols_and_intent_before_sync(tmp_path, monkeypatch, keep_other):
    from dataclasses import replace
    state, records, service, updates = _fixture(tmp_path)
    if keep_other:
        definition = records.find_definition("de-1")
        records.put_definition(replace(definition, protocols=[*definition.protocols, ProtocolAssignment("anytls", {"port": 443})]))
        updates.clear()
    report = SyncReport({"de-1": {"status": "pending", "operation_id": "protocol-apply-1"}})
    snapshots = []
    def sync(node_id):
        snapshots.append(records.read_namespace())
        return report
    monkeypatch.setattr(service, "sync", sync)
    assert service.remove_protocol("de-1", "vless", confirmed=True) == report
    assert updates == ["update"] and len(snapshots) == 1
    namespace = snapshots[0]
    expected = [ProtocolAssignment("anytls", {"port": 443})] if keep_other else []
    assert namespace.definitions[0].protocols == expected
    operation = namespace.operations[-1]
    intent = namespace.apply_intents[operation.id]
    assert operation.plan == intent.to_document()
    assert intent.protocols == expected
    assert intent.users[0].email == state[0].users[0].email
    assert operation.state == "pending"


def test_identical_protocol_settings_do_not_write_state_or_start_sync(tmp_path, monkeypatch):
    state, records, service, updates = _fixture(tmp_path)
    before = copy.deepcopy(state[0])
    monkeypatch.setattr(service, "sync", lambda node_id: pytest.fail("no-op must not sync"))
    assert service.configure_protocol("de-1", ProtocolAssignment("vless", {"port": 443}), confirmed=True) is None
    assert state[0] == before and updates == [] and records.list_operations() == []


@pytest.mark.parametrize("confirmed", [False, None, 1])
def test_protocol_removal_requires_explicit_confirmation(tmp_path, monkeypatch, confirmed):
    _state, records, service, updates = _fixture(tmp_path)
    monkeypatch.setattr(service, "sync", lambda node_id: pytest.fail("not confirmed"))
    with pytest.raises(ValueError, match="confirmation"):
        service.remove_protocol("de-1", "vless", confirmed=confirmed)
    assert updates == [] and records.list_operations() == []


def test_protocol_removal_conflict_preserves_definition_without_network_calls(tmp_path, monkeypatch):
    state, records, service, updates = _fixture(tmp_path, fail_update=True)
    before = copy.deepcopy(state[0])
    monkeypatch.setattr(service, "sync", lambda node_id: pytest.fail("commit failed"))
    with pytest.raises(StateConflictError):
        service.remove_protocol("de-1", "vless", confirmed=True)
    assert state[0] == before and records.list_operations() == []


def test_protocol_removal_failed_send_keeps_pending_intent_for_retry(tmp_path, monkeypatch):
    _state, records, service, updates = _fixture(tmp_path)
    def fail(node_id):
        raise TimeoutError("before send")
    monkeypatch.setattr(service, "sync", fail)
    with pytest.raises(TimeoutError, match="before send"):
        service.remove_protocol("de-1", "vless", confirmed=True)
    operation = records.list_operations()[-1]
    assert operation.state == "pending"
    assert records.find_apply_intent(operation.id).protocols == []
    assert updates == ["update"]


@pytest.mark.parametrize("blocker", ["cascade", "operation", "absent"])
def test_protocol_removal_rejects_blocked_or_unconfigured_targets(tmp_path, monkeypatch, blocker):
    from dataclasses import replace
    state, records, service, updates = _fixture(tmp_path)
    if blocker == "cascade":
        records.put_cascade(CascadeDefinition("route", "Route", "de-1", "base", ["vless"]))
    elif blocker == "operation":
        records.begin_operation(Operation("active-1", "apply", "de-1", "c" * 64, "pending"))
    else:
        records.put_definition(replace(records.find_definition("de-1"), protocols=[]))
    before = copy.deepcopy(state[0])
    monkeypatch.setattr(service, "sync", lambda node_id: pytest.fail("target is blocked"))
    with pytest.raises((ValueError, KeyError)):
        service.remove_protocol("de-1", "vless", confirmed=True)
    assert state[0] == before
