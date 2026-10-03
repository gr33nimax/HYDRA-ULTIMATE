from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable, cast

import pytest

from hydra.contracts.managed_node_models import NodeDefinition, Operation, ProtocolAssignment
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
