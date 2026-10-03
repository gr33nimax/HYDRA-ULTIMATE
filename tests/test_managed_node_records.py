from __future__ import annotations

import copy

import pytest

from hydra.contracts.managed_node_models import NodeDefinition, Operation
from hydra.core import state as state_backend
from hydra.core.state_format import pack_state_document
from hydra.core.state_models import AppState, User
from hydra.services.managed_nodes import records


def node() -> NodeDefinition:
    return NodeDefinition(
        id="de-1", name="DE-1", address="203.0.113.4", ssh_user="root",
        branch="dev", revision="a" * 40, control_port=24443,
        protocols=[], identity_ref="managed-node/de-1",
    )


def record_store() -> records.ManagedNodeRecords:
    return records.ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)


def test_definition_write_round_trips_without_changing_users_or_subscription_data():
    before = AppState(
        users=[User(email="one@example.test", uuid="user-1")],
        install={"subscription_token": "stable-token"},
        network=copy.deepcopy(AppState().network),
        feature_extensions={"subscription-materials": {"active": ["kept"]}, "vendor": {"x": 1}},
    )
    state_backend.save_state(before)
    first = state_backend.load_state()

    store = record_store()
    store.put_definition(node())
    after = state_backend.load_state()

    assert after.users == first.users
    assert after.install == first.install
    assert after.network == first.network
    assert after.feature_extensions["subscription-materials"] == {"active": ["kept"]}
    assert after.feature_extensions["vendor"] == {"x": 1}
    assert after.revision > first.revision
    assert store.list_definitions() == [node()]


def test_old_nodes_namespace_is_opaque_and_never_becomes_a_new_definition():
    raw = pack_state_document(
        {
            "format_version": 1,
            "revision": 9,
            "feature_extensions": {"nodes": [{"id": "legacy", "api": "/old"}]},
        }
    )
    state_backend.STATE_DIR.mkdir(parents=True, exist_ok=True)
    state_backend.STATE_FILE.write_text(__import__("json").dumps(raw), encoding="utf-8")

    state = state_backend.load_state()
    assert record_store().list_definitions() == []
    assert state.feature_extensions["nodes"] == [{"id": "legacy", "api": "/old"}]
    state_backend.save_state(state)
    assert state_backend.load_state().feature_extensions["nodes"] == [{"id": "legacy", "api": "/old"}]


def test_same_operation_id_is_idempotent_only_for_the_same_digest():
    store = record_store()
    original = Operation("op-1", "install", "de-1", "a" * 64, "pending")
    assert store.begin_operation(original) == original
    assert store.begin_operation(original) == original
    changed = Operation("op-1", "install", "de-1", "b" * 64, "pending")
    with pytest.raises(ValueError, match="same operation id"):
        store.begin_operation(changed)


def test_offline_removal_cannot_delete_definition_but_receipt_allows_local_resume():
    store = record_store()
    store.put_definition(node())
    removal = Operation("remove-1", "remove", "de-1", "c" * 64, "pending")
    store.begin_operation(removal)
    assert not store.complete_removal("remove-1")
    assert store.find_definition("de-1") == node()

    confirmed = Operation(
        "remove-1", "remove", "de-1", "c" * 64, "recovery_required",
        completed_steps=["remote_uninstall"], remote_removal_confirmed=True,
    )
    store.update_operation(confirmed)
    assert store.complete_removal("remove-1")
    assert store.find_definition("de-1") is None
    completed = store.find_operation("remove-1")
    assert completed is not None and completed.remote_removal_confirmed is True


def test_unknown_namespace_version_is_rejected_without_fallback():
    state = AppState(feature_extensions={"managed_nodes": {"version": 99, "definitions": [], "cascades": [], "operations": []}})
    with pytest.raises(ValueError, match="unsupported managed_nodes"):
        state_backend.save_state(state)
