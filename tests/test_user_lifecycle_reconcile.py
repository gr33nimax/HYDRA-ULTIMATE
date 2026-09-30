from unittest.mock import Mock

import pytest

from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.invoker import PluginInvoker
from hydra.services.user_lifecycle import UserLifecycleOperations


def _operations(plugin, apply, saved):
    return UserLifecycleOperations(
        transports=lambda: [plugin],
        apply_config=apply,
        save_state=lambda state: saved.append([(user.email, user.uuid) for user in state.users]),
        last_apply_error=lambda: "",
        log_rollback_error=lambda _: None,
        invoker=PluginInvoker(),
    )


def test_reconcile_batches_user_add_remove_and_rename_into_one_apply():
    plugin = AnyTLSPlugin()
    plugin.on_user_add = Mock()
    plugin.on_user_remove = Mock()
    old = User(email="old", uuid="u1", credentials={"anytls": {"password": "local"}})
    state = AppState(
        users=[old, User(email="gone", uuid="u2")],
        protocols={"anytls": PluginState(enabled=True, installed=True)},
    )
    target = User(email="renamed", uuid="u1", credentials={"anytls": {"password": "local"}})
    added = User(email="new", uuid="u3")
    saves = []
    apply = Mock(return_value=True)

    _operations(plugin, apply, saves).reconcile_users(state, [target, added])

    assert [(user.email, user.uuid) for user in state.users] == [
        ("renamed", "u1"),
        ("new", "u3"),
    ]
    assert [call.args[0].email for call in plugin.on_user_remove.call_args_list] == ["old", "gone"]
    assert [call.args[0].email for call in plugin.on_user_add.call_args_list] == ["renamed", "new"]
    assert apply.call_count == 1
    assert saves == [[("renamed", "u1"), ("new", "u3")]]


def test_reconcile_rolls_back_plugin_and_state_when_apply_fails():
    plugin = AnyTLSPlugin()
    plugin.on_user_add = Mock()
    plugin.on_user_remove = Mock()
    old = User(email="alice", uuid="u1")
    state = AppState(
        users=[old],
        protocols={"anytls": PluginState(enabled=True, installed=True)},
    )
    apply = Mock(side_effect=[False, True])
    saves = []

    with pytest.raises(RuntimeError, match="rolled back"):
        _operations(plugin, apply, saves).reconcile_users(
            state,
            [User(email="bob", uuid="u2")],
        )

    assert [(user.email, user.uuid) for user in state.users] == [("alice", "u1")]
    assert [call.args[0].email for call in plugin.on_user_add.call_args_list] == ["bob", "alice"]
    assert [call.args[0].email for call in plugin.on_user_remove.call_args_list] == ["alice", "bob"]
    assert apply.call_count == 2


def test_reconcile_rollback_reblocks_previously_blocked_user():
    plugin = AnyTLSPlugin()
    plugin.on_user_add = Mock()
    plugin.on_user_block = Mock()
    old = User(email="alice", uuid="u1", blocked=True)
    state = AppState(
        users=[old],
        protocols={"anytls": PluginState(enabled=True, installed=True)},
    )
    apply = Mock(side_effect=[False, True])

    with pytest.raises(RuntimeError, match="rolled back"):
        _operations(plugin, apply, []).reconcile_users(
            state,
            [User(email="alice", uuid="u1", blocked=False)],
        )

    assert [call.args[0].blocked for call in plugin.on_user_add.call_args_list] == [False]
    assert [call.args[0].blocked for call in plugin.on_user_block.call_args_list] == [True]


def test_orchestration_service_forwards_bulk_reconcile_to_user_lifecycle(monkeypatch):
    from hydra.services.orchestration_service import OrchestrationService

    lifecycle = Mock()
    service = object.__new__(OrchestrationService)
    monkeypatch.setattr(service, "_user_lifecycle", lambda: lifecycle)
    state = AppState()
    users = [User(email="alice", uuid="u1")]

    getattr(service, "reconcile_users")(state, users)

    lifecycle.reconcile_users.assert_called_once_with(state, users)


def test_user_service_exposes_bulk_reconcile_at_the_application_boundary():
    from hydra.services.users import UserService

    operations = Mock()
    users = [User(email="alice", uuid="u1")]
    state = AppState()

    UserService(operations).reconcile(state, users)

    operations.reconcile_users.assert_called_once_with(state, users)
