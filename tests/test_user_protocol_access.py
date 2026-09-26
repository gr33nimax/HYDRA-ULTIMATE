"""A user's disabled protocol must be absent from server authentication."""

from typing import cast
from unittest.mock import patch

import pytest

from hydra.core.state_models import AppState, PluginState, User, validate_state
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.invoker import PluginInvoker
from hydra.services.user_lifecycle import UserLifecycleOperations


def _state():
    return AppState(
        users=[User(email="alice", uuid="user-a"), User(email="bob", uuid="user-b")],
        protocols={"anytls": PluginState(enabled=True, config={"domain": "example.test"})},
    )


def _lifecycle(apply, saved):
    return UserLifecycleOperations(
        transports=lambda: [AnyTLSPlugin()],
        apply_config=apply,
        save_state=lambda state: saved.append(state.users[0].disabled_protocols[:]),
        last_apply_error=lambda: "",
        log_rollback_error=lambda _: None,
        invoker=PluginInvoker(),
    )


def test_revoke_one_protocol_removes_only_that_server_account():
    state = _state()
    saved = []
    operations = _lifecycle(lambda _: True, saved)
    operations.set_protocol_enabled(state, "alice", "anytls", False)

    with patch("pathlib.Path.exists", return_value=True):
        accounts = cast(list[dict[str, str]], PluginInvoker().configure(AnyTLSPlugin(), state).inbounds[0]["users"])
    assert [account["name"] for account in accounts] == ["bob"]
    assert state.users[0].disabled_protocols == ["anytls"]
    assert state.users[1].disabled_protocols == []
    assert saved == [["anytls"]]

    operations.set_protocol_enabled(state, "alice", "anytls", True)
    with patch("pathlib.Path.exists", return_value=True):
        accounts = cast(list[dict[str, str]], PluginInvoker().configure(AnyTLSPlugin(), state).inbounds[0]["users"])
    assert {account["name"] for account in accounts} == {"alice", "bob"}


def test_failed_server_apply_restores_access_and_persisted_state():
    state = _state()
    saved = []
    operations = _lifecycle(lambda _: len(saved) > 1, saved)
    with pytest.raises(RuntimeError, match="rolled back"):
        operations.set_protocol_enabled(state, "alice", "anytls", False)

    assert state.users[0].disabled_protocols == []
    assert saved == [["anytls"], []]
    with patch("pathlib.Path.exists", return_value=True):
        accounts = cast(list[dict[str, str]], PluginInvoker().configure(AnyTLSPlugin(), state).inbounds[0]["users"])
    assert {account["name"] for account in accounts} == {"alice", "bob"}


def test_invalid_protocol_denylist_is_rejected():
    state = _state()
    state.users[0].disabled_protocols = ["anytls", "anytls"]
    with pytest.raises(ValueError, match="disabled_protocols"):
        validate_state(state)
