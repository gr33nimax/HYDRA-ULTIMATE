from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from hydra.core.hydrabox_keys import (
    generate_hydrabox_jwe_key,
    hydrabox_jwe_kid,
)
from hydra.core.state_migrations import migrate_v5_to_v6
from hydra.core.state_models import AppState, User
from hydra.plugins.invoker import PluginInvoker
from hydra.services.user_lifecycle import UserLifecycleOperations
from hydra.services.subscriptions.jwe import (
    decrypt_hydrabox_subscription,
    encrypt_hydrabox_subscription,
)


def _operations(save_state):
    return UserLifecycleOperations(
        transports=lambda: [],
        apply_config=lambda state: True,
        save_state=save_state,
        last_apply_error=lambda: "",
        log_rollback_error=lambda message: None,
        invoker=PluginInvoker(),
    )


def test_v5_to_v6_is_pure_and_reserves_private_key_field():
    source = {"version": 5, "users": [{"email": "a", "uuid": "token"}]}

    migrated = migrate_v5_to_v6(source)

    assert source == {"version": 5, "users": [{"email": "a", "uuid": "token"}]}
    assert migrated["version"] == 6
    assert migrated["users"][0]["hydrabox_jwe_key"] == ""


def test_shared_hydrabox_jwe_interoperability_vector():
    vector = json.loads(
        (Path(__file__).parent / "fixtures" / "hydrabox-jwe-v1.json").read_text(
            encoding="utf-8",
        ),
    )
    payload = encrypt_hydrabox_subscription(
        vector["plaintext"],
        vector["key"],
        iv=bytes.fromhex(vector["iv_hex"]),
    )

    assert json.loads(payload) == vector["jwe"]
    assert hydrabox_jwe_kid(vector["key"]) == vector["kid"]
    assert decrypt_hydrabox_subscription(payload, vector["key"]) == vector["plaintext"]


def test_key_rotation_persists_new_key_and_invalidates_old_kid():
    user = User("alice", "token", hydrabox_jwe_key=generate_hydrabox_jwe_key())
    state = AppState(users=[user])
    old_key = user.hydrabox_jwe_key
    persisted: list[str] = []
    operations = _operations(
        lambda current: persisted.append(current.users[0].hydrabox_jwe_key),
    )

    with patch.object(UserLifecycleOperations, "_restart_subscriptions"):
        operations.rotate_hydrabox_key(state, "alice")

    assert persisted == [user.hydrabox_jwe_key]
    assert user.hydrabox_jwe_key != old_key
    assert hydrabox_jwe_kid(user.hydrabox_jwe_key) != hydrabox_jwe_kid(old_key)


def test_key_rotation_restores_in_memory_key_when_persistence_fails():
    old_key = generate_hydrabox_jwe_key()
    user = User("alice", "token", hydrabox_jwe_key=old_key)
    state = AppState(users=[user])

    def fail(_state):
        raise OSError("disk full")

    with pytest.raises(OSError, match="disk full"):
        _operations(fail).rotate_hydrabox_key(state, "alice")

    assert user.hydrabox_jwe_key == old_key
