from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hydra.contracts.node_snapshot import (
    NodeDesiredSnapshot,
    NodeProtocolSpec,
    NodeUserProjection,
)
from hydra.contracts.node_validation import NodeContractError
from hydra.core.state_models import AppState, PluginState, User
from hydra.services.nodes.reconcile import NodeReconciler


def _transport(name="vless"):
    return SimpleNamespace(
        meta=SimpleNamespace(
            name=name,
            capabilities=SimpleNamespace(
                subscription_enabled=True,
                hydra_v2_subscription_enabled=True,
            ),
        )
    )


def _snapshot(generation=4, **changes):
    values = {
        "node_id": "de-1",
        "generation": generation,
        "users": (
            NodeUserProjection(
                email="renamed@example.com",
                uuid="u1",
                blocked=True,
                expiry_date="2030-01-01",
                disabled_protocols=("vless",),
                traffic_limit_gb=8.5,
            ),
        ),
    }
    values.update(changes)
    return NodeDesiredSnapshot(**values)


def _reconciler(state):
    app = MagicMock()
    app.protocols.list.return_value = []
    app.protocols.enabled_subscription_names.return_value = set()
    app.users.reconcile.side_effect = lambda current, users: setattr(current, "users", users)
    app.admin.save_state.return_value = None
    return NodeReconciler("de-1", app, state_reader=lambda: state), app


def test_reconcile_preserves_node_credentials_counters_and_local_device_data():
    user = User(
        email="old@example.com",
        uuid="u1",
        traffic_used_bytes=1234,
        credentials={"awg": {"private_key": "node-only"}},
        devices={"device-1": {"first_seen": "local"}},
    )
    state = AppState(users=[user])
    reconciler, app = _reconciler(state)

    reconciler.apply(_snapshot())

    updated = state.users[0]
    assert updated.email == "renamed@example.com"
    assert updated.uuid == "u1"
    assert updated.blocked is True
    assert updated.expiry_date == "2030-01-01"
    assert updated.disabled_protocols == ["vless"]
    assert updated.traffic_limit_gb == 8.5
    assert updated.credentials == {"awg": {"private_key": "node-only"}}
    assert updated.traffic_used_bytes == 1234
    assert updated.devices == {"device-1": {"first_seen": "local"}}
    assert reconciler.current_generation() == 4
    app.admin.save_state.assert_called_once_with(state)


def test_snapshot_reset_epoch_clears_only_node_local_usage_and_report_is_absolute():
    user = User(
        email="renamed@example.com",
        uuid="u1",
        traffic_used_bytes=500,
        credentials={
            "vless": {
                "traffic_used_bytes": 500,
                "traffic_last_raw_bytes": 900,
                "private_key": "node-only",
            },
        },
    )
    state = AppState(users=[user])
    reconciler, app = _reconciler(state)
    snapshot = NodeDesiredSnapshot(
        node_id="de-1",
        generation=4,
        users=(NodeUserProjection(
            email=user.email,
            uuid=user.uuid,
            traffic_reset_epoch=2,
        ),),
    )

    reconciler.apply(snapshot)
    report = reconciler.traffic_report()

    assert state.users[0].traffic_used_bytes == 0
    assert state.users[0].credentials["vless"] == {
        "traffic_last_raw_bytes": 900,
        "private_key": "node-only",
        "traffic_used_bytes": 0,
    }
    assert report.generation == 4
    assert report.users["u1"].reset_epoch == 2
    assert report.users["u1"].used_bytes == 0
    app.admin.save_state.assert_called_once_with(state)


def test_stale_traffic_reset_epoch_is_rejected_without_commit():
    user = User(email="alice@example.com", uuid="u1", traffic_used_bytes=10)
    state = AppState(
        users=[user],
        install={"traffic_user_reset_epochs": {"u1": 3}},
    )
    reconciler, app = _reconciler(state)
    snapshot = NodeDesiredSnapshot(
        node_id="de-1",
        generation=4,
        users=(NodeUserProjection(
            email=user.email,
            uuid=user.uuid,
            traffic_reset_epoch=2,
        ),),
    )

    with pytest.raises(ValueError, match="reset epoch is stale"):
        reconciler.apply(snapshot)

    assert user.traffic_used_bytes == 10
    assert reconciler.current_generation() == 0
    app.admin.save_state.assert_called_once_with(state)


def test_repeated_generation_is_idempotent():
    state = AppState()
    reconciler, app = _reconciler(state)
    snapshot = NodeDesiredSnapshot(node_id="de-1", generation=4)

    reconciler.apply(snapshot)
    reconciler.apply(snapshot)

    app.users.reconcile.assert_not_called()
    app.admin.save_state.assert_called_once()
    assert reconciler.current_generation() == 4


def test_stale_generation_is_rejected_without_mutation():
    state = AppState(feature_extensions={"hydra_node_control": {"generation": 8}})
    reconciler, app = _reconciler(state)

    with pytest.raises(ValueError, match="stale generation"):
        reconciler.apply(NodeDesiredSnapshot(node_id="de-1", generation=7))

    app.users.reconcile.assert_not_called()
    app.admin.save_state.assert_not_called()


def test_invalid_export_rolls_back_snapshot_before_generation_commit():
    state = AppState()
    reconciler, app = _reconciler(state)
    app.protocols.enabled_subscription_names.return_value = {"vless"}
    app.protocols.client_profiles.return_value = []
    app.protocols.client_links.return_value = ["not-a-client-link"]
    app.protocols.client_config.return_value = ""
    snapshot = NodeDesiredSnapshot(
        node_id="de-1",
        generation=4,
        users=(NodeUserProjection(email="alice", uuid="u1"),),
    )

    with pytest.raises(NodeContractError, match="link"):
        reconciler.apply(snapshot)

    assert state.users == []
    assert reconciler.current_generation() == 0


def test_protocol_reconcile_keeps_local_private_key_and_replaces_public_config():
    state = AppState(
        protocols={
            "vless": PluginState(
                installed=True,
                config={
                    "tls": {"server_private_key": "node-key", "server_name": "old.example"},
                    "removed_option": True,
                },
            ),
        }
    )
    app = MagicMock()
    app.protocols.list.return_value = [_transport()]
    app.protocols.enabled_subscription_names.return_value = set()
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)
    snapshot = NodeDesiredSnapshot(
        node_id="de-1",
        generation=1,
        protocols={
            "vless": NodeProtocolSpec(
                enabled=False,
                port=8443,
                config={"tls": {"server_name": "new.example"}, "new_option": True},
            )
        },
    )

    reconciler.apply(snapshot)

    assert state.protocols["vless"].config == {
        "tls": {"server_private_key": "node-key", "server_name": "new.example"},
        "new_option": True,
    }
    assert state.protocols["vless"].port == 8443
    app.apply.assert_called_once_with(state)


def test_selected_protocol_uses_existing_install_and_enable_owners():
    state = AppState()
    app = MagicMock()
    app.protocols.list.return_value = [_transport()]
    app.protocols.enabled_subscription_names.return_value = set()
    app.protocols.enable.side_effect = lambda current, name: (
        setattr(
            current.protocols[name],
            "enabled",
            True,
        )
        or True
    )
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)

    reconciler.apply(
        NodeDesiredSnapshot(
            node_id="de-1",
            generation=1,
            protocols={"vless": NodeProtocolSpec(enabled=True, port=443)},
        )
    )

    app.protocols.install.assert_called_once_with(state, "vless")
    app.protocols.enable.assert_called_once_with(state, "vless")
    assert state.protocols["vless"].enabled is True


def test_protocol_failure_rolls_back_users_and_newly_enabled_protocol():
    state = AppState(users=[User(email="old", uuid="u1")])
    app = MagicMock()
    app.protocols.list.return_value = [_transport("vless"), _transport("trojan")]
    app.protocols.enabled_subscription_names.return_value = set()
    app.users.reconcile.side_effect = lambda current, users: setattr(current, "users", users)
    app.protocols.enable.side_effect = lambda current, name: (
        setattr(
            current.protocols[name],
            "enabled",
            True,
        )
        or True
    )
    app.protocols.disable.side_effect = lambda current, name: (
        setattr(
            current.protocols[name],
            "enabled",
            False,
        )
        or True
    )
    app.protocols.install.side_effect = lambda current, name: name == "vless"
    app.protocols.uninstall.side_effect = lambda current, name: (
        setattr(
            current.protocols[name],
            "installed",
            False,
        )
        or True
    )
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)
    snapshot = NodeDesiredSnapshot(
        node_id="de-1",
        generation=1,
        users=(NodeUserProjection(email="renamed", uuid="u1"),),
        protocols={
            "vless": NodeProtocolSpec(enabled=True, port=443),
            "trojan": NodeProtocolSpec(enabled=True, port=8443),
        },
    )

    with pytest.raises(RuntimeError, match="installation failed"):
        reconciler.apply(snapshot)

    assert [(user.email, user.uuid) for user in state.users] == [("old", "u1")]
    assert state.protocols == {}
    assert reconciler.current_generation() == 0
    app.protocols.disable.assert_called_once_with(state, "vless")
    app.protocols.uninstall.assert_called_once_with(state, "vless")


def test_wrong_node_snapshot_is_rejected_before_user_mutation():
    state = AppState()
    reconciler, app = _reconciler(state)

    with pytest.raises(ValueError, match="node_id"):
        reconciler.apply(NodeDesiredSnapshot(node_id="nl-1", generation=1))

    app.users.reconcile.assert_not_called()


def test_upgrade_target_is_validated_before_scheduling():
    scheduled = []
    reconciler = NodeReconciler(
        "de-1",
        MagicMock(),
        state_reader=AppState,
        upgrade_scheduler=lambda branch, revision: (
            scheduled.append((branch, revision)) or {"status": "scheduled", "branch": branch, "revision": revision}
        ),
    )
    revision = "d" * 40

    result = reconciler.schedule_upgrade(branch="release/node", revision=revision)

    assert result == {
        "node_id": "de-1",
        "status": "scheduled",
        "branch": "release/node",
        "revision": revision,
    }
    with pytest.raises(ValueError):
        reconciler.schedule_upgrade(branch="main;bad", revision=revision)
    assert scheduled == [("release/node", revision)]
