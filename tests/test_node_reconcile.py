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
        users=(
            NodeUserProjection(
                email=user.email,
                uuid=user.uuid,
                traffic_reset_epoch=2,
            ),
        ),
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
        users=(
            NodeUserProjection(
                email=user.email,
                uuid=user.uuid,
                traffic_reset_epoch=2,
            ),
        ),
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


def test_reconcile_keeps_node_local_material_the_base_never_sent():
    """A node's own profiles and keys must survive a desired-state refresh."""
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                installed=True,
                config={
                    "profiles": {"desktop": {"obfuscation": {"S3": "20"}}},
                    "server_private_key": "node-key",
                },
            ),
        }
    )
    app = MagicMock()
    app.protocols.list.return_value = [_transport("amneziawg")]
    app.protocols.enabled_subscription_names.return_value = set()
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)

    reconciler.apply(
        NodeDesiredSnapshot(
            node_id="de-1",
            generation=1,
            protocols={"amneziawg": NodeProtocolSpec(enabled=False, config={})},
        )
    )

    config = state.protocols["amneziawg"].config
    assert config["profiles"] == {"desktop": {"obfuscation": {"S3": "20"}}}
    assert config["server_private_key"] == "node-key"


def test_generation_switch_runs_through_the_plugin_owner_before_the_merge():
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                installed=True,
                config={"protocol_mode": "2.0", "profiles": {"desktop": {"obfuscation": {"S3": "0"}}}},
            ),
        }
    )
    plugin = _transport("amneziawg")
    calls = []

    def set_protocol_mode(current, mode):
        # The owner is what lifts the paddings and creates the generation material.
        current.protocols["amneziawg"].config["protocol_mode"] = mode
        current.protocols["amneziawg"].config["profiles"]["desktop"]["obfuscation"]["S3"] = "20"
        calls.append(mode)
        return True

    plugin.set_protocol_mode = set_protocol_mode
    app = MagicMock()
    app.protocols.list.return_value = [plugin]
    app.protocols.enabled_subscription_names.return_value = set()
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)

    reconciler.apply(
        NodeDesiredSnapshot(
            node_id="de-1",
            generation=1,
            protocols={"amneziawg": NodeProtocolSpec(enabled=True, config={"protocol_mode": "3.1"})},
        )
    )

    assert calls == ["3.1"]
    config = state.protocols["amneziawg"].config
    assert config["protocol_mode"] == "3.1"
    assert config["profiles"]["desktop"]["obfuscation"]["S3"] == "20"


def test_vless_reality_switch_uses_the_plugin_owner_and_keeps_generated_keys():
    state = AppState(protocols={"vless": PluginState(installed=True, config={"security": "tls"})})
    plugin = _transport("vless")
    calls = []

    def set_security(current, mode, handshake="", domain="", short_id=""):
        config = current.protocols["vless"].config
        config["security"] = mode
        config["reality_private_key"] = "generated-private"
        config["reality_public_key"] = "generated-public"
        config["reality_short_id"] = "abcd"
        calls.append({"mode": mode, "handshake": handshake, "domain": domain})
        return True

    plugin.set_security = set_security
    app = MagicMock()
    app.protocols.list.return_value = [plugin]
    app.protocols.enabled_subscription_names.return_value = set()
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)

    reconciler.apply(
        NodeDesiredSnapshot(
            node_id="de-1",
            generation=1,
            protocols={
                "vless": NodeProtocolSpec(
                    enabled=True,
                    config={"security": "reality", "domain": "cover.example.com", "xhttp_path": "/xhttp"},
                )
            },
        )
    )

    assert calls == [{"mode": "reality", "handshake": "cover.example.com", "domain": "cover.example.com"}]
    config = state.protocols["vless"].config
    assert config["security"] == "reality"
    assert config["reality_private_key"] == "generated-private"
    assert config["reality_public_key"] == "generated-public"
    assert config["xhttp_path"] == "/xhttp"


def test_generation_switch_on_a_profile_less_node_materializes_through_the_owner():
    """A node has no console: the plugin's rotation command creates the first profile."""
    state = AppState(protocols={"amneziawg": PluginState(installed=True, config={"protocol_mode": "2.0"})})
    plugin = _transport("amneziawg")
    calls = []

    def rotate_obfuscation(current, profile=None, preset=None):
        current.protocols["amneziawg"].config["profiles"] = {
            "desktop": {"obfuscation": {"S3": "0"}, "server_private_key": "key"},
        }
        calls.append(("rotate_obfuscation", profile))
        return True

    def set_protocol_mode(current, mode):
        profiles = current.protocols["amneziawg"].config["profiles"]
        profiles["desktop"]["obfuscation"]["S3"] = "20"
        current.protocols["amneziawg"].config["protocol_mode"] = mode
        calls.append(("set_protocol_mode", mode))
        return True

    plugin.rotate_obfuscation = rotate_obfuscation
    plugin.set_protocol_mode = set_protocol_mode
    app = MagicMock()
    app.protocols.list.return_value = [plugin]
    app.protocols.enabled_subscription_names.return_value = set()
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)

    reconciler.apply(
        NodeDesiredSnapshot(
            node_id="de-1",
            generation=1,
            protocols={"amneziawg": NodeProtocolSpec(enabled=True, config={"protocol_mode": "3.1"})},
        )
    )

    assert calls == [("rotate_obfuscation", "desktop"), ("set_protocol_mode", "3.1")]
    config = state.protocols["amneziawg"].config
    assert config["protocol_mode"] == "3.1"
    assert config["profiles"]["desktop"]["obfuscation"]["S3"] == "20"
    assert config["profiles"]["desktop"]["server_private_key"] == "key"


def test_real_awg_plugin_serves_31_on_a_node_that_had_no_profiles():
    """End-to-end with the real plugin: no profile, mode 3.1, and the floor is respected."""
    from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin

    plugin = AmneziaWGPlugin()
    state = AppState(protocols={"amneziawg": PluginState(installed=True, config={})})
    app = MagicMock()
    app.protocols.list.return_value = [plugin]
    app.protocols.enabled_subscription_names.return_value = set()
    app.protocols.enable.side_effect = lambda current, name: setattr(current.protocols[name], "enabled", True) or True
    reconciler = NodeReconciler("uk-1", app, state_reader=lambda: state)

    reconciler.apply(
        NodeDesiredSnapshot(
            node_id="uk-1",
            generation=1,
            protocols={"amneziawg": NodeProtocolSpec(enabled=True, config={"protocol_mode": "3.1"})},
        )
    )

    config = state.protocols["amneziawg"].config
    desktop = config["profiles"]["desktop"]
    paddings = desktop["obfuscation"]
    assert config["protocol_mode"] == "3.1"
    # The whole point: header protection reads every padding as its nonce.
    assert all(int(paddings[field]) >= 12 for field in ("S1", "S2", "S3", "S4"))
    assert desktop["generation"]["RandomTrailers"] is True
    assert desktop["generation"]["DisableCookies"] is True
    assert desktop["generation"]["HeaderProtectionKey"]
