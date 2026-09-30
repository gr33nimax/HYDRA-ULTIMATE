from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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
        ),
        # The default plugin contract: nothing command-owned to prepare.
        prepare_node_config=lambda state, config: True,
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


def test_node_preparation_is_delegated_to_the_plugin_owner():
    """The reconciler must not decide protocol material itself: it asks the owner."""
    state = AppState(protocols={"awg": PluginState(installed=True, config={"old": True})})
    plugin = _transport("awg")
    seen = []

    def prepare_node_config(current, config):
        seen.append((current is state, dict(config)))
        current.protocols["awg"].config["prepared"] = True
        return True

    plugin.prepare_node_config = prepare_node_config
    app = MagicMock()
    app.protocols.list.return_value = [plugin]
    app.protocols.enabled_subscription_names.return_value = set()
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)

    reconciler.apply(
        NodeDesiredSnapshot(
            node_id="de-1",
            generation=1,
            protocols={"awg": NodeProtocolSpec(enabled=True, config={"protocol_mode": "3.1"})},
        )
    )

    # The owner sees the desired public settings after the merge has written them.
    assert seen == [(True, {"protocol_mode": "3.1"})]
    assert state.protocols["awg"].config["prepared"] is True


def test_a_plugin_that_cannot_prepare_its_node_config_stops_the_apply_with_its_reason():
    state = AppState(protocols={"awg": PluginState(installed=True, config={})})
    plugin = _transport("awg")

    def prepare_node_config(current, config):
        raise ValueError("no material can be created")

    plugin.prepare_node_config = prepare_node_config
    app = MagicMock()
    app.protocols.list.return_value = [plugin]
    app.protocols.enabled_subscription_names.return_value = set()
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)

    with pytest.raises(RuntimeError, match="awg: no material can be created"):
        reconciler.apply(
            NodeDesiredSnapshot(
                node_id="de-1",
                generation=1,
                protocols={"awg": NodeProtocolSpec(enabled=True, config={"protocol_mode": "3.1"})},
            )
        )

    assert reconciler.current_generation() == 0


def test_damaged_awg_generation_is_repaired_on_a_node_that_already_claims_the_mode():
    """The live case: stored mode says 3.1, the paddings cannot carry 3.1."""
    from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin

    obfuscation = {
        "Jc": "5",
        "Jmin": "10",
        "Jmax": "50",
        "S1": "105",
        "S2": "96",
        "S3": "0",
        "S4": "12",
        "H1": "1",
        "H2": "2",
        "H3": "3",
        "H4": "4",
        "I1": "",
    }
    state = AppState(
        protocols={
            "amneziawg": PluginState(
                installed=True,
                config={
                    "protocol_mode": "3.1",
                    "profiles": {"desktop": {"obfuscation": dict(obfuscation), "server_private_key": "node-key"}},
                },
            ),
        }
    )
    app = MagicMock()
    app.protocols.list.return_value = [AmneziaWGPlugin()]
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
    profile = config["profiles"]["desktop"]
    assert profile["obfuscation"]["S3"] == "12"
    assert profile["obfuscation"]["S1"] == "105"
    assert profile["generation"]["RandomTrailers"] is True
    assert profile["generation"]["DisableCookies"] is True
    assert profile["server_private_key"] == "node-key"
    assert AmneziaWGPlugin().mode_readiness(state, "3.1") == (True, "")


def test_vless_reality_material_survives_the_node_merge_and_is_not_rotated():
    """A Reality switch is command-owned: the merge must not erase what it prepared."""
    from hydra.plugins.vless_xhttp.plugin import VlessXhttpPlugin

    plugin = VlessXhttpPlugin()
    state = AppState(
        protocols={"vless": PluginState(installed=True, config={"security": "tls", "domain": "old.example.com"})}
    )
    app = MagicMock()
    app.protocols.list.return_value = [plugin]
    app.protocols.enabled_subscription_names.return_value = set()
    app.protocols.enable.side_effect = lambda current, name: setattr(current.protocols[name], "enabled", True) or True
    keypairs = iter((("private-1", "public-1"), ("private-2", "public-2")))
    reconciler = NodeReconciler("uk-1", app, state_reader=lambda: state)

    def apply(gen, config):
        reconciler.apply(
            NodeDesiredSnapshot(
                node_id="uk-1",
                generation=gen,
                protocols={"vless": NodeProtocolSpec(enabled=True, config=config)},
            )
        )
        return state.protocols["vless"].config

    with patch("hydra.core.singbox_keys.generate_reality_keypair", side_effect=lambda: next(keypairs)):
        reality = apply(1, {"security": "reality", "domain": "hcp.modxair.com", "xhttp_path": "/xhttp"})
        assert reality["reality_handshake"] == "hcp.modxair.com"
        assert reality["reality_private_key"] == "private-1"
        assert reality["reality_public_key"] == "public-1"
        assert isinstance(reality["_tls_passthrough_route"], dict)
        assert "_tls_http_decoy_route" in reality
        # Reality owns no certificate: the borrowed handshake replaces the domain.
        assert "domain" not in reality

        # Repeating the same desired state must not rotate healthy material.
        again = apply(2, {"security": "reality", "domain": "hcp.modxair.com", "xhttp_path": "/xhttp"})
        assert again["reality_private_key"] == "private-1"
        assert again["reality_short_id"] == reality["reality_short_id"]

        certificate = apply(3, {"security": "tls", "domain": "uk-any.example.com"})
        assert certificate["security"] == "tls"
        assert certificate["domain"] == "uk-any.example.com"
        assert isinstance(certificate["_tls_http_decoy_route"], dict)
        assert "_tls_passthrough_route" not in certificate


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
