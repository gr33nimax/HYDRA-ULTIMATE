import json
from unittest.mock import MagicMock

from hydra.core.state_models import AppState, User
from hydra.services.nodes.reconcile import NodeReconciler


def test_export_is_scoped_to_active_user_and_enabled_protocols():
    active = User(email="alice", uuid="u1")
    blocked = User(email="bob", uuid="u2", blocked=True)
    disabled = User(email="carol", uuid="u3", disabled_protocols=["vless"])
    state = AppState(
        users=[active, blocked, disabled],
        protocols={"vless": MagicMock(enabled=True)},
        feature_extensions={"hydra_node_control": {"generation": 9}},
    )
    app = MagicMock()
    app.protocols.enabled_subscription_names.return_value = {"vless"}
    app.protocols.client_profiles.return_value = []
    app.protocols.client_links.return_value = ["vless://alice@node.example"]
    app.protocols.client_config.return_value = json.dumps(
        {
            "outbounds": [{"type": "vless", "tag": "vless-u1"}],
        }
    )
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)

    exported = reconciler.export()

    assert exported.node_id == "de-1"
    assert exported.generation == 9
    assert set(exported.users) == {"u1", "u3"}
    assert exported.users["u1"].profiles[0].links == ("vless://alice@node.example",)
    assert exported.users["u1"].profiles[0].singbox == (
        {
            "outbounds": [{"type": "vless", "tag": "vless-u1"}],
        },
    )
    assert exported.users["u3"].profiles == ()
    assert app.protocols.client_links.call_count == 1


def test_export_reports_last_apply_error_only_through_diagnostics():
    app = MagicMock()
    app.apply_error.return_value = "last apply failed"
    state = AppState(feature_extensions={"hydra_node_control": {"generation": 2}})
    reconciler = NodeReconciler("de-1", app, state_reader=lambda: state)

    assert reconciler.diagnostics() == {"last_error": "last apply failed"}
