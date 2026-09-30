from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
import hydra.ui._menus.nodes as nodes


def _app():
    app = Mock()
    state = AppState(nodes=[NodeConfig(id="de-1", name="Germany", address="node.example.com")])
    app.admin.load_state.return_value = state
    app.nodes.list_nodes.return_value = state.nodes
    app.protocols.list.return_value = [
        SimpleNamespace(
            meta=SimpleNamespace(
                name="vless",
                display_name="VLESS",
                capabilities=SimpleNamespace(subscription_enabled=True),
            )
        )
    ]
    return app


def test_back_from_nodes_does_not_contact_or_mutate_nodes():
    app = _app()
    with patch.object(nodes, "menu", return_value="0"), patch.object(nodes, "clear"):
        nodes.menu_nodes(AppState(), app)
    app.nodes.check.assert_not_called()
    app.nodes.remove_node.assert_not_called()
    app.nodes.add_node.assert_not_called()


def test_cancel_install_before_ssh_does_not_mutate():
    app = _app()
    with (
        patch.object(nodes, "menu", side_effect=["1", "0"]),
        patch.object(nodes, "clear"),
        patch.object(nodes, "install_node", return_value=None),
    ):
        nodes.menu_nodes(AppState(), app)
    app.nodes.add_node.assert_not_called()


def test_card_can_rename_offline_without_network_check():
    app = _app()
    with (
        patch.object(nodes, "menu", side_effect=["1", "0"]),
        patch.object(nodes, "prompt", side_effect=["Berlin", "DE"]),
        patch.object(nodes, "clear"),
        patch.object(nodes, "panel"),
        patch.object(nodes, "success"),
    ):
        nodes.node_card(app.admin.load_state.return_value.nodes[0], app)
    app.nodes.change_name.assert_called_once_with("de-1", "Berlin", region="DE")
    app.nodes.check.assert_not_called()


def test_delete_requires_exact_name_and_explicit_confirmation():
    app = _app()
    node = app.admin.load_state.return_value.nodes[0]
    with (
        patch.object(nodes, "prompt", return_value="wrong"),
        patch.object(nodes, "confirm", return_value=True),
        patch.object(nodes, "panel"),
        patch.object(nodes, "error"),
    ):
        assert nodes.remove_node(node, app) is False
    app.nodes.remove_node.assert_not_called()
    with (
        patch.object(nodes, "prompt", return_value=node.name),
        patch.object(nodes, "confirm", return_value=True),
        patch.object(nodes, "panel"),
        patch.object(nodes, "success"),
    ):
        assert nodes.remove_node(node, app) is True
    app.nodes.remove_node.assert_called_once_with(node.id, confirmed=True)


def test_offline_protocol_editor_does_not_change_desired_settings():
    app = _app()
    app.nodes.check.side_effect = RuntimeError("offline")
    with (
        patch.object(nodes, "menu", side_effect=["2", "0"]),
        patch.object(nodes, "clear"),
        patch.object(nodes, "panel"),
        patch.object(nodes, "error"),
        patch.object(nodes, "prompt"),
    ):
        nodes.node_card(app.admin.load_state.return_value.nodes[0], app)
    app.nodes.change_protocol.assert_not_called()


@pytest.mark.parametrize("key", ["1", " 1 "])
def test_real_menu_install_key_reaches_wizard(key):
    app = _app()
    with (
        patch("builtins.input", side_effect=[key, "0"]),
        patch.object(nodes, "clear"),
        patch.object(nodes, "install_node") as install,
    ):
        nodes.menu_nodes(AppState(), app)
    install.assert_called_once_with(app.admin.load_state.return_value, app)


@pytest.mark.parametrize("key", ["2", "1"])
def test_real_protocol_menu_accepts_numeric_action_and_protocol_keys(key):
    app = _app()
    node = app.admin.load_state.return_value.nodes[0]
    from hydra.contracts.node_snapshot import NodeProtocolSpec

    node.protocols["vless"] = NodeProtocolSpec()
    with (
        patch("builtins.input", side_effect=[key, "1", "0"] if key == "2" else [key, "0"]),
        patch.object(nodes, "prompt") as prompt,
        patch.object(nodes, "read_protocol", return_value=None) as read,
    ):
        nodes._protocols(node, app)
    read.assert_called_once_with("vless", app, node.protocols["vless"])
    prompt.assert_not_called()


def test_card_publication_row_says_whether_subscriptions_can_include_the_node():
    from hydra.services.nodes import reconcile as _reconcile  # noqa: F401  (import keeps path honest)

    offline = NodeConfig(id="uk-1", name="UK", address="node.example.com")
    assert "не опубликован" in nodes._publication_row(offline)

    published = NodeConfig(id="uk-1", address="node.example.com", generation=2, published_generation=2)
    published.published_digest = "a" * 64
    assert "поколение 2" in nodes._publication_row(published)
    assert "не опубликован" not in nodes._publication_row(published)

    pending = NodeConfig(id="uk-1", address="node.example.com", generation=3, published_generation=2)
    pending.published_digest = "a" * 64
    assert "ждёт подтверждения 3" in nodes._publication_row(pending)
