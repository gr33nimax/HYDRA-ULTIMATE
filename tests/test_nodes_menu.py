from unittest.mock import Mock, patch

from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
import hydra.ui._menus.nodes as nodes


def _app():
    app = Mock()
    state = AppState(nodes=[NodeConfig(id="de-1", name="Germany", address="node.example.com")])
    app.admin.load_state.return_value = state
    app.nodes.list_nodes.return_value = state.nodes
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
        patch.object(nodes, "menu", side_effect=["a", "0"]),
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
