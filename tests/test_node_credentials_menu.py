from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.ui._menus import nodes, nodes_setup


def test_detach_requires_exact_name_and_additional_confirmation():
    app = Mock()
    node = NodeConfig(id="de-1", name="Germany", address="node.example.com")
    with (
        patch.object(nodes, "panel"),
        patch.object(nodes, "error"),
        patch.object(nodes, "prompt", return_value="wrong"),
        patch.object(nodes, "confirm") as confirmation,
    ):
        assert nodes.detach_node(node, app) is False
    confirmation.assert_not_called()
    with (
        patch.object(nodes, "panel"),
        patch.object(nodes, "prompt", return_value="Germany"),
        patch.object(nodes, "confirm", return_value=False),
    ):
        assert nodes.detach_node(node, app) is False
    app.nodes.detach_node.assert_not_called()
    app.nodes.remove_node.assert_not_called()


def test_confirmed_detach_warns_that_remote_vps_is_not_stopped():
    app = Mock()
    app.nodes.detach_node.return_value = {"status": "detached", "remote_cleanup": False}
    node = NodeConfig(id="de-1", name="Germany", address="node.example.com")
    with (
        patch.object(nodes, "panel") as panel,
        patch.object(nodes, "success"),
        patch.object(nodes, "prompt", return_value="Germany"),
        patch.object(nodes, "confirm", return_value=True),
    ):
        assert nodes.detach_node(node, app) is True
    assert any("НЕ остановлена" in line for line in panel.call_args.args[1])
    app.nodes.detach_node.assert_called_once_with("de-1", confirmed=True)
    app.nodes.remove_node.assert_not_called()


@pytest.mark.parametrize("confirmed", [False, True])
def test_cookie_menu_targets_only_selected_node_and_never_base_or_pool(confirmed):
    app = Mock()
    node = NodeConfig(id="de-1", address="node.example.com")
    with (
        patch.object(nodes, "panel"),
        patch.object(nodes, "success"),
        patch.object(nodes, "prompt", return_value="/secure/separate-vk.json"),
        patch.object(nodes, "confirm", return_value=confirmed),
    ):
        nodes._import_vk_cookies(node, app)
    if confirmed:
        app.nodes.import_vk_cookies.assert_called_once_with("de-1", "/secure/separate-vk.json")
    else:
        app.nodes.import_vk_cookies.assert_not_called()
    app.calls.import_vk_cookies.assert_not_called()
    app.calls.rotate_native_vk.assert_not_called()


def test_v2_only_calls_is_available_in_node_protocol_editor():
    app = Mock()
    app.protocols.list.return_value = [
        SimpleNamespace(
            meta=SimpleNamespace(
                name="calls",
                capabilities=SimpleNamespace(subscription_enabled=False, hydra_v2_subscription_enabled=True),
            )
        )
    ]
    with (
        patch.object(nodes_setup, "menu", side_effect=["1", "2"]),
        patch.object(nodes_setup, "prompt", side_effect=["56002", "{}"]),
    ):
        spec = nodes_setup.read_protocol("calls", app, NodeProtocolSpec())
    assert spec is not None and spec.enabled and spec.port == 56002


def test_calls_install_wizard_passes_separate_cookie_file_before_initial_activation():
    app = Mock()
    app.admin.subscription_certificate.return_value = ("cert", "key")
    app.admin.subscription_public_host.return_value = "base.example.com"
    app.nodes.list_nodes.return_value = []
    app.nodes.resolve_revision.return_value = "a" * 40
    app.protocols.list.return_value = [
        SimpleNamespace(
            meta=SimpleNamespace(
                name="calls",
                display_name="Hydra VK Tunnel",
                capabilities=SimpleNamespace(subscription_enabled=False, hydra_v2_subscription_enabled=True),
            )
        )
    ]
    values = ["de-1", "node.example.com", "22", "Germany", "DE", "main", "9444", "-", "/secure/node-vk.json"]
    with (
        patch.object(nodes_setup, "prompt", side_effect=values),
        patch.object(nodes_setup, "menu", side_effect=["1", "2"]),
        patch.object(nodes_setup, "read_protocol", return_value=NodeProtocolSpec(enabled=True)),
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "confirm", return_value=True),
        patch.object(nodes_setup, "success"),
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.add_node.assert_called_once()
    assert app.nodes.add_node.call_args.kwargs["vk_cookie_source"] == "/secure/node-vk.json"
    assert app.nodes.add_node.call_args.args[0].protocols["calls"].enabled
