from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


@contextmanager
def _no_channel():
    yield None


from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.ui._menus import node_cookies, node_removal, nodes_setup


def test_detach_requires_exact_name_and_additional_confirmation():
    app = Mock()
    node = NodeConfig(id="de-1", name="Germany", address="node.example.com")
    with (
        patch.object(node_removal, "panel"),
        patch.object(node_removal, "error"),
        patch.object(node_removal, "ask", return_value="wrong"),
        patch.object(node_removal, "menu") as confirmation,
    ):
        assert node_removal.detach_node(node, app) is False
    confirmation.assert_not_called()
    with (
        patch.object(node_removal, "panel"),
        patch.object(node_removal, "ask", return_value="Germany"),
        patch.object(node_removal, "menu", return_value="0"),
    ):
        assert node_removal.detach_node(node, app) is False
    app.nodes.detach_node.assert_not_called()
    app.nodes.remove_node.assert_not_called()


def test_confirmed_detach_warns_that_remote_vps_is_not_stopped():
    app = Mock()
    app.nodes.detach_node.return_value = {"status": "detached", "remote_cleanup": False}
    node = NodeConfig(id="de-1", name="Germany", address="node.example.com")
    with (
        patch.object(node_removal, "panel") as panel,
        patch.object(node_removal, "success"),
        patch.object(node_removal, "ask", return_value="Germany"),
        patch.object(node_removal, "menu", return_value="1"),
    ):
        assert node_removal.detach_node(node, app) is True
    assert any("очистка НЕ выполняется" in line for line in panel.call_args.args[1])
    app.nodes.detach_node.assert_called_once_with("de-1", confirmed=True)
    app.nodes.remove_node.assert_not_called()


@pytest.mark.parametrize("confirmed", [False, True])
def test_cookie_menu_targets_only_selected_node_and_never_base_or_pool(confirmed):
    app = Mock()
    node = NodeConfig(id="de-1", address="node.example.com")
    with (
        patch.object(node_cookies, "panel"),
        patch.object(node_cookies, "success"),
        patch.object(node_cookies, "ask", return_value="/secure/separate-vk.json"),
        patch.object(node_cookies, "confirm", return_value=confirmed),
    ):
        node_cookies.import_vk_cookies(node, app)
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
    from hydra.ui._menus import node_protocol_fields

    with (
        patch.object(nodes_setup, "menu", return_value="1"),
        patch.object(node_protocol_fields, "prompt", return_value="56002"),
    ):
        spec = nodes_setup.read_protocol("calls", app, NodeProtocolSpec())
    assert spec is not None and spec.enabled and spec.config["listen_port"] == 56002


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
    with (
        patch.object(
            nodes_setup, "ask", side_effect=["node.example.com", "root", "de-1", "Germany", "-", "/secure/node-vk.json"]
        ),
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch.object(nodes_setup, "read_protocol", return_value=NodeProtocolSpec(enabled=True)),
        patch("builtins.input", side_effect=["1", "1", "2", "1"]),
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "ssh_password_auth", Mock(side_effect=lambda password: _no_channel())),
        patch.object(nodes_setup, "success"),
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.add_node.assert_called_once()
    assert app.nodes.add_node.call_args.kwargs["vk_cookie_source"] == "/secure/node-vk.json"
    assert app.nodes.add_node.call_args.args[0].protocols["calls"].enabled
