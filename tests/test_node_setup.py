from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.contracts.node_validation import NodeContractError
from hydra.core.state_models import AppState
from hydra.ui._menus import nodes_setup


def _app():
    app = Mock()
    app.admin.subscription_certificate.return_value = ("base.crt", "base.key")
    app.admin.subscription_public_host.return_value = "base.example.com"
    app.nodes.list_nodes.return_value = []
    app.nodes.resolve_revision.return_value = "a" * 40
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


@pytest.mark.parametrize("step", range(7))
def test_cancel_at_each_install_input_never_reaches_ssh(step):
    app = _app()
    values = ["de-1", "node.example.com", "22", "Germany", "DE", "main", "9444"]
    values[step] = "cancel"
    with patch.object(nodes_setup, "prompt", side_effect=values):
        nodes_setup.install_node(AppState(), app)
    app.nodes.add_node.assert_not_called()


def test_cancel_protocol_selection_never_reaches_ssh():
    app = _app()
    with (
        patch.object(
            nodes_setup,
            "prompt",
            side_effect=["de-1", "node.example.com", "22", "Germany", "DE", "main", "9444"],
        ),
        patch.object(nodes_setup, "menu", return_value="0"),
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.add_node.assert_not_called()


def test_final_install_confirmation_is_required():
    app = _app()
    with (
        patch.object(
            nodes_setup,
            "prompt",
            side_effect=["de-1", "node.example.com", "22", "Germany", "DE", "main", "9444"],
        ),
        patch.object(nodes_setup, "menu", return_value="2"),
        patch.object(nodes_setup, "confirm", return_value=False),
        patch.object(nodes_setup, "panel"),
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.add_node.assert_not_called()


def test_protocol_json_cannot_smuggle_private_node_credentials():
    app = _app()
    with (
        patch.object(nodes_setup, "menu", side_effect=["1", "2"]),
        patch.object(nodes_setup, "prompt", side_effect=["443", '{"private_key":"do-not-copy"}']),
    ):
        with pytest.raises(NodeContractError, match="node-local secret"):
            nodes_setup.read_protocol("vless", app, NodeProtocolSpec())
    app.nodes.change_protocol.assert_not_called()


def test_install_rejects_inactive_base_subscription_service_before_prompts():
    app = _app()
    app.admin.unit_active.return_value = False
    with patch.object(nodes_setup, "prompt") as prompt:
        with pytest.raises(ValueError, match="must be active"):
            nodes_setup.install_node(AppState(), app)
    prompt.assert_not_called()
    app.nodes.add_node.assert_not_called()


def test_real_install_menu_accepts_numeric_protocol_and_continue():
    app = _app()
    values = ["de-1", "node.example.com", "22", "Germany", "DE", "main", "9444", "-"]
    with (
        patch.object(nodes_setup, "_input", side_effect=values),
        patch("builtins.input", side_effect=["1", "2"]),
        patch.object(nodes_setup, "read_protocol", return_value=NodeProtocolSpec(enabled=True)) as read,
        patch.object(nodes_setup, "confirm", return_value=True),
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "success"),
    ):
        nodes_setup.install_node(AppState(), app)
    read.assert_called_once_with("vless", app, NodeProtocolSpec())
    app.nodes.add_node.assert_called_once()
    assert app.nodes.add_node.call_args.args[0].protocols["vless"].enabled
