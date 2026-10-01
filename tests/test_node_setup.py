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


def test_wizard_offers_no_way_to_smuggle_private_node_credentials():
    """The base must not be able to send node-local keys, not even by hand."""
    from hydra.plugins.base import PluginCategory
    from hydra.plugins.defaults import default_plugins
    from hydra.ui._menus import node_protocol_fields
    from hydra.contracts.node_snapshot import is_node_local_secret_key

    app = _app()
    app.protocols.list.return_value = [
        plugin for plugin in default_plugins() if plugin.meta.category == PluginCategory.TRANSPORT
    ]
    assert all(
        not is_node_local_secret_key(item.key)
        for items in node_protocol_fields.PROTOCOL_FIELDS.values()
        for item in items
    )
    with pytest.raises(NodeContractError, match="node-local secret"):
        NodeProtocolSpec(enabled=True, config={"private_key": "do-not-copy"}).validate()


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
    with (
        patch.object(nodes_setup, "ask", side_effect=["node.example.com", "root", "de-1", "Germany", "-"]),
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch.object(nodes_setup, "menu", side_effect=["1", "2", "1"]),
        patch.object(nodes_setup, "read_protocol", return_value=NodeProtocolSpec(enabled=True)) as read,
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "success"),
    ):
        nodes_setup.install_node(AppState(), app)
    read.assert_called_once_with("vless", app, NodeProtocolSpec())
    app.nodes.add_node.assert_called_once()
    assert app.nodes.add_node.call_args.args[0].protocols["vless"].enabled


def test_a_failed_install_offers_to_continue_the_same_node_without_reinstalling():
    """The recovery is offered where the failure happens, with the data already collected."""
    app = _app()
    app.nodes.add_node.side_effect = RuntimeError("node was installed but control identity provisioning failed")
    with (
        patch.object(nodes_setup, "ask", side_effect=["node.example.com", "root", "de-1", "Germany", "-"]),
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch.object(nodes_setup, "menu", side_effect=["1", "2", "1"]),
        patch.object(nodes_setup, "read_protocol", return_value=NodeProtocolSpec(enabled=True)),
        patch.object(nodes_setup, "confirm", return_value=True) as confirm,
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "error"),
        patch.object(nodes_setup, "success"),
    ):
        nodes_setup.install_node(AppState(), app)

    app.nodes.resume_node.assert_called_once()
    # The installer is not run a second time; the same node record is resumed.
    assert app.nodes.resume_node.call_args.args[0].id == "de-1"
    assert any("Продолжить подключение этой ноды?" in str(call) for call in confirm.call_args_list)


def test_declining_the_continuation_offer_leaves_the_node_unmanaged():
    app = _app()
    app.nodes.add_node.side_effect = RuntimeError("node was installed but control identity provisioning failed")
    with (
        patch.object(nodes_setup, "ask", side_effect=["node.example.com", "root", "de-1", "Germany", "-"]),
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch.object(nodes_setup, "menu", side_effect=["1", "2", "1"]),
        patch.object(nodes_setup, "read_protocol", return_value=NodeProtocolSpec(enabled=True)),
        patch.object(nodes_setup, "confirm", return_value=False),
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "error"),
    ):
        nodes_setup.install_node(AppState(), app)

    app.nodes.resume_node.assert_not_called()
