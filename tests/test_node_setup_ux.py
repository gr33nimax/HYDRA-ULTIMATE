from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.plugins.base import PluginCategory
from hydra.plugins.defaults import default_plugins
from hydra.ui import tui
from hydra.ui._menus import nodes, nodes_setup


SHA = "a" * 40


def _app():
    app = Mock()
    app.admin.subscription_certificate.return_value = ("cert", "key")
    app.admin.subscription_public_host.return_value = "base.example.com"
    app.nodes.list_nodes.return_value = []
    app.nodes.resolve_revision.return_value = SHA
    app.protocols.list.return_value = [
        SimpleNamespace(
            meta=SimpleNamespace(
                name="amneziawg",
                display_name="",
                capabilities=SimpleNamespace(subscription_enabled=True),
            )
        )
    ]
    return app


def test_empty_plugin_display_names_use_shared_product_labels():
    app = _app()
    assert nodes_setup.protocol_choices(app) == {"1": ("amneziawg", "AmneziaWG")}


def test_real_transport_catalogue_renders_nonempty_product_names(capsys):
    app = _app()
    app.protocols.list.return_value = [
        plugin for plugin in default_plugins() if plugin.meta.category == PluginCategory.TRANSPORT
    ]
    choices = nodes_setup.protocol_choices(app)
    assert len(choices) >= 12
    assert all(label.strip() for _, label in choices.values())
    with patch("builtins.input", return_value="0"):
        tui.menu([(key, label, "") for key, (_, label) in choices.items()] + [("0", "Отмена", "")], "ПРОТОКОЛЫ НОДЫ")
    rendered = capsys.readouterr().out
    for label in ("AmneziaWG", "AnyTLS", "Hysteria2", "VLESS", "Hydra VK Tunnel"):
        assert label in rendered


def test_real_wizard_input_flow_uses_auto_port_auto_sha_and_safe_final_cancel(capsys):
    app = _app()
    app.protocols.list.return_value = [
        plugin for plugin in default_plugins() if plugin.meta.category == PluginCategory.TRANSPORT
    ]
    choices = nodes_setup.protocol_choices(app)
    awg = next(key for key, (name, _) in choices.items() if name == "amneziawg")
    values = [
        "uk-1",
        "194.147.35.112",
        "22",
        "UK London",
        "UK",
        "dev",
        "9444",
        awg,
        "1",
        "1",
        "1",
        "-",
        str(len(choices) + 1),
        "n",
    ]
    with patch("builtins.input", side_effect=values):
        nodes_setup.install_node(AppState(), app)
    output = capsys.readouterr().out
    assert "AmneziaWG" in output and "выбран" in output and "не SSH-логин" in output
    assert "2.0" in output and "ПАРАМЕТРЫ" in output
    assert "root@194.147.35.112:22" in output and SHA in output
    assert "cancel" not in output
    app.nodes.resolve_revision.assert_called_once_with("dev")
    app.nodes.add_node.assert_not_called()


@pytest.mark.parametrize("choices", [["9"], ["1", "9"]])
def test_invalid_protocol_action_or_port_choice_cannot_enable_protocol(choices):
    app = _app()
    with patch.object(nodes_setup, "menu", side_effect=choices), patch.object(nodes_setup, "prompt") as prompt:
        assert nodes_setup.read_protocol("amneziawg", app, NodeProtocolSpec()) is None
    prompt.assert_not_called()


@pytest.mark.parametrize("step", range(7))
def test_zero_cancels_each_install_field_without_network_or_ssh(step):
    app = _app()
    values = ["uk-1", "node.example.com", "22", "UK London", "UK", "dev", "9444"]
    values[step] = "0"
    with patch.object(nodes_setup, "prompt", side_effect=values), patch.object(nodes_setup, "panel"):
        nodes_setup.install_node(AppState(), app)
    app.nodes.resolve_revision.assert_not_called()
    app.nodes.add_node.assert_not_called()


def test_install_fetches_sha_once_after_selection_and_shows_it_before_confirmation():
    app = _app()
    with (
        patch.object(
            nodes_setup, "prompt", side_effect=["uk-1", "node.example.com", "22", "UK London", "UK", "dev", "9444"]
        ) as prompt,
        patch.object(nodes_setup, "menu", return_value="2"),
        patch.object(nodes_setup, "confirm", return_value=True),
        patch.object(nodes_setup, "panel") as panel,
        patch.object(nodes_setup, "success"),
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.resolve_revision.assert_called_once_with("dev")
    app.nodes.add_node.assert_called_once()
    node = app.nodes.add_node.call_args.args[0]
    assert node.revision == SHA and node.branch == "dev" and node.name == "UK London"
    assert any(SHA in str(call) for call in panel.call_args_list)
    assert not any("SHA" in call.args[0] for call in prompt.call_args_list)
    hints = " ".join(str(part) for call in panel.call_args_list for part in call.args)
    assert "не SSH-логин" in hints


def test_revision_lookup_failure_stops_install_and_reports_safe_actionable_error():
    app = _app()
    app.nodes.resolve_revision.side_effect = RuntimeError("secret-token")
    with (
        patch.object(
            nodes_setup, "prompt", side_effect=["uk-1", "node.example.com", "22", "UK London", "UK", "dev", "9444"]
        ),
        patch.object(nodes_setup, "menu", return_value="2"),
        patch.object(nodes_setup, "confirm") as confirm,
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "error") as error,
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.add_node.assert_not_called()
    confirm.assert_not_called()
    assert error.called
    assert "secret-token" not in str(error.call_args)
    assert "GitHub" in str(error.call_args)


def test_cancel_protocol_selection_does_not_fetch_sha():
    app = _app()
    with (
        patch.object(
            nodes_setup, "prompt", side_effect=["uk-1", "node.example.com", "22", "UK London", "UK", "dev", "9444"]
        ),
        patch.object(nodes_setup, "menu", return_value="0"),
        patch.object(nodes_setup, "panel"),
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.resolve_revision.assert_not_called()
    app.nodes.add_node.assert_not_called()


def test_upgrade_resolves_branch_without_manual_sha_and_confirms_before_mutation():
    app = _app()
    node = NodeConfig(id="uk-1", branch="dev", revision="b" * 40)
    with (
        patch.object(nodes, "prompt", return_value="dev") as prompt,
        patch.object(nodes, "confirm", return_value=False),
        patch.object(nodes, "panel"),
    ):
        nodes._upgrade(node, app)
    assert prompt.call_count == 1
    app.nodes.resolve_revision.assert_called_once_with("dev")
    app.nodes.change_update_target.assert_not_called()
    app.nodes.update.assert_not_called()


def test_automatic_protocol_port_does_not_require_typing_zero_into_data_field():
    app = _app()
    with (
        patch.object(nodes_setup, "menu", side_effect=["1", "1"]),
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "prompt") as prompt,
        patch.object(nodes_setup, "collect_protocol_config", return_value={"protocol_mode": "2.0"}),
    ):
        spec = nodes_setup.read_protocol("amneziawg", app, NodeProtocolSpec())
    assert spec is not None and spec.port == 0 and spec.enabled
    assert spec.config["protocol_mode"] == "2.0"
    prompt.assert_not_called()
