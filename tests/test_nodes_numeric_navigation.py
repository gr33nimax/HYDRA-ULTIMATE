from types import SimpleNamespace
from unittest.mock import Mock, patch

from hydra.contracts.node_export import NodeClientExport, NodeClientExportUser, NodeClientProfile
from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.ui import tui
from hydra.ui._menus import nodes, nodes_setup


def _app():
    app = Mock()
    node = NodeConfig(id="de-1", name="Germany", address="node.example.com", protocols={"vless": NodeProtocolSpec()})
    state = AppState(nodes=[node])
    app.admin.load_state.return_value = state
    app.admin.subscription_certificate.return_value = ("cert", "key")
    app.admin.subscription_public_host.return_value = "base.example.com"
    app.nodes.list_nodes.return_value = state.nodes
    app.nodes.published_export.return_value = None
    app.nodes.resolve_revision.return_value = "a" * 40
    app.protocols.list.return_value = [
        SimpleNamespace(
            meta=SimpleNamespace(
                name="vless",
                display_name="VLESS",
                capabilities=SimpleNamespace(subscription_enabled=True, hydra_v2_subscription_enabled=False),
            )
        )
    ]
    return app, state, node


def _numeric_menu(options, header=""):
    assert all(key.isdecimal() for key, _, _ in options)
    return tui.menu(options, header)


def test_empty_list_install_is_numeric_one():
    app, state, _ = _app()
    state.nodes.clear()
    with (
        patch.object(nodes, "menu", side_effect=_numeric_menu),
        patch("builtins.input", side_effect=["1", "", "0"]),
        patch.object(nodes, "clear"),
        patch.object(nodes, "install_node") as install,
    ):
        nodes.menu_nodes(state, app)
    install.assert_called_once_with(state, app)


def test_existing_node_is_numeric_two_after_install_action():
    app, state, node = _app()
    with (
        patch.object(nodes, "menu", side_effect=_numeric_menu),
        patch("builtins.input", side_effect=["2", "0"]),
        patch.object(nodes, "clear"),
        patch.object(nodes, "node_card") as card,
    ):
        nodes.menu_nodes(state, app)
    card.assert_called_once_with(node, app)


def test_add_protocol_uses_numeric_picker_without_typing_internal_name():
    app, _, node = _app()
    with (
        patch.object(nodes, "menu", side_effect=_numeric_menu),
        patch("builtins.input", side_effect=["2", "1", "1", "0"]),
        patch.object(nodes, "ask") as ask,
        patch.object(nodes, "read_protocol", return_value=None) as read,
    ):
        nodes._protocols(node, app)
    read.assert_called_once_with("vless", app, node.protocols["vless"])
    ask.assert_not_called()


def test_install_collects_identity_in_order_and_continues_with_a_numeric_key():
    app, _, _ = _app()
    app.nodes.list_nodes.return_value = []
    with (
        patch.object(nodes_setup, "ask", side_effect=["node.example.com", "root", "new-node", "Germany", "-"]) as ask,
        patch.object(nodes_setup, "ask_secret", return_value="pw") as secret,
        patch.object(nodes_setup, "menu", side_effect=_numeric_menu),
        patch("builtins.input", side_effect=["1", "1", "2", "1"]),
        patch.object(nodes_setup, "read_protocol", return_value=NodeProtocolSpec(enabled=True)),
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "success"),
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.add_node.assert_called_once()
    node = app.nodes.add_node.call_args.args[0]
    assert node.protocols["vless"].enabled
    assert node.ssh_user == "root"
    assert [call.args[0].split(" (")[0] for call in ask.call_args_list] == [
        "Адрес VPS",
        "Имя пользователя SSH",
        "ID ноды",
        "Имя ноды",
        "Название профиля в подписке",
    ]
    assert secret.call_args.args[0].startswith("Пароль SSH")


def test_profile_name_selects_published_profile_numerically_and_stays_offline():
    app, _, node = _app()
    app.nodes.published_export.return_value = NodeClientExport(
        node_id=node.id,
        generation=1,
        users={
            "u1": NodeClientExportUser(uuid="u1", profiles=(NodeClientProfile(protocol="vless", profile="mobile"),)),
        },
    )
    with (
        patch.object(nodes, "menu", side_effect=_numeric_menu),
        patch("builtins.input", return_value="2"),
        patch.object(nodes, "ask", return_value="My mobile") as ask,
        patch.object(nodes, "success"),
    ):
        nodes._profile_name(node, app, "vless")
    app.nodes.change_profile_name.assert_called_once_with(node.id, "vless:mobile", "My mobile")
    assert ask.call_count == 1
    app.nodes.check.assert_not_called()
