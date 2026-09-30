from datetime import datetime, timezone
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
    offline = NodeConfig(id="uk-1", name="UK", address="node.example.com")
    assert "не опубликованы" in nodes._publication_row(offline)

    published = NodeConfig(id="uk-1", address="node.example.com", generation=2, published_generation=2)
    published.published_digest = "a" * 64
    assert "поколение 2" in nodes._publication_row(published)
    assert "не опубликованы" not in nodes._publication_row(published)

    pending = NodeConfig(id="uk-1", address="node.example.com", generation=3, published_generation=2)
    pending.published_digest = "a" * 64
    assert "ждёт подтверждения 3" in nodes._publication_row(pending)


def test_connection_row_separates_reachability_from_a_failed_operation():
    """ "Нет связи" and "применение не выполнено" are different problems, and both differ
    from "не проверялась": the card must not blur them into one word."""
    stamp = datetime.now(timezone.utc).isoformat()
    assert nodes._connection_row(None) == "не проверялась"

    ok = SimpleNamespace(control="ok", checked_at=stamp, stage="", message="")
    assert nodes._connection_row(ok).startswith("доступна · ")

    offline = SimpleNamespace(control="error", checked_at=stamp, stage="connect", message="control failed")
    row = nodes._connection_row(offline)
    assert row.startswith("нет связи · ")
    assert "не выполнена" not in row

    apply_failed = SimpleNamespace(control="error", checked_at=stamp, stage="apply", message="S3=0")
    row = nodes._connection_row(apply_failed)
    assert row.startswith("есть связь, но применение настроек не выполнено")
    assert nodes._reason_row(apply_failed) == "применение настроек: S3=0"


def test_coverage_row_shows_which_transports_actually_produced_profiles():
    node = NodeConfig(id="uk-1", address="node.example.com", generation=4, published_generation=4)
    node.published_digest = "a" * 64
    observation = SimpleNamespace(coverage={"amneziawg": 2, "calls": 0})

    row = nodes._coverage_row(node, observation)

    assert "поколение 4" in row
    assert "amneziawg: 2" in row
    assert "calls: 0" in row


def test_node_list_summary_never_calls_an_unpublished_node_ready():
    node = NodeConfig(id="uk-1", address="node.example.com")
    assert nodes._node_summary(node, None) == "профили не опубликованы"
    assert nodes._node_summary(node, SimpleNamespace(control="error", stage="connect")) == (
        "нет связи · профили не опубликованы"
    )

    node.published_generation = 2
    node.published_digest = "a" * 64
    assert nodes._node_summary(node, None) == "готова · поколение 2"


def test_vk_cookies_are_offered_only_when_the_node_actually_uses_calls():
    from hydra.contracts.node_snapshot import NodeProtocolSpec

    app = _app()
    node = app.admin.load_state.return_value.nodes[0]
    seen = []

    def record(options, title):
        seen.append([key for key, _, _ in options])
        return "0"

    with patch.object(nodes, "menu", side_effect=record), patch.object(nodes, "clear"), patch.object(nodes, "panel"):
        nodes.node_card(node, app)
        assert "8" not in seen[-1]

    node.protocols["calls"] = NodeProtocolSpec(enabled=True)
    with patch.object(nodes, "menu", side_effect=record), patch.object(nodes, "clear"), patch.object(nodes, "panel"):
        nodes.node_card(node, app)
        assert "8" in seen[-1]
