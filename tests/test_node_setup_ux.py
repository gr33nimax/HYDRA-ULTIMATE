from contextlib import contextmanager
from typing import cast
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.plugins.base import PluginCategory
from hydra.plugins.defaults import default_plugins
from hydra.ui import tui
from hydra.ui._menus import nodes, nodes_setup


SHA = "a" * 40


@contextmanager
def _no_password_channel(password):
    """Stand in for the askpass channel: tests never open a real socket."""
    assert password is None or isinstance(password, str)
    yield None


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


def test_real_wizard_asks_address_account_password_id_and_name_in_that_order(capsys):
    app = _app()
    app.protocols.list.return_value = [
        plugin for plugin in default_plugins() if plugin.meta.category == PluginCategory.TRANSPORT
    ]
    choices = nodes_setup.protocol_choices(app)
    awg = next(key for key, (name, _) in choices.items() if name == "amneziawg")
    with (
        patch.object(nodes_setup, "ask", side_effect=["194.147.35.112", "root", "uk-1", "UK London", "-"]) as ask,
        patch.object(nodes_setup, "ask_secret", return_value="hunter2") as secret,
        patch.object(nodes_setup, "read_protocol", return_value=NodeProtocolSpec(enabled=True, port=0)),
        patch("builtins.input", side_effect=[awg, str(len(choices) + 1), "0"]),
    ):
        nodes_setup.install_node(AppState(), app)
    output = capsys.readouterr().out
    assert "AmneziaWG" in output and "выбран" in output
    assert "root@194.147.35.112:22" in output and SHA in output
    assert [call.args[0].split(" (")[0] for call in ask.call_args_list] == [
        "Адрес VPS",
        "Имя пользователя SSH",
        "ID ноды",
        "Имя ноды",
        "Название профиля в подписке",
    ]
    assert secret.call_args.args[0].startswith("Пароль SSH")
    app.nodes.resolve_revision.assert_called_once_with("main")
    app.nodes.add_node.assert_not_called()


def test_install_plan_never_prints_the_ssh_password(capsys):
    app = _app()
    with (
        patch.object(nodes_setup, "ask", side_effect=["node.example.com", "root", "uk-1", "UK"]),
        patch.object(nodes_setup, "ask_secret", return_value="top-secret-pw"),
        patch("builtins.input", side_effect=["2", "0"]),
    ):
        nodes_setup.install_node(AppState(), app)
    output = capsys.readouterr().out
    assert "top-secret-pw" not in output
    assert "не сохраняется" in output


@pytest.mark.parametrize("choices", [["9"]])
def test_invalid_protocol_action_cannot_enable_protocol(choices):
    app = _app()
    with patch.object(nodes_setup, "menu", side_effect=choices), patch.object(nodes_setup, "prompt") as prompt:
        assert nodes_setup.read_protocol("amneziawg", app, NodeProtocolSpec()) is None
    prompt.assert_not_called()


@pytest.mark.parametrize("step", range(5))
def test_cancel_at_each_install_question_stops_before_network_or_ssh(step):
    app = _app()
    values = ["194.147.35.112", "root", "uk-1", "UK London"]
    secrets = [None] if step == 2 else ["pw"]
    if step != 2:
        values[step if step < 2 else step - 1] = "0"
    with (
        patch.object(nodes_setup, "ask", side_effect=values),
        patch.object(nodes_setup, "ask_secret", side_effect=secrets),
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "menu") as menu,
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.resolve_revision.assert_not_called()
    app.nodes.add_node.assert_not_called()
    menu.assert_not_called()


def test_install_fetches_sha_once_and_passes_a_password_channel_not_a_password():
    app = _app()
    with (
        patch.object(nodes_setup, "ask", side_effect=["node.example.com", "deploy", "uk-1", "UK London", "-"]) as ask,
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch.object(nodes_setup, "read_protocol", return_value=NodeProtocolSpec(enabled=True)),
        patch("builtins.input", side_effect=["1", "2", "1"]),
        patch.object(nodes_setup, "panel") as panel,
        patch.object(nodes_setup, "ssh_password_auth", Mock(side_effect=_no_password_channel)) as channel,
        patch.object(nodes_setup, "success"),
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.resolve_revision.assert_called_once_with("main")
    app.nodes.add_node.assert_called_once()
    node = app.nodes.add_node.call_args.args[0]
    assert node.revision == SHA and node.name == "UK London" and node.ssh_user == "deploy"
    assert any(SHA in str(call) for call in panel.call_args_list)
    assert not any("SHA" in call.args[0] for call in ask.call_args_list)
    assert "pw" not in str(app.nodes.add_node.call_args)
    channel.assert_called_once_with("pw")


def test_revision_lookup_failure_stops_install_and_reports_safe_actionable_error():
    app = _app()
    app.nodes.resolve_revision.side_effect = RuntimeError("secret-token")
    with (
        patch.object(nodes_setup, "ask", side_effect=["node.example.com", "root", "uk-1", "UK London"]),
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch("builtins.input", return_value="2"),
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "error") as error,
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.add_node.assert_not_called()
    assert error.called
    assert "secret-token" not in str(error.call_args)
    assert "GitHub" in str(error.call_args)


def test_cancel_protocol_selection_does_not_fetch_sha():
    app = _app()
    with (
        patch.object(nodes_setup, "ask", side_effect=["node.example.com", "root", "uk-1", "UK London"]),
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch("builtins.input", return_value="0"),
        patch.object(nodes_setup, "panel"),
    ):
        nodes_setup.install_node(AppState(), app)
    app.nodes.resolve_revision.assert_not_called()
    app.nodes.add_node.assert_not_called()


def test_upgrade_resolves_branch_without_manual_sha_and_confirms_before_mutation():
    app = _app()
    node = NodeConfig(id="uk-1", branch="dev", revision="b" * 40)
    with (
        patch.object(nodes, "ask", return_value="dev") as ask,
        patch.object(nodes, "confirm", return_value=False),
        patch.object(nodes, "panel"),
    ):
        nodes._upgrade(node, app)
    assert ask.call_count == 1
    app.nodes.resolve_revision.assert_called_once_with("dev")
    app.nodes.change_update_target.assert_not_called()
    app.nodes.update.assert_not_called()


def test_automatic_protocol_port_does_not_require_typing_zero_into_data_field():
    app = _app()
    with (
        patch.object(nodes_setup, "menu", side_effect=["1"]),
        patch.object(nodes_setup, "panel"),
        patch.object(nodes_setup, "prompt") as prompt,
        patch.object(nodes_setup, "collect_protocol_config", return_value={"protocol_mode": "2.0"}),
    ):
        spec = nodes_setup.read_protocol("amneziawg", app, NodeProtocolSpec())
    assert spec is not None and spec.port == 0 and spec.enabled
    assert spec.config["protocol_mode"] == "2.0"
    prompt.assert_not_called()


def test_a_bad_address_is_re_asked_without_losing_the_other_answers(capsys):
    """One wrong field must not send the operator back to the beginning."""
    app = _app()
    with (
        patch.object(
            nodes_setup,
            "ask",
            side_effect=["not an address", "194.147.35.112", "root", "uk-1", "UK London"],
        ) as ask,
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch("builtins.input", side_effect=["2", "0"]),
    ):
        nodes_setup.install_node(AppState(), app)
    output = capsys.readouterr().out
    assert "повтори адрес" in output
    questions = [call.args[0].split(" (")[0] for call in ask.call_args_list]
    assert questions[:3] == ["Адрес VPS", "Адрес VPS", "Имя пользователя SSH"]
    # The address question is asked once more, and the password is not re-asked.
    assert questions.count("Адрес VPS") == 2
    assert questions.count("Пароль SSH") == 0
    app.nodes.add_node.assert_not_called()


def test_a_taken_node_id_is_re_asked_and_the_wizard_stays_in_place():
    app = _app()
    app.nodes.list_nodes.return_value = [NodeConfig(id="uk-1", address="203.0.113.7")]
    with (
        patch.object(nodes_setup, "ask", side_effect=["194.147.35.112", "root", "uk-1", "uk-2", "UK"]) as ask,
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch("builtins.input", side_effect=["2", "0"]),
        patch.object(nodes_setup, "error") as error,
    ):
        nodes_setup.install_node(AppState(), app)
    assert any("уже есть" in str(call) for call in error.call_args_list)
    assert [call.args[0].split(" (")[0] for call in ask.call_args_list].count("ID ноды") == 2


def test_the_plan_shows_the_technical_id_not_the_name(capsys):
    """A plan whose ID line shows the name tells the operator nothing about the node."""
    app = _app()
    with (
        patch.object(nodes_setup, "ask", side_effect=["194.147.35.112", "root", "uk-1", "Великобритания"]),
        patch.object(nodes_setup, "ask_secret", return_value="pw"),
        patch("builtins.input", side_effect=["2", "0"]),
    ):
        nodes_setup.install_node(AppState(), app)
    output = capsys.readouterr().out
    assert "uk-1" in output
    assert "Великобритания" in output
    # The ID line carries the id; the name lives on its own line.
    id_line = next(line for line in output.splitlines() if "ID:" in line)
    assert "uk-1" in id_line
    assert "Великобритания" not in id_line


def test_editing_the_branch_resolves_that_branch_commit():
    """A SHA belongs to its branch: editing one alone once installed the wrong tree."""
    app = _app()
    node = NodeConfig(id="uk-1", name="UK", address="194.147.35.112", branch="main", revision="a" * 40)
    with (
        patch.object(nodes_setup, "ask", return_value="dev"),
        patch.object(nodes_setup, "success"),
    ):
        nodes_setup._edit_branch(node, app)
    app.nodes.resolve_revision.assert_called_once_with("dev")
    assert node.branch == "dev"
    assert node.revision == SHA


def test_a_failed_branch_resolution_leaves_branch_and_commit_alone():
    app = _app()
    app.nodes.resolve_revision.side_effect = RuntimeError("github down")
    node = NodeConfig(id="uk-1", name="UK", address="194.147.35.112", branch="main", revision="a" * 40)
    with patch.object(nodes_setup, "ask", return_value="dev"), patch.object(nodes_setup, "error") as error:
        nodes_setup._edit_branch(node, app)
    assert node.branch == "main"
    assert node.revision == "a" * 40
    assert error.called


def test_the_plan_is_installed_with_the_script_of_its_own_revision():
    """The installer must come from the pinned commit, not from the base's checkout."""
    from hydra.services.nodes.bootstrap import NodeBootstrap

    requested: list[str] = []

    class FakeHost:
        pass

    bootstrap = NodeBootstrap(host=cast(HostBackend, FakeHost()), script="#!/bin/sh\necho base\n")
    with (
        patch.object(
            bootstrap,
            "bootstrap_script",
            side_effect=lambda revision: requested.append(revision) or "#!/bin/sh\necho pinned\n",
        ),
        patch("hydra.services.nodes.bootstrap.install_node") as install,
    ):
        bootstrap.install(
            node_id="uk-1",
            address="194.147.35.112",
            ssh_port=22,
            branch="dev",
            revision="b" * 40,
            confirm_fingerprint=lambda value: True,
        )
        provider = install.call_args.kwargs["script"]
        # A provider, not a value: the installer is fetched only when it is streamed,
        # so a refused host key causes no download at all.
        assert callable(provider)
        assert provider() == "#!/bin/sh\necho pinned\n"
        assert requested == ["b" * 40]


def test_a_branch_without_the_node_role_is_refused_before_the_plan():
    """A branch that predates the node role would fail only after touching the VPS."""
    app = _app()
    app.nodes.supports_node_mode.return_value = False
    with patch.object(nodes_setup, "error") as error:
        assert nodes_setup.resolve_revision(app, "main") is None
    assert "не содержит режим ноды" in str(error.call_args)
    app.nodes.resolve_revision.assert_called_once_with("main")


def test_a_branch_with_the_node_role_resolves_normally():
    app = _app()
    app.nodes.supports_node_mode.return_value = True
    assert nodes_setup.resolve_revision(app, "dev") == SHA
    app.nodes.supports_node_mode.assert_called_once_with(SHA)
