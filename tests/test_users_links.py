"""Controller tests for descriptor-driven manual client artifacts."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from hydra.core.state_models import AppState, User
from hydra.plugins.base import PluginCategory
from hydra.services.protocols import ManualClientArtifact
from hydra.ui._menus.users_links import _client_artifacts, _link_caption, _render_inline_artifact


def test_manual_configs_include_global_plugin_artifacts() -> None:
    protocols = MagicMock()
    protocols.enabled_subscription_names.return_value = set()
    protocols.manual_client_artifacts.return_value = [
        ManualClientArtifact(
            plugin_name="wdtt",
            display_name="qWDTT",
            profile_name="master",
            profile_label="Master · общая для всех пользователей",
            config="",
            links=("qwdtt://config?pass=master",),
        ),
    ]
    app = SimpleNamespace(protocols=protocols)
    state = AppState()
    user = User(email="user@example.com", uuid="user-uuid")

    artifacts = _client_artifacts(state, user, app)  # type: ignore[arg-type]

    assert len(artifacts) == 1
    assert artifacts[0].plugin_name == "wdtt"
    assert artifacts[0].links == ("qwdtt://config?pass=master",)
    assert _link_caption(artifacts[0].links[0]) == "qWDTT master URL"
    protocols.manual_client_artifacts.assert_called_once_with(
        state,
        PluginCategory.TRANSPORT,
    )


def test_manual_configs_include_hydra_vk_tunnel() -> None:
    protocols = MagicMock()
    protocols.enabled_subscription_names.return_value = {"calls"}
    protocols.client_profiles.return_value = []
    protocols.client_config.return_value = '{"outbounds":[{"type":"call"}]}'
    protocols.client_links.return_value = []
    protocols.display_name.return_value = "Hydra VK Tunnel"
    protocols.manual_client_artifacts.return_value = []
    app = SimpleNamespace(protocols=protocols)
    state = AppState()
    user = User(email="user@example.com", uuid="user-uuid")

    artifacts = _client_artifacts(state, user, app)  # type: ignore[arg-type]

    assert [(item.plugin_name, item.display_name) for item in artifacts] == [
        ("calls", "Hydra VK Tunnel"),
    ]


def test_manual_configs_include_the_telemt_link_through_the_shared_artifact_layer() -> None:
    """R8: Telemt links are rendered here, not in the protocol manager."""
    link = "tg://proxy?server=203.0.113.10&port=443&secret=ee" + "a" * 96
    protocols = MagicMock()
    protocols.enabled_subscription_names.return_value = {"telemt"}
    protocols.client_profiles.return_value = []
    protocols.client_config.return_value = ""
    protocols.client_links.return_value = [link]
    protocols.display_name.return_value = "TeleMT"
    protocols.manual_client_artifacts.return_value = []
    app = SimpleNamespace(protocols=protocols)
    state = AppState()
    user = User(email="user@example.com", uuid="user-uuid")

    artifacts = _client_artifacts(state, user, app)  # type: ignore[arg-type]

    assert [(item.plugin_name, item.links) for item in artifacts] == [("telemt", (link,))]
    protocols.client_links.assert_called_once_with(state, "telemt", user)


def test_manual_configs_render_the_whole_telemt_link(capsys) -> None:
    """R8.2: the generic artifact view is the surface that prints the Telemt link."""
    link = "tg://proxy?server=203.0.113.10&port=443&secret=ee" + "a" * 96
    protocols = MagicMock()
    protocols.enabled_subscription_names.return_value = {"telemt"}
    protocols.client_profiles.return_value = []
    protocols.client_config.return_value = ""
    protocols.client_links.return_value = [link]
    protocols.manual_client_artifacts.return_value = []
    app = SimpleNamespace(
        protocols=protocols,
        configuration_names=SimpleNamespace(resolve=MagicMock(return_value="TeleMT")),
    )
    state = AppState()
    user = User(email="user@example.com", uuid="user-uuid")

    for artifact in _client_artifacts(state, user, app):  # type: ignore[arg-type]
        _render_inline_artifact(artifact, state, user, app)  # type: ignore[arg-type]

    assert link in capsys.readouterr().out


def test_manual_configs_keep_the_empty_state_when_telemt_is_disabled() -> None:
    """A disabled transport creates no Telemt-specific fallback screen."""
    protocols = MagicMock()
    protocols.enabled_subscription_names.return_value = set()
    protocols.client_profiles.return_value = []
    protocols.client_config.return_value = ""
    protocols.client_links.return_value = []
    protocols.manual_client_artifacts.return_value = []
    app = SimpleNamespace(protocols=protocols)
    state = AppState()
    user = User(email="user@example.com", uuid="user-uuid")

    artifacts = _client_artifacts(state, user, app)  # type: ignore[arg-type]

    assert artifacts == []
    protocols.client_links.assert_not_called()
