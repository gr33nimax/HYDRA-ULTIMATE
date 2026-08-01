"""Controller tests for descriptor-driven manual client artifacts."""
from types import SimpleNamespace
from unittest.mock import MagicMock

from hydra.core.state_models import AppState, User
from hydra.plugins.base import PluginCategory
from hydra.services.protocols import ManualClientArtifact
from hydra.ui._menus.users_links import _client_artifacts, _link_caption


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

    artifacts = _client_artifacts(state, user, app)

    assert len(artifacts) == 1
    assert artifacts[0].plugin_name == "wdtt"
    assert artifacts[0].links == ("qwdtt://config?pass=master",)
    assert _link_caption(artifacts[0].links[0]) == "qWDTT master URL"
    protocols.manual_client_artifacts.assert_called_once_with(
        state,
        PluginCategory.TRANSPORT,
    )
