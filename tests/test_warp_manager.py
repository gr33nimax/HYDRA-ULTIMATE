from unittest.mock import MagicMock, patch

from hydra.core.state import AppState, PluginState
from hydra.plugins.warp.manager import _commit_route_target


def _state_with_target(target="direct"):
    state = AppState()
    plugin_state = PluginState(enabled=True, config={
        "list_targets": {"ext:russia": target},
    })
    state.protocols["warp"] = plugin_state
    return state, plugin_state


@patch("hydra.plugins.warp.manager.save_state")
@patch("hydra.plugins.warp.manager.orchestrator.last_apply_error", return_value="invalid endpoint")
@patch("hydra.plugins.warp.manager.orchestrator.apply_config")
def test_route_change_rolls_back_when_runtime_apply_fails(apply, _error, save):
    state, plugin_state = _state_with_target()
    plugin = MagicMock()
    plugin.update_external_rules.return_value = (True, "updated")
    apply.side_effect = lambda current: (
        current.protocols.__setitem__(
            "warp",
            PluginState(enabled=True, config={"list_targets": {"ext:russia": "warp"}}),
        )
        or False
    )

    ok, message = _commit_route_target(state, plugin_state, "ext:russia", "warp", plugin)

    assert ok is False
    assert "invalid endpoint" in message
    assert plugin_state.config["list_targets"]["ext:russia"] == "direct"
    assert state.protocols["warp"] is plugin_state
    assert save.call_count == 2


@patch("hydra.plugins.warp.manager.save_state")
@patch("hydra.plugins.warp.manager.orchestrator.apply_config")
def test_route_change_rolls_back_when_external_download_fails(apply, save):
    state, plugin_state = _state_with_target()
    plugin = MagicMock()
    plugin.update_external_rules.return_value = (False, "download failed")

    ok, message = _commit_route_target(state, plugin_state, "ext:russia", "warp", plugin)

    assert (ok, message) == (False, "download failed")
    assert plugin_state.config["list_targets"]["ext:russia"] == "direct"
    apply.assert_not_called()
    assert save.call_count == 2


@patch("hydra.plugins.warp.manager.save_state")
@patch("hydra.plugins.warp.manager.orchestrator.apply_config", return_value=True)
def test_route_change_is_kept_after_success(_apply, save):
    state, plugin_state = _state_with_target()
    plugin = MagicMock()
    plugin.update_external_rules.return_value = (True, "updated")

    ok, message = _commit_route_target(state, plugin_state, "ext:russia", "warp", plugin)

    assert (ok, message) == (True, "")
    assert plugin_state.config["list_targets"]["ext:russia"] == "warp"
    assert save.call_count == 1
