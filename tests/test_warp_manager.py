from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

from hydra.core.state import AppState, PluginState
from hydra.plugins.warp.manager import _commit_route_target


def _state_with_target(target="direct"):
    state = AppState()
    plugin_state = PluginState(
        enabled=True,
        config={"list_targets": {"ext:russia": target}},
    )
    state.protocols["warp"] = plugin_state
    return state, plugin_state


def _application(*, update=(True, "updated"), applied=True, error=""):
    save = Mock()
    plugin_action = Mock(return_value=update)
    apply = Mock(return_value=applied)
    return SimpleNamespace(
        admin=SimpleNamespace(save_state=save),
        plugin_action=plugin_action,
        apply=apply,
        apply_error=Mock(return_value=error),
    )


def test_route_change_rolls_back_when_runtime_apply_fails():
    state, plugin_state = _state_with_target()
    app = _application(applied=False, error="invalid endpoint")
    app.apply.side_effect = lambda current: (
        current.protocols.__setitem__(
            "warp",
            PluginState(
                enabled=True,
                config={"list_targets": {"ext:russia": "warp"}},
            ),
        )
        or False
    )

    ok, message = _commit_route_target(
        state,
        plugin_state,
        "ext:russia",
        "warp",
        app,
    )

    assert ok is False
    assert "invalid endpoint" in message
    assert plugin_state.config["list_targets"]["ext:russia"] == "direct"
    assert state.protocols["warp"] is plugin_state
    assert app.admin.save_state.call_count == 2


def test_route_change_rolls_back_when_external_download_fails():
    state, plugin_state = _state_with_target()
    app = _application(update=(False, "download failed"))

    ok, message = _commit_route_target(
        state,
        plugin_state,
        "ext:russia",
        "warp",
        app,
    )

    assert (ok, message) == (False, "download failed")
    assert plugin_state.config["list_targets"]["ext:russia"] == "direct"
    app.apply.assert_not_called()
    assert app.admin.save_state.call_count == 2


def test_route_change_is_kept_after_success():
    state, plugin_state = _state_with_target()
    app = _application()

    ok, message = _commit_route_target(
        state,
        plugin_state,
        "ext:russia",
        "warp",
        app,
    )

    assert (ok, message) == (True, "")
    assert plugin_state.config["list_targets"]["ext:russia"] == "warp"
    assert app.admin.save_state.call_count == 1
