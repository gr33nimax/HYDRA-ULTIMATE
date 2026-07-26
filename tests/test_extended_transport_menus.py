from __future__ import annotations

from unittest.mock import MagicMock, patch

from hydra.core.state import AppState, PluginState
from hydra.ui.menus import _menu_hysteria2_settings, _menu_snell_settings


def test_hysteria2_tui_changes_congestion_mode():
    state = AppState()
    state.protocols["hysteria2"] = PluginState(installed=True, enabled=True, config={
        "domain": "hy.example.com", "port": 8443, "congestion_mode": "bbr",
    })
    plugin = MagicMock()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.plugin_command.return_value = True

    with patch("hydra.ui.menus.menu", side_effect=["3", "1", "0"]), \
         patch("hydra.ui.menus.prompt", return_value=""):
        _menu_hysteria2_settings(state, plugin, app)

    app.plugin_command.assert_called_once_with(
        state,
        "hysteria2",
        "set_congestion",
        mode="bbr",
    )


def test_snell_tui_changes_obfs():
    state = AppState()
    state.protocols["snell"] = PluginState(installed=True, enabled=True, config={
        "version": 4, "obfs_mode": "http", "obfs_host": "www.bing.com",
    })
    plugin = MagicMock()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.plugin_command.return_value = True

    with patch("hydra.ui.menus.menu", side_effect=["1", "2", "0"]), \
         patch("hydra.ui.menus.prompt", return_value=""):
        _menu_snell_settings(state, plugin, app)

    app.plugin_command.assert_called_once_with(
        state,
        "snell",
        "set_settings",
        version=4,
        obfs_mode="",
        obfs_host="www.bing.com",
    )
    assert plugin.method_calls == []
