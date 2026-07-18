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
    plugin.set_congestion.return_value = True

    with patch("hydra.ui.menus.menu", side_effect=["3", "1", "0"]), \
         patch("hydra.ui.menus.prompt", return_value=""):
        _menu_hysteria2_settings(state, plugin)

    plugin.set_congestion.assert_called_once_with(state, "bbr")


def test_snell_tui_changes_obfs():
    state = AppState()
    state.protocols["snell"] = PluginState(installed=True, enabled=True, config={
        "version": 4, "obfs_mode": "tls", "obfs_host": "www.bing.com",
    })
    plugin = MagicMock()
    plugin._version.return_value = 4
    plugin.set_settings.return_value = True

    with patch("hydra.ui.menus.menu", side_effect=["1", "3", "0"]), \
         patch("hydra.ui.menus.prompt", return_value=""):
        _menu_snell_settings(state, plugin)

    plugin.set_settings.assert_called_once_with(state, 4, "", "www.bing.com")
