from __future__ import annotations

from unittest.mock import MagicMock, patch

from hydra.core.state import AppState, PluginState

# The public facade materialises its forwarders at import time, so a static analyser
# cannot resolve these names even though the facade owns them.
from hydra.ui.menus import _menu_hysteria2_settings, _menu_snell_settings  # type: ignore[attr-defined]


def test_hysteria2_tui_changes_congestion_mode():
    state = AppState()
    state.protocols["hysteria2"] = PluginState(
        installed=True,
        enabled=True,
        config={
            "domain": "hy.example.com",
            "port": 8443,
            "congestion_mode": "bbr",
        },
    )
    plugin = MagicMock()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.plugin_command.return_value = True

    with patch("hydra.ui.menus.menu", side_effect=["3", "1", "0"]), patch("hydra.ui.menus.prompt", return_value=""):
        _menu_hysteria2_settings(state, plugin, app)

    app.plugin_command.assert_called_once_with(
        state,
        "hysteria2",
        "set_congestion",
        mode="bbr",
    )


def test_snell_tui_changes_obfs_to_tls_on_the_classic_generation():
    state = AppState()
    state.protocols["snell"] = PluginState(
        installed=True,
        enabled=True,
        config={
            "version": 4,
            "obfs_mode": "http",
            "obfs_host": "www.bing.com",
        },
    )
    plugin = MagicMock()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.plugin_command.return_value = True

    with (
        patch("hydra.ui.menus.menu", side_effect=["2", "2", "0"]),
        patch("hydra.ui.menus.prompt", return_value="cdn.example.com"),
    ):
        _menu_snell_settings(state, plugin, app)

    # The stored version 4 is the classic generation; its client half stays a 4.
    app.plugin_command.assert_called_once_with(
        state,
        "snell",
        "set_settings",
        version=5,
        obfs_mode="tls",
        obfs_host="cdn.example.com",
        mode="default",
    )
    assert plugin.method_calls == []


def test_snell_tui_switches_to_generation_six_after_the_warning():
    state = AppState()
    state.protocols["snell"] = PluginState(
        installed=True,
        enabled=True,
        config={
            "version": 5,
            "obfs_mode": "http",
            "obfs_host": "www.bing.com",
        },
    )
    plugin = MagicMock()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.plugin_command.return_value = True

    with (
        patch("hydra.ui.menus.menu", side_effect=["1", "2", "1", "0"]),
        patch("hydra.ui.menus.prompt", return_value=""),
    ):
        _menu_snell_settings(state, plugin, app)

    app.plugin_command.assert_called_once_with(
        state,
        "snell",
        "set_settings",
        version=6,
        obfs_mode="none",
        mode="default",
    )


def test_snell_tui_keeps_the_generation_when_the_v6_warning_is_cancelled():
    state = AppState()
    state.protocols["snell"] = PluginState(
        installed=True,
        enabled=True,
        config={
            "version": 5,
            "obfs_mode": "http",
            "obfs_host": "www.bing.com",
        },
    )
    plugin = MagicMock()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.plugin_command.return_value = True

    with (
        patch("hydra.ui.menus.menu", side_effect=["1", "2", "0", "0"]),
        patch("hydra.ui.menus.prompt", return_value=""),
    ):
        _menu_snell_settings(state, plugin, app)

    app.plugin_command.assert_not_called()


def test_snell_tui_picks_a_v6_mode():
    state = AppState()
    state.protocols["snell"] = PluginState(
        installed=True,
        enabled=True,
        config={
            "version": 6,
            "mode": "default",
        },
    )
    plugin = MagicMock()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.plugin_command.return_value = True

    with patch("hydra.ui.menus.menu", side_effect=["2", "3", "0"]), patch("hydra.ui.menus.prompt", return_value=""):
        _menu_snell_settings(state, plugin, app)

    app.plugin_command.assert_called_once_with(
        state,
        "snell",
        "set_settings",
        version=6,
        obfs_mode="none",
        mode="unsafe-raw",
    )
