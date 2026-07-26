from unittest.mock import MagicMock, patch

from hydra.core.state import AppState, PluginState
from hydra.plugins.base import PluginStatus
from hydra.ui import menus


def test_protocol_menu_refreshes_state_before_status_render():
    stale = AppState()
    fresh = AppState(protocols={"anytls": PluginState(installed=True, enabled=True)})
    app = MagicMock()
    app.admin.load_state.return_value = fresh
    app.protocols.list.return_value = []
    app.protocols.statuses.return_value = {}

    with patch.object(menus, "clear"), \
         patch.object(menus, "panel"), \
         patch.object(menus, "menu", return_value="0"):
        menus.menu_protocols(stale, app)

    app.admin.load_state.assert_called_once_with()
    app.protocols.statuses.assert_called_once_with(fresh)


def test_anytls_menu_refreshes_state_before_choosing_action():
    stale = AppState(protocols={"anytls": PluginState(installed=False, enabled=False)})
    fresh = AppState(protocols={"anytls": PluginState(installed=True, enabled=True)})
    plugin = MagicMock()
    plugin.meta.name = "anytls"
    plugin.get_current_preset.return_value = "web_browsing"
    app = MagicMock()
    app.admin.load_state.return_value = fresh
    app.protocols.status.return_value = PluginStatus(True, True, True, 20444)
    app.plugin_query.return_value = "web_browsing"

    with patch.object(menus, "clear"), \
         patch.object(menus, "protocol_status_panel"), \
         patch.object(menus, "menu", return_value="0"):
        menus._menu_anytls(stale, plugin, app)

    app.admin.load_state.assert_called_once_with()
    app.protocols.status.assert_called_once_with("anytls")
    app.plugin_query.assert_called_once_with(
        "anytls",
        "get_current_preset",
        state=fresh,
    )
    plugin.get_current_preset.assert_not_called()
