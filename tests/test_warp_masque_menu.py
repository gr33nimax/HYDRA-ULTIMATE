"""WARP MASQUE picker: cancellation never changes the running configuration."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra.core.state_models import AppState, PluginState
from hydra.ui.plugin_managers._warp_masque import _menu_masque, _result_lines


def test_picker_matches_numbered_dnscrypt_pages_without_selecting_a_dead_endpoint():
    rows = [
        {"address": "162.159.198.1", "port": 443, "ping_ms": 38.0, "loss_percent": 0, "node": "HEL", "seen_as": "NL"}
    ]
    rendered = "\n".join(_result_lines(rows, None, page=0))
    assert "1." in rendered and "162.159.198.1:443" in rendered
    assert "38" in rendered and "HEL" in rendered
    assert "[0]" in rendered


def test_cancel_after_scan_does_not_persist_a_candidate():
    state = AppState(protocols={"warp": PluginState(installed=True, enabled=True)})
    app = SimpleNamespace(
        plugin_query=MagicMock(return_value={"installed": True, "account_ready": True}),
        plugin_action=MagicMock(
            return_value=[
                {
                    "address": "162.159.198.1",
                    "port": 443,
                    "ping_ms": 38.0,
                    "loss_percent": 0,
                    "node": "HEL",
                    "seen_as": "NL",
                }
            ]
        ),
        plugin_command=MagicMock(),
    )
    with (
        patch("hydra.ui.plugin_managers._warp_masque.menu", side_effect=["1", "0"]),
        patch("hydra.ui.plugin_managers._warp_masque.confirm", return_value=True),
        patch("hydra.ui.plugin_managers._warp_masque.prompt", side_effect=["0"]),
        patch("hydra.ui.plugin_managers._warp_masque.clear"),
    ):
        _menu_masque(state, app)
    app.plugin_command.assert_not_called()
    assert "masque_endpoint" not in state.protocols["warp"].config
