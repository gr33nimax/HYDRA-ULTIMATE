from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hydra.services.plugin_actions import PluginActionService


def _plugin(**handlers):
    return SimpleNamespace(
        meta=SimpleNamespace(
            name="antidpi",
            contract_version=1,
            capabilities=SimpleNamespace(actions=("manual_ban",)),
        ),
        **handlers,
    )


def test_allowlisted_action_returns_plugin_owned_result():
    expected = {"ok": True, "remaining": 3600}
    plugin = _plugin(manual_ban=MagicMock(return_value=expected))
    service = PluginActionService(get_plugin=lambda name: plugin)

    result = service.execute(
        "antidpi",
        "manual_ban",
        raw="203.0.113.7",
        source="test",
    )

    assert result == expected
    plugin.manual_ban.assert_called_once_with(
        raw="203.0.113.7",
        source="test",
    )


def test_action_allowlist_rejects_unpublished_plugin_methods():
    get_plugin = MagicMock()
    service = PluginActionService(get_plugin=get_plugin)

    with pytest.raises(ValueError, match="unsupported plugin action"):
        service.execute("antidpi", "_load_state")

    get_plugin.assert_not_called()


def test_action_reports_missing_plugin_at_the_boundary():
    service = PluginActionService(get_plugin=lambda name: None)

    with pytest.raises(ValueError, match="unknown plugin"):
        service.execute("honeypot", "unban", raw="203.0.113.7")
