from unittest.mock import Mock

from hydra.core.state import AppState, NetworkConfig, PluginState
from hydra.core import status


def test_build_status_uses_effective_dnscrypt_state_without_mutating_config():
    state = AppState(
        network=NetworkConfig(),
        protocols={"dnscrypt": PluginState(enabled=False)},
    )
    read_statuses = Mock(
        return_value={"dnscrypt": {"enabled": True, "running": True}},
    )
    payload = status.build_status(state, read_statuses)

    read_statuses.assert_called_once_with(state)
    assert payload["network"]["dnscrypt_enabled"] is True
    assert payload["network"]["configured_dnscrypt_enabled"] is False
    assert state.protocols["dnscrypt"].enabled is False


def test_build_status_never_exposes_clash_api_secret():
    state = AppState(network=NetworkConfig(clash_api_secret="top-secret"))

    payload = status.build_status(state, Mock(return_value={}))

    assert "clash_api_secret" not in payload["network"]
    assert payload["network"]["clash_api_auth_configured"] is True
