"""Fresh managed-node public parameters must produce usable local AWG material."""
from copy import deepcopy
from unittest.mock import MagicMock
import pytest

from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.services.protocol_setup import ProtocolSetupService


@pytest.mark.parametrize("mode", ["2.0", "3.1"])
def test_fresh_node_awg_parameters_materialize_endpoint_and_client_without_rotating_keys(mode):
    state = AppState(users=[User(email="one", uuid="user-1")], protocols={
        "amneziawg": PluginState(enabled=True, installed=True, port=443, config={"protocol_mode": mode}),
    })
    state.network.server_ip = "203.0.113.4"
    plugin = AmneziaWGPlugin()
    certificates = MagicMock()
    setup = ProtocolSetupService(certificates, lambda name: plugin if name == "amneziawg" else None)
    assert plugin.configure(state).endpoints == []
    setup.prepare_enabled(state)
    endpoints = plugin.configure(state).endpoints
    assert len(endpoints) == 1 and endpoints[0]["listen_port"] == 443
    if mode == "3.1":
        assert endpoints[0]["amnezia"]["random_trailers"] is True
        assert endpoints[0]["amnezia"]["disable_cookies"] is True
        assert endpoints[0]["amnezia"]["header_protection_key"]
    assert "PrivateKey" in plugin.generate_client_config(state.users[0], state)
    before = deepcopy(state)
    setup.prepare_enabled(state)
    assert state == before
    certificates.ensure.assert_not_called()
