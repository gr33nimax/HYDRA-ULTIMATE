from __future__ import annotations

import json
from unittest.mock import patch
import pytest

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.base import PluginCategory
from hydra.plugins.hysteria2.plugin import DEFAULT_PORT, Hysteria2Plugin


def _state(*users: User) -> AppState:
    state = AppState()
    state.network.server_ip = "203.0.113.10"
    state.protocols["hysteria2"] = PluginState(enabled=True, config={
        "domain": "hy.example.com",
        "cert_file": "/cert.pem",
        "key_file": "/key.pem",
        "port": DEFAULT_PORT,
        "obfs_password": "salamander-secret",
    })
    state.users = list(users)
    return state


def test_meta_and_extended_inbound_contract():
    plugin = Hysteria2Plugin()
    state = _state(User("a@example.com", "uuid-a"))

    inbound = plugin.configure(state).inbounds[0]

    assert plugin.meta.category == PluginCategory.TRANSPORT
    assert inbound["type"] == "hysteria2"
    assert inbound["listen_port"] == 8443
    assert inbound["users"][0]["name"] == "a@example.com"
    assert inbound["obfs"] == {"type": "salamander", "password": "salamander-secret"}
    assert inbound["tls"]["alpn"] == ["h3"]
    assert inbound["masquerade"]["type"] == "string"


def test_blocked_users_are_not_authorized():
    state = _state(
        User("active@example.com", "uuid-a"),
        User("blocked@example.com", "uuid-b", blocked=True),
    )
    users = Hysteria2Plugin().configure(state).inbounds[0]["users"]
    assert [user["name"] for user in users] == ["active@example.com"]


def test_client_config_and_share_link_match_server():
    plugin = Hysteria2Plugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)

    config = json.loads(plugin.generate_client_config(user, state))
    outbound = next(item for item in config["outbounds"] if item["type"] == "hysteria2")
    link = plugin.client_link(user, state)

    assert outbound["password"] == plugin._password(user.uuid)
    assert outbound["server_port"] == DEFAULT_PORT
    assert outbound["tls"]["server_name"] == "hy.example.com"
    assert link.startswith("hysteria2://")
    assert "obfs=salamander" in link
    assert "sni=hy.example.com" in link


def test_enable_prepares_tls_and_opens_udp():
    plugin = Hysteria2Plugin()
    state = _state()
    with patch("hydra.plugins.hysteria2.plugin.ensure_tls_material") as ensure, \
         patch("hydra.utils.firewall.open_udp") as open_udp:
        plugin.on_enable(state)
    ensure.assert_called_once_with(state, "hysteria2")
    open_udp.assert_called_once_with(DEFAULT_PORT, "hysteria2")


def test_invalid_port_is_rejected():
    state = _state(User("a@example.com", "uuid-a"))
    state.protocols["hysteria2"].config["port"] = 70000
    with pytest.raises(ValueError, match="between 1 and 65535"):
        Hysteria2Plugin().configure(state)


def test_brutal_bandwidth_is_applied_to_server_and_client():
    plugin = Hysteria2Plugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)
    state.protocols["hysteria2"].config.update({
        "congestion_mode": "brutal", "up_mbps": 250, "down_mbps": 500,
    })

    inbound = plugin.configure(state).inbounds[0]
    outbound = next(
        item for item in json.loads(plugin.generate_client_config(user, state))["outbounds"]
        if item["type"] == "hysteria2"
    )
    assert inbound["up_mbps"] == outbound["up_mbps"] == 250
    assert inbound["down_mbps"] == outbound["down_mbps"] == 500
    assert "ignore_client_bandwidth" not in inbound


def test_runtime_port_change_updates_firewall_and_applies():
    plugin = Hysteria2Plugin()
    state = _state(User("a@example.com", "uuid-a"))
    with patch("hydra.core.state.save_state"), \
         patch("hydra.core.orchestrator.apply_config", return_value=True), \
         patch("hydra.utils.firewall.open_udp") as open_udp, \
         patch("hydra.utils.firewall.close_udp") as close_udp:
        assert plugin.set_port(state, 9444) is True
    assert state.protocols["hysteria2"].config["port"] == 9444
    open_udp.assert_called_once_with(9444, "hysteria2")
    close_udp.assert_called_once_with(DEFAULT_PORT, "hysteria2")


def test_failed_obfs_change_restores_previous_value():
    plugin = Hysteria2Plugin()
    state = _state(User("a@example.com", "uuid-a"))
    old_password = state.protocols["hysteria2"].config["obfs_password"]
    with patch("hydra.core.state.save_state"), \
         patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]):
        assert plugin.set_obfs_password(state, "new-salamander-password") is False
    assert state.protocols["hysteria2"].config["obfs_password"] == old_password


def test_invalid_congestion_does_not_mutate_state():
    plugin = Hysteria2Plugin()
    state = _state(User("a@example.com", "uuid-a"))
    before = dict(state.protocols["hysteria2"].config)
    with pytest.raises(ValueError, match="bbr or brutal"):
        plugin.set_congestion(state, "invalid")
    assert state.protocols["hysteria2"].config == before


def test_invalid_runtime_port_does_not_mutate_state():
    plugin = Hysteria2Plugin()
    state = _state(User("a@example.com", "uuid-a"))
    before = dict(state.protocols["hysteria2"].config)
    with pytest.raises(ValueError, match="between 1 and 65535"):
        plugin.set_port(state, 70000)
    assert state.protocols["hysteria2"].config == before
