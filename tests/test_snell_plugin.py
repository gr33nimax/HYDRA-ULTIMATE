from __future__ import annotations

import json
from unittest.mock import patch
import pytest

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.snell.plugin import PORT_END, PORT_START, SNELL_VERSION, SnellPlugin


def _state(*users: User) -> AppState:
    state = AppState()
    state.network.server_ip = "203.0.113.10"
    state.protocols["snell"] = PluginState(enabled=True)
    state.users = list(users)
    return state


def test_each_user_gets_an_isolated_inbound():
    plugin = SnellPlugin()
    first = User("a@example.com", "uuid-a")
    second = User("b@example.com", "uuid-b")
    inbounds = plugin.configure(_state(first, second)).inbounds

    assert len(inbounds) == 2
    assert all(item["type"] == "snell" for item in inbounds)
    assert all(item["version"] == SNELL_VERSION for item in inbounds)
    assert all(item["network"] == ["tcp", "udp"] for item in inbounds)
    assert len({item["listen_port"] for item in inbounds}) == 2
    assert len({item["psk"] for item in inbounds}) == 2
    assert all(PORT_START <= item["listen_port"] <= PORT_END for item in inbounds)


def test_port_assignment_is_order_independent():
    plugin = SnellPlugin()
    first = User("a@example.com", "uuid-a")
    second = User("b@example.com", "uuid-b")
    assert plugin._port_map(_state(first, second)) == plugin._port_map(_state(second, first))


def test_previously_issued_port_is_preserved():
    plugin = SnellPlugin()
    existing = User("a@example.com", "uuid-a", credentials={"snell": {"port": 32123}})
    newcomer = User("b@example.com", "uuid-b")
    assert plugin._port_map(_state(existing, newcomer))[existing.uuid] == 32123


def test_blocked_user_keeps_reserved_port_but_has_no_inbound():
    plugin = SnellPlugin()
    active = User("a@example.com", "uuid-a")
    blocked = User("b@example.com", "uuid-b", blocked=True)
    state = _state(active, blocked)
    ports = plugin._port_map(state)
    inbounds = plugin.configure(state).inbounds

    assert set(ports) == {"uuid-a", "uuid-b"}
    assert [item["tag"] for item in inbounds] == [plugin._tag(active)]


def test_client_material_matches_inbound():
    plugin = SnellPlugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)
    inbound = plugin.configure(state).inbounds[0]
    client = json.loads(plugin.generate_client_config(user, state))
    outbound = next(item for item in client["outbounds"] if item["type"] == "snell")

    assert outbound["psk"] == inbound["psk"]
    assert outbound["server_port"] == inbound["listen_port"]
    assert outbound["obfs"] == {"mode": "tls", "host": "www.bing.com"}
    assert plugin.client_link(user, state).startswith("snell://")


def test_firewall_uses_dedicated_tcp_range():
    plugin = SnellPlugin()
    with patch("hydra.utils.firewall.open_range") as open_range:
        plugin.on_enable(_state())
    open_range.assert_called_once_with("tcp", PORT_START, PORT_END, "snell")


def test_v4_and_disabled_obfs_are_configurable():
    plugin = SnellPlugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)
    state.protocols["snell"].config.update({
        "version": 4, "obfs_mode": "", "obfs_host": "www.example.com",
    })
    inbound = plugin.configure(state).inbounds[0]
    outbound = next(
        item for item in json.loads(plugin.generate_client_config(user, state))["outbounds"]
        if item["type"] == "snell"
    )
    assert inbound["version"] == outbound["version"] == 4
    assert "obfs" not in inbound
    assert "obfs" not in outbound
    assert "obfs=" not in plugin.client_link(user, state)


def test_runtime_settings_apply_and_rollback():
    plugin = SnellPlugin()
    state = _state(User("a@example.com", "uuid-a"))
    with patch("hydra.core.state.save_state"), \
         patch("hydra.core.orchestrator.apply_config", return_value=True):
        assert plugin.set_settings(state, 4, "http", "cdn.example.com") is True
    assert state.protocols["snell"].config == {
        "version": 4, "obfs_mode": "http", "obfs_host": "cdn.example.com",
    }

    with patch("hydra.core.state.save_state"), \
         patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]):
        assert plugin.set_settings(state, 5, "tls", "new.example.com") is False
    assert state.protocols["snell"].config == {
        "version": 4, "obfs_mode": "http", "obfs_host": "cdn.example.com",
    }


def test_invalid_runtime_settings_do_not_mutate_state():
    plugin = SnellPlugin()
    state = _state(User("a@example.com", "uuid-a"))
    before = dict(state.protocols["snell"].config)
    with pytest.raises(ValueError, match="versions 4 and 5"):
        plugin.set_settings(state, 3, "tls", "cdn.example.com")
    assert state.protocols["snell"].config == before
