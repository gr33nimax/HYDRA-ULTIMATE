from __future__ import annotations

import json
from typing import cast
from unittest.mock import patch
import pytest

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.snell.plugin import PORT_END, PORT_START, SNELL_VERSION, SnellPlugin


@pytest.fixture(autouse=True)
def _core_with_the_upstream_snell():
    """The renderers assert the core gate; these tests exercise rendering itself."""
    with patch("hydra.plugins.snell.plugin.kernel_supports_snell", return_value=True):
        yield


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
    ports = [cast(int, item["listen_port"]) for item in inbounds]
    keys = [cast(str, item["psk"]) for item in inbounds]
    assert len(set(ports)) == 2
    assert len(set(keys)) == 2
    assert all(PORT_START <= port <= PORT_END for port in ports)


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
    # The classic generation is server 5 against client 4; the core has no outbound 5.
    assert inbound["version"] == 5
    assert outbound["version"] == 4
    assert "obfs" not in inbound
    assert "obfs" not in outbound
    assert "obfs-mode=" not in plugin.client_link(user, state)
    assert "udp-relay=true" in plugin.client_link(user, state)
    assert plugin.client_link(user, state).startswith("snell://")


def test_firewall_uses_dedicated_tcp_range():
    plugin = SnellPlugin()
    with patch("hydra.utils.firewall.open_range") as open_range:
        plugin.on_enable(_state())
    open_range.assert_called_once_with("tcp", PORT_START, PORT_END, "snell")


def test_enable_accepts_a_state_written_for_the_previous_core():
    plugin = SnellPlugin()
    state = _state()
    state.protocols["snell"].config["version"] = 4
    with patch("hydra.utils.firewall.open_range"):
        plugin.on_enable(state)
    assert plugin._version(state) == 5
    assert state.protocols["snell"].config["version"] == 4


def test_http_obfs_is_configurable_on_the_classic_generation():
    plugin = SnellPlugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)
    state.protocols["snell"].config.update(
        {
            "version": 5,
            "obfs_mode": "http",
            "obfs_host": "www.example.com",
        }
    )
    inbound = plugin.configure(state).inbounds[0]
    outbound = next(
        item for item in json.loads(plugin.generate_client_config(user, state))["outbounds"]
        if item["type"] == "snell"
    )

    assert inbound["version"] == 5
    assert outbound["version"] == 4
    assert inbound["obfs_mode"] == "http"
    assert outbound["obfs_mode"] == "http"
    assert outbound["obfs_host"] == "www.example.com"
    assert "obfs" not in inbound
    assert "obfs" not in outbound
    assert "obfs-mode=http" in plugin.client_link(user, state)
    assert "udp-relay=true" in plugin.client_link(user, state)


def test_tls_obfs_is_configurable_on_the_classic_generation():
    plugin = SnellPlugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)
    state.protocols["snell"].config.update(
        {
            "version": 5,
            "obfs_mode": "tls",
            "obfs_host": "cdn.example.com",
        }
    )
    inbound = plugin.configure(state).inbounds[0]
    outbound = next(
        item for item in json.loads(plugin.generate_client_config(user, state))["outbounds"]
        if item["type"] == "snell"
    )

    assert inbound["obfs_mode"] == "tls"
    assert outbound["obfs_mode"] == "tls"
    assert outbound["obfs_host"] == "cdn.example.com"
    assert "obfs-mode=tls" in plugin.client_link(user, state)


def test_generation_six_uses_its_own_mode_on_both_ends():
    plugin = SnellPlugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)
    state.protocols["snell"].config.update({"version": 6, "mode": "unshaped"})

    inbound = plugin.configure(state).inbounds[0]
    outbound = next(
        item for item in json.loads(plugin.generate_client_config(user, state))["outbounds"]
        if item["type"] == "snell"
    )

    assert inbound["version"] == outbound["version"] == 6
    assert inbound["mode"] == outbound["mode"] == "unshaped"
    assert "obfs_mode" not in inbound
    assert "obfs_mode" not in outbound
    assert "version=6" in plugin.client_link(user, state)
    assert "mode=unshaped" in plugin.client_link(user, state)


def test_settings_command_only_updates_desired_state():
    plugin = SnellPlugin()
    state = _state(User("a@example.com", "uuid-a"))
    assert plugin.set_settings(
        state,
        5,
        "http",
        "cdn.example.com",
    ) is True
    assert state.protocols["snell"].config == {
        "version": 5,
        "obfs_mode": "http",
        "obfs_host": "cdn.example.com",
        "mode": "default",
    }

    assert plugin.set_settings(
        state,
        6,
        "none",
        "cdn.example.com",
        "unshaped",
    ) is True
    assert state.protocols["snell"].config == {
        "version": 6,
        "obfs_mode": "none",
        "obfs_host": "cdn.example.com",
        "mode": "unshaped",
    }


def test_invalid_runtime_settings_do_not_mutate_state():
    plugin = SnellPlugin()
    state = _state(User("a@example.com", "uuid-a"))
    before = dict(state.protocols["snell"].config)
    with pytest.raises(ValueError, match="generations 5 and 6"):
        plugin.set_settings(
            state,
            3,
            "http",
            "cdn.example.com",
        )
    assert state.protocols["snell"].config == before

    with pytest.raises(ValueError, match="Snell obfs mode"):
        plugin.set_settings(
            state,
            5,
            "quic",
            "cdn.example.com",
        )
    assert state.protocols["snell"].config == before

    with pytest.raises(ValueError, match="replaces obfuscation"):
        plugin.set_settings(
            state,
            6,
            "tls",
            "cdn.example.com",
        )
    assert state.protocols["snell"].config == before


def test_a_state_written_for_the_previous_core_is_served_as_generation_five():
    plugin = SnellPlugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)
    state.protocols["snell"].config["version"] = 4

    inbound = plugin.configure(state).inbounds[0]
    outbound = next(
        item for item in json.loads(plugin.generate_client_config(user, state))["outbounds"]
        if item["type"] == "snell"
    )

    assert inbound["version"] == 5
    assert outbound["version"] == 4
    assert "version=4" in plugin.client_link(user, state)


def test_naive_domain_is_never_reused_as_snell_endpoint():
    plugin = SnellPlugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)
    state.network.server_ip = ""
    state.network.domain = "yagami.gr33nimax.ru"

    with patch("hydra.plugins.snell.plugin.public_ip", return_value="31.77.203.66"):
        client = json.loads(plugin.generate_client_config(user, state))
        link = plugin.client_link(user, state)

    outbound = next(item for item in client["outbounds"] if item["type"] == "snell")
    assert outbound["server"] == "31.77.203.66"
    assert "@31.77.203.66:" in link
    assert "yagami.gr33nimax.ru" not in link


def test_ipv6_endpoint_is_bracketed_in_share_link():
    plugin = SnellPlugin()
    user = User("a@example.com", "uuid-a")
    state = _state(user)
    state.network.server_ip = "2001:db8::10"

    assert "@[2001:db8::10]:" in plugin.client_link(user, state)
