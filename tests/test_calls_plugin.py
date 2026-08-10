from __future__ import annotations

from dataclasses import dataclass, field
import json
from unittest.mock import patch

import pytest

from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.base import PluginCategory
from hydra.plugins.calls import CallsPlugin
from hydra.plugins.calls.configuration import user_password
from hydra.services.subscriptions.links import generate_links


@dataclass
class Source:
    cookies: list[dict[str, str]]
    link: str
    supported: bool = True
    running: bool = True
    links: list[str] = field(default_factory=list)
    multi: bool = False

    def load_vk_cookies(self) -> list[dict[str, str]]:
        return self.cookies

    def load_native_join_link(self) -> str:
        return self.link

    def load_native_join_links(self) -> list[str]:
        return list(self.links)

    def feature_supported(self) -> bool:
        return self.supported

    def multi_user_supported(self) -> bool:
        return self.multi

    def singbox_running(self) -> bool:
        return self.running


def _state(*, enabled: bool = True) -> AppState:
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={
            "calls": PluginState(
                installed=True,
                enabled=enabled,
                config={
                    "mode": "multi_user",
                    "obfs_password": "o" * 43,
                },
            ),
        },
    )
    state.network.server_ip = "203.0.113.10"
    return state


def test_calls_plugin_contract_and_native_fragment() -> None:
    source = Source(
        cookies=[],
        link="",
        links=["https://vk.com/call/join/room-token"],
        multi=True,
    )
    plugin = CallsPlugin(source)

    assert plugin.meta.name == "calls"
    assert plugin.meta.display_name == "Hydra VK Tunnel"
    assert plugin.meta.subscription_profile_name == "Обход БС"
    assert plugin.meta.category is PluginCategory.TRANSPORT
    assert plugin.meta.capabilities.central_apply is True
    assert plugin.meta.capabilities.subscription_enabled is False
    assert plugin.meta.capabilities.hydra_v2_subscription_enabled is True
    assert plugin.meta.capabilities.connection_source == "tracked"
    assert plugin.meta.capabilities.config_defaults == (
        ("mode", "multi_user"),
        ("room_count", 4),
        ("listen_port", 56002),
    )
    inbound = plugin.configure(_state()).inbounds[0]
    assert inbound["mode"] == "multi_user"
    assert "join_link" not in inbound
    assert "cookies" not in inbound
    fragment = plugin.configure(_state())
    assert fragment.outbounds == []


def test_calls_plugin_disabled_is_empty_and_enabled_requires_secrets() -> None:
    plugin = CallsPlugin(Source([], ""))
    assert plugin.configure(_state(enabled=False)).inbounds == []
    with pytest.raises(ValueError, match="multi_user"):
        plugin.configure(_state())


def test_calls_plugin_rejects_legacy_p2p_mode() -> None:
    state = _state()
    state.protocols["calls"].config["mode"] = "p2p"
    source = Source([], "", multi=True)
    with pytest.raises(ValueError, match="must be multi_user"):
        CallsPlugin(source).configure(state)


def test_calls_plugin_emits_exact_hydracore_multi_user_contract() -> None:
    source = Source(
        [],
        "",
        links=[
            "https://vk.com/call/join/one",
            "https://vk.com/call/join/two",
        ],
        multi=True,
    )
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={"calls": PluginState(installed=True, enabled=True, config={
            "mode": "multi_user",
            "listen_port": 56002,
            "obfs_password": "o" * 43,
            "workers": 4,
        })},
    )
    state.network.server_ip = "203.0.113.10"
    plugin = CallsPlugin(source)

    inbound = plugin.configure(state).inbounds[0]
    assert inbound == {
        "type": "call",
        "tag": "calls-vk-in",
        "platform": "vk",
        "mode": "multi_user",
        "listen": "0.0.0.0",
        "listen_port": 56002,
        "obfs_password": "o" * 43,
        "users": [{
            "name": "alice@example.com",
            "password": user_password(state.users[0]),
            "max_sessions": 1,
        }],
        "max_sessions": 128,
        "max_workers_per_session": 4,
        "max_pending_handshakes": 256,
        "handshake_timeout": "10s",
        "session_idle_timeout": "5m",
    }
    outbound = json.loads(plugin.generate_client_config(state.users[0], state))["outbounds"][0]
    assert outbound["join_links"] == source.links
    assert outbound["server"] == "203.0.113.10"
    assert outbound["server_port"] == 56002
    assert outbound["workers"] == 4
    assert outbound["worker_connect_timeout"] == "15s"
    assert "cookies" not in inbound and "join_link" not in inbound
    assert "join_link" not in outbound


def test_calls_client_uses_public_ip_instead_of_transport_sni() -> None:
    source = Source(
        [],
        "",
        links=["https://vk.com/call/join/one"],
        multi=True,
    )
    state = _state()
    state.network.server_ip = ""
    state.network.domain = "transport-sni.example"

    with patch(
        "hydra.plugins.calls.configuration.public_ip",
        return_value="203.0.113.42",
    ):
        payload = CallsPlugin(source).generate_client_config(state.users[0], state)

    outbound = json.loads(payload)["outbounds"][0]
    assert outbound["server"] == "203.0.113.42"
    assert outbound["server"] != state.network.domain


def test_calls_client_rejects_a_url_as_public_endpoint() -> None:
    source = Source(
        [],
        "",
        links=["https://vk.com/call/join/one"],
        multi=True,
    )
    state = _state()
    state.protocols["calls"].config["public_endpoint"] = "https://sni.example"

    with pytest.raises(ValueError, match="scheme, port, or path"):
        CallsPlugin(source).generate_client_config(state.users[0], state)


def test_calls_multi_user_normalizes_links_and_enforces_worker_budget() -> None:
    source = Source(
        [],
        "",
        links=[" https://vk.com/call/join/one "],
        multi=True,
    )
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={"calls": PluginState(installed=True, enabled=True, config={
            "mode": "multi_user",
            "obfs_password": "o" * 43,
            "workers": 28,
            "max_workers_per_session": 108,
        })},
    )
    state.network.server_ip = "203.0.113.10"

    with pytest.raises(ValueError, match="workers.*between 1 and 27"):
        CallsPlugin(source).generate_client_config(state.users[0], state)

    del state.protocols["calls"].config["workers"]
    default_outbound = json.loads(
        CallsPlugin(source).generate_client_config(state.users[0], state),
    )["outbounds"][0]
    assert default_outbound["workers"] == 1

    state.protocols["calls"].config["workers"] = 27
    outbound = json.loads(
        CallsPlugin(source).generate_client_config(state.users[0], state),
    )["outbounds"][0]
    assert outbound["join_links"] == ["https://vk.com/call/join/one"]
    assert outbound["workers"] == 27


def test_calls_multi_user_rejects_duplicate_links() -> None:
    source = Source(
        [],
        "",
        links=[
            "https://vk.com/call/join/one",
            " https://vk.com/call/join/one ",
        ],
        multi=True,
    )
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={"calls": PluginState(installed=True, enabled=True, config={
            "mode": "multi_user",
            "obfs_password": "o" * 43,
        })},
    )
    state.network.server_ip = "203.0.113.10"

    with pytest.raises(ValueError, match="unique VK join links"):
        CallsPlugin(source).generate_client_config(state.users[0], state)


def test_calls_multi_user_rejects_enabled_external_udp_port_collision() -> None:
    source = Source(
        [],
        "",
        links=["https://vk.com/call/join/one"],
        multi=True,
    )
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={
            "calls": PluginState(installed=True, enabled=True, config={
                "mode": "multi_user",
                "listen_port": 56001,
                "obfs_password": "o" * 43,
            }),
            "wdtt": PluginState(enabled=True, config={"wg_port": 56001}),
        },
    )

    with pytest.raises(ValueError, match=r"wdtt\.wg_port"):
        CallsPlugin(source).configure(state)


@pytest.mark.parametrize(
    ("awg", "field"),
    [
        (PluginState(enabled=True, port=51820), r"amneziawg\.port"),
        (
            PluginState(
                enabled=True,
                config={"profiles": {"mobile": {"port": 51820}}},
            ),
            r"amneziawg\.profiles\.mobile\.port",
        ),
    ],
)
def test_calls_multi_user_rejects_amneziawg_udp_collision(awg, field) -> None:
    source = Source([], "", links=["https://vk.com/call/join/one"], multi=True)
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={
            "calls": PluginState(installed=True, enabled=True, config={
                "mode": "multi_user",
                "listen_port": 51820,
                "obfs_password": "o" * 43,
            }),
            "amneziawg": awg,
        },
    )

    with pytest.raises(ValueError, match=field):
        CallsPlugin(source).configure(state)


def test_calls_multi_user_normalizes_shared_obfs_password() -> None:
    source = Source([], "", links=["https://vk.com/call/join/one"], multi=True)
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={"calls": PluginState(installed=True, enabled=True, config={
            "mode": "multi_user",
            "obfs_password": f"  {'o' * 43}  ",
        })},
    )
    state.network.server_ip = "203.0.113.10"
    plugin = CallsPlugin(source)

    inbound = plugin.configure(state).inbounds[0]
    outbound = json.loads(
        plugin.generate_client_config(state.users[0], state),
    )["outbounds"][0]

    assert inbound["obfs_password"] == "o" * 43
    assert outbound["obfs_password"] == inbound["obfs_password"]


def test_calls_multi_user_default_workers_respects_session_cap() -> None:
    source = Source(
        [],
        "",
        links=[f"https://vk.com/call/join/{index}" for index in range(4)],
        multi=True,
    )
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={"calls": PluginState(installed=True, enabled=True, config={
            "mode": "multi_user",
            "obfs_password": "o" * 43,
            "max_workers_per_session": 1,
        })},
    )
    state.network.server_ip = "203.0.113.10"

    outbound = json.loads(
        CallsPlugin(source).generate_client_config(state.users[0], state),
    )["outbounds"][0]

    assert outbound["workers"] == 1


def test_calls_apply_opens_listener_and_rollback_restores_firewall(monkeypatch) -> None:
    source = Source(
        [],
        "",
        links=["https://vk.com/call/join/one"],
        multi=True,
    )
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
        protocols={"calls": PluginState(installed=True, enabled=True, config={
            "mode": "multi_user",
            "obfs_password": "o" * 43,
        })},
    )
    opened: set[int] = set()
    monkeypatch.setattr(
        "hydra.utils.firewall.port_is_open",
        lambda proto, port: proto == "udp" and port in opened,
    )
    monkeypatch.setattr(
        "hydra.utils.firewall.open_udp",
        lambda port, _comment: opened.add(port),
    )
    monkeypatch.setattr(
        "hydra.utils.firewall.close_udp",
        lambda port, _comment: opened.discard(port),
    )
    plugin = CallsPlugin(source)

    snapshot = plugin.snapshot(state)
    assert plugin.apply(state) is True
    assert opened == {56002}
    assert plugin.rollback(state, snapshot) is True
    assert opened == set()


class SubscriptionPlugins:
    def __init__(self, plugin: CallsPlugin) -> None:
        self.plugin = plugin
        self.client_link_called = False

    def enabled_transports(self, state):
        return [self.plugin]

    def client_links(self, plugin, user, state):
        self.client_link_called = True
        return ["call://must-not-leak"]


def test_calls_profile_never_enters_legacy_user_subscriptions() -> None:
    plugin = CallsPlugin(Source([], ""))
    access = SubscriptionPlugins(plugin)
    links = generate_links(User(email="u@example.com", uuid="u"), _state(), plugins=access)
    assert links == []
    assert access.client_link_called is False
