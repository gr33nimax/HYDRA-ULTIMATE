from __future__ import annotations

from dataclasses import dataclass

import pytest

from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.base import PluginCategory
from hydra.plugins.calls import CallsPlugin
from hydra.services.subscriptions.links import generate_links


@dataclass
class Source:
    cookies: list[dict[str, str]]
    link: str
    supported: bool = True
    running: bool = True

    def load_vk_cookies(self) -> list[dict[str, str]]:
        return self.cookies

    def load_native_join_link(self) -> str:
        return self.link

    def feature_supported(self) -> bool:
        return self.supported

    def singbox_running(self) -> bool:
        return self.running


def _state(*, enabled: bool = True) -> AppState:
    return AppState(
        protocols={
            "calls": PluginState(
                installed=True,
                enabled=enabled,
                config={"read_buffer": 32768},
            ),
        },
    )


def test_calls_plugin_contract_and_native_fragment() -> None:
    source = Source(
        cookies=[{"name": "remixsid", "value": "secret"}],
        link="https://vk.com/call/join/room-token",
    )
    plugin = CallsPlugin(source)

    assert plugin.meta.name == "calls"
    assert plugin.meta.category is PluginCategory.TRANSPORT
    assert plugin.meta.capabilities.central_apply is True
    assert plugin.meta.capabilities.subscription_enabled is False
    assert plugin.meta.capabilities.hydra_v2_subscription_enabled is True
    assert plugin.meta.capabilities.connection_source == "none"
    fragment = plugin.configure(_state())
    assert fragment.inbounds == [
        {
            "type": "call",
            "tag": "calls-vk-in",
            "platform": "vk",
            "read_buffer": 32768,
            "cookies": source.cookies,
            "join_link": source.link,
        },
    ]
    assert fragment.outbounds == []


def test_calls_plugin_disabled_is_empty_and_enabled_requires_secrets() -> None:
    plugin = CallsPlugin(Source([], ""))
    assert plugin.configure(_state(enabled=False)).inbounds == []
    with pytest.raises(ValueError, match="cookies"):
        plugin.configure(_state())


def test_calls_plugin_rejects_invalid_read_buffer() -> None:
    state = _state()
    state.protocols["calls"].config["read_buffer"] = 1
    source = Source(
        [{"name": "remixsid", "value": "secret"}],
        "https://vk.com/call/join/room-token",
    )
    with pytest.raises(ValueError, match="read_buffer"):
        CallsPlugin(source).configure(state)


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
