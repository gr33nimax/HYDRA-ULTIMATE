"""Revoked transports must not be reissued in subscriptions or manual links."""

import json

from hydra.contracts import ConfigFragment
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus
from hydra.services.subscriptions.access import SubscriptionPluginService
from hydra.services.subscriptions.client_configs import (
    generate_client_config,
    generate_singbox_config,
)
from hydra.services.subscriptions.links import generate_links


class _Transport(BasePlugin):
    meta = PluginMeta(name="mock", description="Mock")

    def install(self):
        return True

    def uninstall(self):
        return True

    def status(self, state=None):
        return PluginStatus(installed=True, enabled=True, running=True)

    def configure(self, state):
        return ConfigFragment()

    def client_link(self, user, state):
        return f"mock://{user.email}@example.test"

    def generate_client_config(self, user, state):
        return json.dumps({"outbounds": [{"type": "direct", "tag": "mock"}]})


def test_disabled_protocol_is_absent_from_every_client_projection():
    user = User(email="alice", uuid="uuid", disabled_protocols=["mock"])
    state = AppState(users=[user], protocols={"mock": PluginState(enabled=True)})
    plugin = _Transport()
    access = SubscriptionPluginService(
        enabled_plugins=lambda state, category: [plugin],
        get_plugin=lambda name: plugin,
    )
    assert generate_links(user, state, plugins=access) == []
    assert generate_singbox_config(user, state, plugins=access)["outbounds"] == [
        {"type": "direct", "tag": "direct"},
    ]
    assert generate_client_config(user, state, "mock", plugins=access) == ""
    assert access.client_link(plugin, user, state) == ""
    assert access.client_links(plugin, user, state) == []
    assert access.client_config(plugin, user, state) == ""
    assert access.singbox_client_config(plugin, user, state) == ""
