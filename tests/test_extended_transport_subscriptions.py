from __future__ import annotations

import json

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.registry import enabled, get
from hydra.services.subscriptions.generator import (
    SubscriptionPluginService,
    generate_hydrabox_subscription,
    generate_links,
    generate_singbox_config,
)


PLUGINS = SubscriptionPluginService(
    enabled_plugins=enabled,
    get_plugin=get,
)


def _state() -> tuple[AppState, User]:
    user = User("subscriber@example.com", "subscriber-uuid")
    state = AppState(users=[user])
    state.network.server_ip = "203.0.113.10"
    state.protocols["hysteria2"] = PluginState(enabled=True, installed=True, config={
        "domain": "hy.example.com",
        "cert_file": "/cert.pem",
        "key_file": "/key.pem",
        "port": 8443,
        "obfs_password": "obfs-secret",
    })
    state.protocols["snell"] = PluginState(enabled=True, installed=True)
    state.protocols["vless"] = PluginState(
        enabled=True,
        installed=True,
        config={
            "domain": "xhttp.example.com",
            "cert_file": "/cert.pem",
            "key_file": "/key.pem",
            "xhttp_mode": "stream-up",
            "xhttp_path": "/xhttp",
        },
    )
    return state, user


def test_share_subscription_contains_both_extended_transports():
    state, user = _state()
    links = generate_links(user, state, plugins=PLUGINS)
    assert any(link.startswith("hysteria2://") for link in links)
    assert any(link.startswith("snell://") for link in links)
    assert any(link.startswith("vless://") for link in links)


def test_singbox_subscription_contains_both_outbounds():
    state, user = _state()
    config = generate_singbox_config(user, state, plugins=PLUGINS)
    outbound_types = {outbound["type"] for outbound in config["outbounds"]}
    assert {"hysteria2", "snell", "vless", "direct"} <= outbound_types
    assert config["route"]["final"].startswith("hysteria2-")


def test_individual_client_payloads_are_json_serializable():
    state, user = _state()
    config = generate_singbox_config(user, state, plugins=PLUGINS)
    assert json.loads(json.dumps(config))["outbounds"] == config["outbounds"]


def test_hydrabox_subscription_contains_remote_safe_extended_transports():
    state, user = _state()
    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=PLUGINS,
    )

    resources = subscription["resources"]
    documents = [resource["document"] for resource in resources]
    assert all(set(document) == {"outbounds"} for document in documents)
    outbounds = [
        item
        for document in documents
        for item in document["outbounds"]
    ]
    assert {item["type"] for item in outbounds} >= {
        "hysteria2",
        "snell",
        "vless",
    }
    assert "direct" not in {item["tag"] for item in outbounds}
    assert {profile["entrypoint"]["tag"] for profile in subscription["profiles"]} == {
        item["tag"] for item in outbounds
    }
