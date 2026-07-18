from __future__ import annotations

import json

from hydra.core.state import AppState, PluginState, User
from hydra.services.subscriptions.generator import generate_links, generate_singbox_config


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
    return state, user


def test_share_subscription_contains_both_extended_transports():
    state, user = _state()
    links = generate_links(user, state)
    assert any(link.startswith("hysteria2://") for link in links)
    assert any(link.startswith("snell://") for link in links)


def test_singbox_subscription_contains_both_outbounds():
    state, user = _state()
    config = generate_singbox_config(user, state)
    outbound_types = {outbound["type"] for outbound in config["outbounds"]}
    assert {"hysteria2", "snell", "direct"} <= outbound_types
    assert config["route"]["final"].startswith("hysteria2-")


def test_individual_client_payloads_are_json_serializable():
    state, user = _state()
    config = generate_singbox_config(user, state)
    assert json.loads(json.dumps(config))["outbounds"] == config["outbounds"]
