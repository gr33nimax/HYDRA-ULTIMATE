from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import pytest

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.base import PluginCategory
from hydra.plugins.vless_xhttp.plugin import (
    DEFAULT_MODE,
    DEFAULT_PATH,
    INTERNAL_PORT,
    ROUTE_CONFIG_KEY,
    VlessXhttpPlugin,
)
from hydra.services.protocol_setup import normalize_protocol_config


def _state(*users: User) -> AppState:
    state = AppState()
    state.network.server_ip = "203.0.113.10"
    state.protocols["vless"] = PluginState(
        enabled=True,
        installed=True,
        config={
            "domain": "xhttp.example.com",
            "cert_file": "/cert.pem",
            "key_file": "/key.pem",
            "xhttp_mode": DEFAULT_MODE,
            "xhttp_path": DEFAULT_PATH,
            ROUTE_CONFIG_KEY: VlessXhttpPlugin.route_config(),
        },
    )
    state.users = list(users)
    return state


def test_meta_declares_tls_route_and_extended_core_requirement():
    plugin = VlessXhttpPlugin()
    defaults = dict(plugin.meta.config_defaults)

    assert plugin.meta.category == PluginCategory.TRANSPORT
    assert plugin.meta.tls_domain_source == "protocol"
    assert defaults["xhttp_mode"] == "stream-up"
    assert defaults["xhttp_path"] == "/xhttp"
    assert defaults[ROUTE_CONFIG_KEY]["internal_port"] == INTERNAL_PORT
    assert "sing-box" in plugin.meta.required_commands


def test_nested_route_defaults_are_copied_per_protocol_state():
    defaults = VlessXhttpPlugin.meta.config_defaults
    first = normalize_protocol_config({}, defaults)
    second = normalize_protocol_config({}, defaults)

    first[ROUTE_CONFIG_KEY]["internal_port"] = 65500

    assert second[ROUTE_CONFIG_KEY]["internal_port"] == INTERNAL_PORT


def test_configure_builds_vless_xhttp_inbound_for_active_users():
    plugin = VlessXhttpPlugin()
    state = _state(
        User("active@example.com", "uuid-active"),
        User("blocked@example.com", "uuid-blocked", blocked=True),
    )

    inbound = plugin.configure(state).inbounds[0]

    assert inbound["type"] == "vless"
    assert inbound["tag"] == "vless-xhttp-in"
    assert inbound["listen"] == "127.0.0.1"
    assert inbound["listen_port"] == INTERNAL_PORT
    assert inbound["users"] == [
        {"name": "active@example.com", "uuid": "uuid-active"},
    ]
    assert inbound["tls"] == {
        "enabled": True,
        "server_name": "xhttp.example.com",
        "alpn": ["h2"],
        "certificate_path": "/cert.pem",
        "key_path": "/key.pem",
    }
    assert inbound["transport"]["type"] == "xhttp"
    assert inbound["transport"]["mode"] == "stream-up"
    assert inbound["transport"]["path"] == "/xhttp"


def test_client_config_and_share_link_match_server_contract():
    plugin = VlessXhttpPlugin()
    user = User("active@example.com", "uuid-active")
    state = _state(user)

    config = json.loads(plugin.generate_client_config(user, state))
    outbound = next(
        item for item in config["outbounds"] if item["type"] == "vless"
    )
    link = plugin.client_link(user, state)
    parsed = urlsplit(link)
    query = parse_qs(parsed.query)

    assert outbound["server"] == "xhttp.example.com"
    assert outbound["server_port"] == 443
    assert outbound["uuid"] == user.uuid
    assert outbound["tls"]["server_name"] == "xhttp.example.com"
    assert outbound["transport"]["type"] == "xhttp"
    assert outbound["transport"]["host"] == "xhttp.example.com"
    assert outbound["transport"]["path"] == "/xhttp"
    assert parsed.scheme == "vless"
    assert parsed.username == user.uuid
    assert query["type"] == ["xhttp"]
    assert query["security"] == ["tls"]
    assert query["sni"] == ["xhttp.example.com"]
    assert query["path"] == ["/xhttp"]
    assert query["mode"] == ["stream-up"]


@pytest.mark.parametrize(
    "path",
    ["", "/", "xhttp", "/bad path", "/x#bad", "/x*", "/a/../b"],
)
def test_invalid_path_does_not_mutate_state(path: str):
    plugin = VlessXhttpPlugin()
    state = _state(User("active@example.com", "uuid-active"))
    before = dict(state.protocols["vless"].config)

    with pytest.raises(ValueError, match="XHTTP path"):
        plugin.set_path(state, path)

    assert state.protocols["vless"].config == before


def test_invalid_mode_does_not_mutate_state():
    plugin = VlessXhttpPlugin()
    state = _state(User("active@example.com", "uuid-active"))
    before = dict(state.protocols["vless"].config)

    with pytest.raises(ValueError, match="XHTTP mode"):
        plugin.set_mode(state, "invalid")

    assert state.protocols["vless"].config == before


@pytest.mark.parametrize("domain", ["localhost", "bad/path.example", "-bad.example"])
def test_invalid_domain_does_not_mutate_state(domain: str):
    plugin = VlessXhttpPlugin()
    state = _state(User("active@example.com", "uuid-active"))
    before = dict(state.protocols["vless"].config)

    with pytest.raises(ValueError, match="domain is invalid"):
        plugin.set_domain(state, domain)

    assert state.protocols["vless"].config == before


def test_enable_requires_prepared_tls_and_opens_public_http_ports():
    plugin = VlessXhttpPlugin()
    state = _state()

    with patch("hydra.utils.firewall.open_tcp") as open_tcp:
        plugin.on_enable(state)

    assert open_tcp.call_args_list == [
        ((80, "vless-xhttp-http"),),
        ((443, "vless-xhttp"),),
    ]


def test_enable_rejects_missing_tls_without_firewall_mutation():
    plugin = VlessXhttpPlugin()
    state = _state()
    state.protocols["vless"].config.pop("cert_file")

    with patch("hydra.utils.firewall.open_tcp") as open_tcp:
        with pytest.raises(ValueError, match="TLS material"):
            plugin.on_enable(state)

    open_tcp.assert_not_called()


def test_health_rejects_missing_caddy_route_metadata():
    plugin = VlessXhttpPlugin()
    state = _state(User("active@example.com", "uuid-active"))
    state.protocols["vless"].config.pop(ROUTE_CONFIG_KEY)

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.has_configured_inbound", return_value=True), \
         patch("hydra.core.sni_router.is_active", return_value=True), \
         patch("hydra.core.sni_router.audit_routes") as audit, \
         patch("hydra.core.sni_router.probe_tls_route") as probe:
        result = plugin.healthcheck_for_state(state)

    assert result.healthy is False
    assert result.detail == "VLESS XHTTP Caddy route metadata is missing"
    audit.assert_not_called()
    probe.assert_not_called()


def test_health_rejects_route_missing_from_active_caddy_config():
    plugin = VlessXhttpPlugin()
    state = _state(User("active@example.com", "uuid-active"))
    report = SimpleNamespace(
        ok=False,
        missing=("xhttp.example.com",),
        certificate_errors=(),
        errors=(),
        actual=(),
    )

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.has_configured_inbound", return_value=True), \
         patch("hydra.core.sni_router.is_active", return_value=True), \
         patch("hydra.core.sni_router.audit_routes", return_value=report), \
         patch("hydra.core.sni_router.probe_tls_route") as probe:
        result = plugin.healthcheck_for_state(state)

    assert result.healthy is False
    assert result.detail == (
        "VLESS XHTTP Caddy route is not active for xhttp.example.com"
    )
    probe.assert_not_called()


def test_health_rejects_failed_tls_route_probe():
    plugin = VlessXhttpPlugin()
    state = _state(User("active@example.com", "uuid-active"))
    report = SimpleNamespace(
        ok=True,
        missing=(),
        certificate_errors=(),
        errors=(),
        actual=("xhttp.example.com",),
    )

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.has_configured_inbound", return_value=True), \
         patch("hydra.core.sni_router.is_active", return_value=True), \
         patch("hydra.core.sni_router.audit_routes", return_value=report), \
         patch(
             "hydra.core.sni_router.probe_tls_route",
             return_value=(False, "no certificate available"),
         ):
        result = plugin.healthcheck_for_state(state)

    assert result.healthy is False
    assert result.detail == "VLESS XHTTP TLS route failed: no certificate available"


def test_health_accepts_applied_route_and_verified_tls():
    plugin = VlessXhttpPlugin()
    state = _state(User("active@example.com", "uuid-active"))
    report = SimpleNamespace(
        ok=True,
        missing=(),
        certificate_errors=(),
        errors=(),
        actual=("xhttp.example.com",),
    )

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.has_configured_inbound", return_value=True), \
         patch("hydra.core.sni_router.is_active", return_value=True), \
         patch("hydra.core.sni_router.audit_routes", return_value=report), \
         patch(
             "hydra.core.sni_router.probe_tls_route",
             return_value=(True, ""),
         ):
        result = plugin.healthcheck_for_state(state)

    assert result.healthy is True
    assert result.detail == ""
    assert result.checks["caddy_route"] is True
    assert result.checks["tls_handshake"] is True
