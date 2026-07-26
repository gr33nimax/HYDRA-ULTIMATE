from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from hydra.core.sni_router_audit import audit_routes
from hydra.core.sni_router import (
    _collect_backends,
    _generate_config,
    needs_mux,
)
from hydra.core.sni_router_reconcile import _ensure_decoy_sites
from hydra.core.sni_router_reconcile import _apply_loopback_firewall
from hydra.core.sni_router_runtime import configured_loopback_ports
from hydra.core.state import AppState, PluginState
from hydra.plugins.vless_xhttp.plugin import (
    DECOY_DIR,
    DECOY_HTTP_PORT,
    DEFAULT_PATH,
    INTERNAL_PORT,
    ROUTE_CONFIG_KEY,
    VlessXhttpPlugin,
)


def _state() -> AppState:
    state = AppState()
    state.protocols["vless"] = PluginState(
        enabled=True,
        installed=True,
        config={
            "domain": "xhttp.example.com",
            "cert_file": "/cert.pem",
            "key_file": "/key.pem",
            "xhttp_path": DEFAULT_PATH,
            ROUTE_CONFIG_KEY: VlessXhttpPlugin.route_config(),
        },
    )
    return state


def test_plugin_owned_route_forces_mux_and_is_projected():
    state = _state()

    assert needs_mux(state) is True
    assert _collect_backends(state) == [
        {
            "name": "vless",
            "domain": "xhttp.example.com",
            "port": INTERNAL_PORT,
            "cert_file": "/cert.pem",
            "key_file": "/key.pem",
            "network_mode": "",
            "route_kind": "http_path_proxy",
            "decoy_port": DECOY_HTTP_PORT,
            "decoy_root": DECOY_DIR,
            "decoy_theme": "media",
            "proxy_path": DEFAULT_PATH,
        },
    ]


def test_caddy_terminates_tls_and_routes_only_xhttp_path_to_singbox():
    state = _state()
    config = _generate_config(_collect_backends(state), state)

    tls_route = config["apps"]["layer4"]["servers"]["tls_mux"]["routes"][0]
    assert tls_route["match"] == [
        {"tls": {"sni": ["xhttp.example.com"]}},
    ]
    assert tls_route["handle"][0] == {"handler": "tls"}
    assert tls_route["handle"][1]["proxy_protocol"] == "v2"
    assert tls_route["handle"][1]["upstreams"][0]["dial"] == [
        f"127.0.0.1:{DECOY_HTTP_PORT}",
    ]

    server = config["apps"]["http"]["servers"]["vless_decoy"]
    assert server["listen"] == [f"127.0.0.1:{DECOY_HTTP_PORT}"]
    xhttp_route = server["routes"][0]
    assert xhttp_route["match"] == [
        {"path": [DEFAULT_PATH, f"{DEFAULT_PATH}/*"]},
    ]
    proxy = xhttp_route["handle"][0]
    assert proxy["handler"] == "reverse_proxy"
    assert proxy["upstreams"] == [{"dial": f"127.0.0.1:{INTERNAL_PORT}"}]
    assert proxy["transport"]["versions"] == ["2"]
    assert proxy["transport"]["tls"] == {
        "server_name": "xhttp.example.com",
    }
    assert server["routes"][1]["handle"] == [
        {"handler": "file_server", "root": DECOY_DIR},
    ]


def test_dynamic_decoy_site_uses_plugin_owned_directory_and_theme():
    backend = _collect_backends(_state())[0]

    with patch("hydra.core.decoy.ensure_site") as ensure:
        _ensure_decoy_sites([backend])

    ensure.assert_called_once_with(Path(DECOY_DIR), "media")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("internal_port", 443),
        ("decoy_http_port", 70000),
        ("decoy_http_port", 10801),
        ("decoy_root", "/etc"),
        ("decoy_theme", "unknown"),
    ],
)
def test_invalid_plugin_owned_route_is_rejected(field: str, value: object):
    state = _state()
    route = dict(state.protocols["vless"].config[ROUTE_CONFIG_KEY])
    route[field] = value
    state.protocols["vless"].config[ROUTE_CONFIG_KEY] = route

    with pytest.raises(ValueError, match="vless"):
        _collect_backends(state)


def test_vless_domain_must_not_be_shared_with_another_tls_transport():
    state = _state()
    state.protocols["anytls"] = PluginState(
        enabled=True,
        config={"domain": "xhttp.example.com"},
    )

    with pytest.raises(ValueError, match="assigned to both"):
        _collect_backends(state)


def test_runtime_cleanup_discovers_dynamic_ports_from_saved_caddy_config(
    tmp_path,
):
    path = tmp_path / "config.json"
    path.write_text(
        """
        {
          "apps": {
            "http": {"servers": {"vless_decoy": {
              "listen": ["127.0.0.1:10804"],
              "routes": [{"handle": [{"upstreams": [
                {"dial": "127.0.0.1:20448"}
              ]}]}]
            }}}
          }
        }
        """,
        encoding="utf-8",
    )

    assert configured_loopback_ports(path) == {10804, 20448}


def test_audit_requires_certificate_pair_for_dynamic_tls_route(tmp_path):
    state = _state()
    config_path = tmp_path / "caddy.json"
    config_path.write_text(
        json.dumps(_generate_config(_collect_backends(state), state)),
        encoding="utf-8",
    )

    report = audit_routes(
        state,
        config_path=config_path,
        service_name="caddy-l4",
        collect_backends=_collect_backends,
        needs_mux=needs_mux,
        is_active=lambda: True,
    )

    assert report.ok is False
    assert any(
        "xhttp.example.com" in error
        for error in report.certificate_errors
    )


def test_dynamic_loopback_firewall_rules_are_comment_scoped():
    backend = _collect_backends(_state())[0]
    calls: list[list[str]] = []
    host = SimpleNamespace(run=lambda command, **_options: calls.append(command))

    _apply_loopback_firewall(
        [backend],
        None,
        SimpleNamespace(decoy_ports={}),
        host,
    )

    inserts = [
        command
        for command in calls
        if command[:3] == ["iptables", "-I", "INPUT"]
    ]
    assert len(inserts) == 2
    assert all(
        "hydra-caddy-dynamic-loopback" in command
        for command in inserts
    )
