"""tests/test_sni_router.py — Tests for SNI multiplexer (Caddy L4)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.core.sni_router import (
    needs_mux,
    get_effective_port,
    _generate_config,
    rebuild,
    stop,
    get_quic_owner,
    get_quic_owners,
    audit_routes,
    _INTERNAL_PORTS,
    _install_service,
    CADDY_ADMIN_ADDRESS,
)
from hydra.core.state import AppState, PluginState


def _state(naive_enabled=False, anytls_enabled=False, trusttunnel_enabled=False,
           hysteria2_enabled=False,
           naive_domain="naive.com", anytls_domain="anytls.com",
           trusttunnel_domain="trusttunnel.com", hysteria2_domain="hysteria2.com",
           naive_network="tcp",
           trusttunnel_transport="tcp"):
    s = AppState()
    s.network.domain = naive_domain
    s.protocols["naive"] = PluginState(
        enabled=naive_enabled, config={"network": naive_network},
    )
    s.protocols["anytls"] = PluginState(enabled=anytls_enabled, config={"domain": anytls_domain})
    s.protocols["trusttunnel"] = PluginState(
        enabled=trusttunnel_enabled,
        config={"domain": trusttunnel_domain, "transport": trusttunnel_transport},
    )
    s.protocols["hysteria2"] = PluginState(
        enabled=hysteria2_enabled,
        config={
            "domain": hysteria2_domain,
            "cert_file": "hysteria2-cert.pem",
            "key_file": "hysteria2-key.pem",
        },
    )
    return s


def test_needs_mux_single_plugin():
    """needs_mux() -> False when 0 or 1 plugin is active."""
    s = _state(naive_enabled=False, anytls_enabled=False)
    assert needs_mux(s) is False

    s = _state(naive_enabled=True, anytls_enabled=False)
    assert needs_mux(s) is False

    s = _state(naive_enabled=False, anytls_enabled=True)
    assert needs_mux(s) is True

    s = _state(hysteria2_enabled=True)
    assert needs_mux(s) is True


def test_needs_mux_two_plugins():
    """needs_mux() -> True when 2+ plugins are active."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    assert needs_mux(s) is True


def test_audit_routes_accepts_matching_config_and_certificates(tmp_path):
    state = _state(anytls_enabled=True)
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    state.protocols["anytls"].config.update(cert_file=str(cert), key_file=str(key))
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "apps": {"layer4": {"servers": {"tls_mux": {"routes": [
            {"match": [{"tls": {"sni": ["anytls.com"]}}]}
        ]}}}}}
    ))
    with patch("hydra.core.sni_router.CADDY_CFG", config_path), \
         patch("hydra.core.sni_router.is_active", return_value=True):
        report = audit_routes(state)
    assert report.ok is True
    assert report.missing == ()
    assert report.actual == ("anytls.com",)


def test_audit_routes_reports_stale_and_missing_domains(tmp_path):
    state = _state(anytls_enabled=True)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "apps": {"layer4": {"servers": {"tls_mux": {"routes": [
            {"match": [{"tls": {"sni": ["old.example"]}}]}
        ]}}}}}
    ))
    with patch("hydra.core.sni_router.CADDY_CFG", config_path), \
         patch("hydra.core.sni_router.is_active", return_value=True):
        report = audit_routes(state)
    assert report.ok is False
    assert report.missing == ("anytls.com",)
    assert report.stale == ("old.example",)


def test_get_effective_port_no_mux():
    """If multiplexer is not needed, plugins listen on port 443 directly."""
    s = _state(naive_enabled=True, anytls_enabled=False)
    assert get_effective_port("naive", s) == 443
    assert get_effective_port("anytls", s) == 443


def test_get_effective_port_with_mux():
    """If multiplexer is needed, plugins switch to internal ports."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    assert get_effective_port("naive", s) == 10443
    assert get_effective_port("anytls", s) == 20444


def test_generate_config_two_backends():
    """Caddy L4 config generation for two backends."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    backends = [
        {"name": "naive", "domain": "naive.com", "port": 10443, "cert_file": "cert.pem", "key_file": "key.pem"},
        {"name": "anytls", "domain": "anytls.com", "port": 20444, "cert_file": "cert2.pem", "key_file": "key2.pem"},
    ]
    cfg = _generate_config(backends, s)
    
    assert "apps" in cfg
    assert cfg["admin"] == {"listen": CADDY_ADMIN_ADDRESS}
    assert "layer4" in cfg["apps"]
    assert "tls_mux" in cfg["apps"]["layer4"]["servers"]
    
    routes = cfg["apps"]["layer4"]["servers"]["tls_mux"]["routes"]
    assert len(routes) >= 2
    
    # Check naive route
    naive_route = next(r for r in routes if r.get("match") and r["match"][0].get("tls", {}).get("sni") == ["naive.com"])
    assert naive_route["handle"][0]["upstreams"][0]["dial"] == ["127.0.0.1:10443"]
    assert "local_address" not in naive_route["handle"][0]["upstreams"][0]
    assert naive_route["handle"][0]["proxy_protocol"] == "v2"

    # Check anytls route
    anytls_route = next(r for r in routes if r.get("match") and r["match"][0].get("tls", {}).get("sni") == ["anytls.com"])
    # AnyTLS has a subroute to filter out non-HTTP
    assert anytls_route["handle"][1]["handler"] == "subroute"
    anytls_proxy = anytls_route["handle"][1]["routes"][0]["handle"][0]
    assert "local_address" not in anytls_proxy["upstreams"][0]
    assert "proxy_protocol" not in anytls_proxy

    # Only the browser/decoy branch carries the original peer to the local
    # HTTP access logger. Protocol backends must not receive a PROXY preamble.
    anytls_decoy_proxy = anytls_route["handle"][1]["routes"][1]["handle"][0]
    assert anytls_decoy_proxy["proxy_protocol"] == "v2"
    decoy_server = cfg["apps"]["http"]["servers"]["anytls_decoy"]
    assert decoy_server["listener_wrappers"] == [{
        "wrapper": "proxy_protocol",
        "timeout": "1s",
        "allow": ["127.0.0.0/8", "::1/128"],
        "fallback_policy": "require",
    }]


def test_antidpi_bans_are_enforced_only_by_dynamic_firewall():
    backends = [{"name": "naive", "domain": "naive.com", "port": 10443, "cert_file": "", "key_file": ""}]
    cfg = _generate_config(backends, _state(naive_enabled=True))
    routes = cfg["apps"]["layer4"]["servers"]["tls_mux"]["routes"]
    assert all("remote_ip" not in matcher for route in routes for matcher in route.get("match", []))


def test_caddy_service_uses_transactional_cli_reload(tmp_path):
    service = tmp_path / "caddy-l4.service"
    binary = tmp_path / "caddy-l4"
    config = tmp_path / "config.json"
    result = MagicMock(returncode=0)
    with patch("hydra.core.sni_router.SERVICE_FILE", service), \
         patch("hydra.core.sni_router.CADDY_BIN", binary), \
         patch("hydra.core.sni_router.CADDY_CFG", config), \
         patch("hydra.core.sni_router.HOST.run", return_value=result):
        assert _install_service() is True
    unit = service.read_text(encoding="utf-8")
    assert (
        f"ExecReload={binary} reload --config {config} "
        f"--address {CADDY_ADMIN_ADDRESS} --force"
    ) in unit
    assert "kill -USR1" not in unit


def test_config_has_sni_rules():
    """Config has correct SNI routing rules."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    backends = [
        {"name": "naive", "domain": "naive.com", "port": 10443, "cert_file": "cert.pem", "key_file": "key.pem"},
        {"name": "anytls", "domain": "anytls.com", "port": 20444, "cert_file": "cert2.pem", "key_file": "key2.pem"},
    ]
    cfg = _generate_config(backends, s)
    routes = cfg["apps"]["layer4"]["servers"]["tls_mux"]["routes"]
    
    snis = [r["match"][0]["tls"]["sni"][0] for r in routes if r.get("match")]
    assert "naive.com" in snis
    assert "anytls.com" in snis


def test_hysteria2_has_browser_https_decoy_route():
    s = _state(hysteria2_enabled=True)
    backends = [
        {
            "name": "hysteria2", "domain": "hysteria2.com", "port": 20447,
            "cert_file": "hysteria2-cert.pem", "key_file": "hysteria2-key.pem",
            "network_mode": "",
        },
    ]

    cfg = _generate_config(backends, s)

    routes = cfg["apps"]["layer4"]["servers"]["tls_mux"]["routes"]
    route = next(r for r in routes if r.get("match"))
    assert route["match"][0]["tls"]["sni"] == ["hysteria2.com"]
    assert route["handle"][0] == {"handler": "tls"}
    assert route["handle"][1]["upstreams"][0]["dial"] == ["127.0.0.1:10803"]
    assert route["handle"][1]["proxy_protocol"] == "v2"

    tls_files = cfg["apps"]["tls"]["certificates"]["load_files"]
    assert tls_files == [{
        "certificate": "hysteria2-cert.pem", "key": "hysteria2-key.pem",
    }]
    decoy = cfg["apps"]["http"]["servers"]["hysteria2_decoy"]
    assert decoy["listen"] == ["127.0.0.1:10803"]
    assert decoy["listener_wrappers"][0]["wrapper"] == "proxy_protocol"
    assert decoy["routes"][0]["handle"][0] == {
        "handler": "file_server", "root": "/var/www/decoy-hysteria2",
    }

    redirect = cfg["apps"]["http"]["servers"]["https_redirect"]
    assert redirect["listen"] == [":80"]
    response = redirect["routes"][0]["handle"][0]
    assert response == {
        "handler": "static_response",
        "status_code": 308,
        "headers": {
            "Location": ["https://{http.request.host}{http.request.uri}"],
        },
    }


def test_rebuild_starts_caddy():
    """rebuild() generates config and restarts/reloads caddy-l4."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    
    mock_cfg = MagicMock()
    mock_cfg_dir = MagicMock()
    with patch("hydra.core.sni_router.is_installed", return_value=True), \
        patch("hydra.core.sni_router.CADDY_CFG", mock_cfg), \
        patch("hydra.core.sni_router.CADDY_CFG_DIR", mock_cfg_dir), \
        patch("hydra.core.sni_router.is_active", return_value=True), \
        patch("hydra.core.sni_router._install_source_service"), \
        patch("hydra.core.sni_router._install_service", return_value=True), \
        patch("hydra.core.source_transparency.apply"), \
        patch("hydra.core.sni_router.HOST.run") as mock_run:
        
        mock_run.return_value = MagicMock(returncode=0)
        
        assert rebuild(s) is True
        
        # Config is validated through a pending file before atomic replacement.
        mock_cfg.with_suffix.return_value.write_text.assert_called_once()
        mock_cfg.with_suffix.return_value.replace.assert_called_once_with(mock_cfg)
        # Check caddy-l4 was restarted/reloaded
        mock_run.assert_any_call(["systemctl", "reload-or-restart", "caddy-l4"], capture_output=True)


def test_rebuild_restarts_when_admin_endpoint_migration_breaks_reload():
    s = _state(naive_enabled=True, anytls_enabled=True)
    mock_cfg = MagicMock()

    def run(command, **_kwargs):
        code = 1 if command == ["systemctl", "reload-or-restart", "caddy-l4"] else 0
        return MagicMock(returncode=code, stdout="", stderr="")

    with patch("hydra.core.sni_router.is_installed", return_value=True), \
         patch("hydra.core.sni_router.CADDY_CFG", mock_cfg), \
         patch("hydra.core.sni_router.CADDY_CFG_DIR", MagicMock()), \
         patch("hydra.core.sni_router.is_active", return_value=True), \
         patch("hydra.core.sni_router._install_source_service"), \
         patch("hydra.core.sni_router._install_service", return_value=True), \
         patch("hydra.core.source_transparency.apply"), \
         patch("hydra.core.sni_router.HOST.run", side_effect=run) as mock_run:
        assert rebuild(s) is True

    mock_run.assert_any_call(["systemctl", "restart", "caddy-l4"], capture_output=True)


def test_rebuild_stops_when_single():
    """rebuild() stops caddy-l4 when 0-1 backends are active."""
    s = _state(naive_enabled=True, anytls_enabled=False)
    
    with patch("hydra.core.sni_router.is_installed", return_value=True), \
         patch("hydra.core.sni_router.HOST.run") as mock_run:
        
        mock_run.return_value = MagicMock(returncode=0)
        assert rebuild(s) is True
        
        # Check caddy-l4 was stopped
        mock_run.assert_any_call(["systemctl", "stop", "caddy-l4"], capture_output=True)


def test_internal_ports_unique():
    """All internal ports are unique."""
    ports = list(_INTERNAL_PORTS.values())
    assert len(ports) == len(set(ports))


def test_trusttunnel_quic_is_proxied_by_caddy_udp():
    s = _state(trusttunnel_enabled=True, trusttunnel_transport="quic")
    backends = [
        {
            "name": "trusttunnel", "domain": "trusttunnel.com",
            "port": 20445, "cert_file": "cert.pem", "key_file": "key.pem",
            "network_mode": "quic",
        },
    ]

    cfg = _generate_config(backends, s)

    quic_server = cfg["apps"]["layer4"]["servers"]["quic_mux"]
    assert quic_server["listen"] == ["udp/:443"]
    upstream = quic_server["routes"][0]["handle"][0]["upstreams"][0]
    assert upstream["dial"] == ["udp/127.0.0.1:20445"]


def test_naive_quic_remains_caddy_udp_owner():
    s = _state(
        naive_enabled=True, anytls_enabled=True, naive_network="quic",
    )
    backends = [
        {
            "name": "naive", "domain": "naive.com", "port": 10443,
            "cert_file": "", "key_file": "", "network_mode": "quic",
        },
        {
            "name": "anytls", "domain": "anytls.com", "port": 20444,
            "cert_file": "cert.pem", "key_file": "key.pem",
            "network_mode": "",
        },
    ]

    cfg = _generate_config(backends, s)

    upstream = cfg["apps"]["layer4"]["servers"]["quic_mux"]["routes"][0]["handle"][0]["upstreams"][0]
    assert upstream["dial"] == ["udp/127.0.0.1:10443"]


def test_quic_owner_rejects_naive_and_trusttunnel_conflict():
    s = _state(
        naive_enabled=True, trusttunnel_enabled=True,
        naive_network="quic", trusttunnel_transport="both",
    )

    assert get_quic_owners(s) == ["naive", "trusttunnel"]
    try:
        get_quic_owner(s)
    except ValueError as exc:
        assert "UDP/443" in str(exc)
    else:
        raise AssertionError("QUIC owner conflict was not rejected")


def test_needs_mux_with_sub_domain():
    """needs_mux() -> True когда настроен sub_domain, независимо от других плагинов."""
    s = _state(naive_enabled=False, anytls_enabled=False)
    s.network.sub_domain = "sub.domain.com"
    assert needs_mux(s) is True


def test_rebuild_runs_caddy_l4_with_only_sub_domain():
    """rebuild() запускает caddy-l4, если активен только домен подписок."""
    s = _state(naive_enabled=False, anytls_enabled=False)
    s.network.sub_domain = "sub.domain.com"
    
    mock_cfg = MagicMock()
    mock_cfg_dir = MagicMock()
    with patch("hydra.core.sni_router.is_installed", return_value=True), \
        patch("hydra.core.sni_router.CADDY_CFG", mock_cfg), \
        patch("hydra.core.sni_router.CADDY_CFG_DIR", mock_cfg_dir), \
        patch("hydra.core.sni_router.is_active", return_value=True), \
        patch("hydra.core.sni_router._remove_source_service"), \
        patch("hydra.core.sni_router._install_service", return_value=True), \
        patch("hydra.core.source_transparency.clear"), \
        patch("hydra.core.sni_router.HOST.run") as mock_run:
        
        mock_run.return_value = MagicMock(returncode=0)
        assert rebuild(s) is True
        
        # Проверяем атомарную запись и запуск/перезапуск caddy-l4
        mock_cfg.with_suffix.return_value.write_text.assert_called_once()
        mock_cfg.with_suffix.return_value.replace.assert_called_once_with(mock_cfg)
        mock_run.assert_any_call(["systemctl", "reload-or-restart", "caddy-l4"], capture_output=True)
