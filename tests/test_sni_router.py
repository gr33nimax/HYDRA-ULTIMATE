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
    _INTERNAL_PORTS,
)
from hydra.core.state import AppState, PluginState


def _state(naive_enabled=False, anytls_enabled=False, trusttunnel_enabled=False, naive_domain="naive.com", anytls_domain="anytls.com", trusttunnel_domain="trusttunnel.com"):
    s = AppState()
    s.network.domain = naive_domain
    s.protocols["naive"] = PluginState(enabled=naive_enabled)
    s.protocols["anytls"] = PluginState(enabled=anytls_enabled, config={"domain": anytls_domain})
    s.protocols["trusttunnel"] = PluginState(enabled=trusttunnel_enabled, config={"domain": trusttunnel_domain})
    return s


def test_needs_mux_single_plugin():
    """needs_mux() -> False when 0 or 1 plugin is active."""
    s = _state(naive_enabled=False, anytls_enabled=False)
    assert needs_mux(s) is False

    s = _state(naive_enabled=True, anytls_enabled=False)
    assert needs_mux(s) is False

    s = _state(naive_enabled=False, anytls_enabled=True)
    assert needs_mux(s) is True


def test_needs_mux_two_plugins():
    """needs_mux() -> True when 2+ plugins are active."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    assert needs_mux(s) is True


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
    assert "layer4" in cfg["apps"]
    assert "tls_mux" in cfg["apps"]["layer4"]["servers"]
    
    routes = cfg["apps"]["layer4"]["servers"]["tls_mux"]["routes"]
    assert len(routes) >= 2
    
    # Check naive route
    naive_route = next(r for r in routes if r.get("match") and r["match"][0].get("tls", {}).get("sni") == ["naive.com"])
    assert naive_route["handle"][0]["upstreams"][0]["dial"] == ["127.0.0.1:10443"]

    # Check anytls route
    anytls_route = next(r for r in routes if r.get("match") and r["match"][0].get("tls", {}).get("sni") == ["anytls.com"])
    # AnyTLS has a subroute to filter out non-HTTP
    assert anytls_route["handle"][1]["handler"] == "subroute"


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


def test_rebuild_starts_caddy():
    """rebuild() generates config and restarts/reloads caddy-l4."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    
    mock_cfg = MagicMock()
    mock_cfg_dir = MagicMock()
    with patch("hydra.core.sni_router.is_installed", return_value=True), \
         patch("hydra.core.sni_router.CADDY_CFG", mock_cfg), \
         patch("hydra.core.sni_router.CADDY_CFG_DIR", mock_cfg_dir), \
         patch("subprocess.run") as mock_run:
        
        mock_run.return_value = MagicMock(returncode=0)
        
        assert rebuild(s) is True
        
        # Check config write
        mock_cfg.write_text.assert_called_once()
        # Check caddy-l4 was restarted/reloaded
        mock_run.assert_any_call(["systemctl", "reload-or-restart", "caddy-l4"], capture_output=True)


def test_rebuild_stops_when_single():
    """rebuild() stops caddy-l4 when 0-1 backends are active."""
    s = _state(naive_enabled=True, anytls_enabled=False)
    
    with patch("hydra.core.sni_router.is_installed", return_value=True), \
         patch("subprocess.run") as mock_run:
        
        mock_run.return_value = MagicMock(returncode=0)
        assert rebuild(s) is True
        
        # Check caddy-l4 was stopped
        mock_run.assert_any_call(["systemctl", "stop", "caddy-l4"], capture_output=True)


def test_internal_ports_unique():
    """All internal ports are unique."""
    ports = list(_INTERNAL_PORTS.values())
    assert len(ports) == len(set(ports))


def test_needs_mux_with_sub_domain():
    """needs_mux() -> True когда настроен sub_domain, независимо от других плагинов."""
    s = _state(naive_enabled=False, anytls_enabled=False)
    s.network.sub_domain = "sub.domain.com"
    assert needs_mux(s) is True


def test_rebuild_runs_haproxy_with_only_sub_domain():
    """rebuild() запускает haproxy, если активен только домен подписок."""
    s = _state(naive_enabled=False, anytls_enabled=False)
    s.network.sub_domain = "sub.domain.com"
    
    mock_cfg = MagicMock()
    mock_cfg_dir = MagicMock()
    with patch("hydra.core.sni_router.is_installed", return_value=True), \
         patch("hydra.core.sni_router.HAPROXY_CFG", mock_cfg), \
         patch("hydra.core.sni_router.HAPROXY_CFG_DIR", mock_cfg_dir), \
         patch("subprocess.run") as mock_run:
        
        mock_run.return_value = MagicMock(returncode=0)
        assert rebuild(s) is True
        
        # Проверяем, что конфиг был записан и haproxy запущен/перезапущен
        mock_cfg.write_text.assert_called_once()
        mock_run.assert_any_call(["systemctl", "restart", "haproxy"], capture_output=True)

