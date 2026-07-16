"""tests/test_trusttunnel_plugin.py — Тесты для TrustTunnel plugin."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _state(users=None, domain="tt.example.com", naive_enabled=False, naive_domain="naive.example.com"):
    s = AppState()
    s.network.domain = naive_domain
    s.protocols["naive"] = PluginState(enabled=naive_enabled)
    s.protocols["trusttunnel"] = PluginState(enabled=True, config={"domain": domain})
    if users:
        s.users = users
    return s


def _user(email, uuid="u1", blocked=False):
    return User(email=email, uuid=uuid, blocked=blocked)


def test_meta():
    p = TrustTunnelPlugin()
    assert p.meta.name == "trusttunnel"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is True


def test_configure_returns_inbound():
    """configure() генерит ConfigFragment с trusttunnel inbound."""
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")])
    
    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    assert isinstance(frag, ConfigFragment)
    assert len(frag.inbounds) == 1
    assert frag.inbounds[0]["type"] == "trusttunnel"
    assert frag.inbounds[0]["tag"] == "trusttunnel-in"
    assert frag.inbounds[0]["listen"] == "127.0.0.1"
    assert frag.inbounds[0]["listen_port"] == 20445


def test_configure_has_tls():
    """configure() содержит TLS настройки в inbound."""
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")], domain="custom.domain")
    
    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    assert frag.inbounds[0]["tls"]["enabled"] is True
    assert frag.inbounds[0]["tls"]["server_name"] == "custom.domain"


def test_configure_users_in_inbound():
    """Все незаблокированные юзеры попадают в inbound.users."""
    p = TrustTunnelPlugin()
    state = _state([
        _user("a@x.com", uuid="u1"),
        _user("b@x.com", uuid="u2"),
    ])
    
    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    names = [u["name"] for u in frag.inbounds[0]["users"]]
    assert len(names) == 2
    assert "a@x.com" in names
    assert "b@x.com" in names


def test_configure_skips_blocked():
    """Blocked юзеры не попадают в inbound."""
    p = TrustTunnelPlugin()
    state = _state([
        _user("a@x.com", uuid="u1"),
        _user("b@x.com", uuid="u2", blocked=True),
    ])
    
    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    names = [u["name"] for u in frag.inbounds[0]["users"]]
    assert len(names) == 1
    assert "a@x.com" in names


def test_generate_client_config():
    """Генерирует корректный клиентский конфиг."""
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")], domain="custom.domain")
    user = state.users[0]
    
    config_str = p.generate_client_config(user, state)
    assert config_str != ""
    
    parsed = json.loads(config_str)
    assert parsed["log"]["level"] == "info"
    
    outbound = parsed["outbounds"][0]
    assert outbound["type"] == "trusttunnel"
    assert outbound["username"] == "a@x.com"
    assert outbound["tls"]["enabled"] is True
    assert outbound["tls"]["server_name"] == "custom.domain"


def test_client_link():
    """Генерирует правильную ссылку tt://."""
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")], domain="custom.domain")
    user = state.users[0]
    
    link = p.client_link(user, state)
    assert link.startswith("tt://")
    assert "custom.domain" in link
    assert "a%40x.com" in link  # URL-encoded
    assert "security=tls" in link
    assert "alpn" in link


def test_on_user_add():
    """Добавляет учетные данные в credentials."""
    p = TrustTunnelPlugin()
    state = _state()
    user = _user("a@x.com", uuid="uuid-a")
    
    p.on_user_add(user, state)
    assert "trusttunnel" in user.credentials
    assert user.credentials["trusttunnel"]["username"] == "a@x.com"
    assert len(user.credentials["trusttunnel"]["password"]) > 0


def test_presets_logic():
    from hydra.plugins.trusttunnel.presets import list_presets, get_preset, validate_preset
    
    presets = list_presets()
    assert len(presets) == 3
    assert any(pr["name"] == "stealth" for pr in presets)
    
    default_pr = get_preset("default")
    assert default_pr.name == "default"
    assert default_pr.transport == "tcp"
    
    invalid_pr = get_preset("nonexistent")
    assert invalid_pr.name == "default"
    
    assert validate_preset("stealth") is True
    assert validate_preset("nonexistent") is False



def test_generate_client_config_with_multiplex():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")])
    state.protocols["trusttunnel"].config["preset"] = "stealth"
    user = state.users[0]
    
    config_str = p.generate_client_config(user, state)
    parsed = json.loads(config_str)
    
    outbound = parsed["outbounds"][0]
    assert outbound["tls"]["utls"]["fingerprint"] == "chrome"
    assert outbound["multiplex"]["enabled"] is True
    assert outbound["multiplex"]["protocol"] == "h2mux"
    assert outbound["multiplex"]["padding"] is True

