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


def _state(users=None, domain="tt.example.com", transport="tcp",
           naive_enabled=False, naive_domain="naive.example.com",
           naive_network="tcp"):
    s = AppState()
    s.network.domain = naive_domain
    s.protocols["naive"] = PluginState(
        enabled=naive_enabled, config={"network": naive_network},
    )
    s.protocols["trusttunnel"] = PluginState(
        enabled=True, config={"domain": domain, "transport": transport},
    )
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


def test_configure_quic_uses_server_network_udp():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com")], transport="quic")

    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    assert len(frag.inbounds) == 1
    inbound = frag.inbounds[0]
    assert inbound["tag"] == "trusttunnel-quic-in"
    assert inbound["network"] == "udp"
    assert "quic" not in inbound
    assert inbound["listen"] == "127.0.0.1"
    assert inbound["listen_port"] == 20445
    assert inbound["tls"]["alpn"] == ["h3"]


def test_configure_both_creates_tcp_and_quic_inbounds():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com")], transport="both")

    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    assert {item["tag"] for item in frag.inbounds} == {
        "trusttunnel-in", "trusttunnel-quic-in",
    }


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


def test_generate_client_config_quic_has_server_and_quic_flag():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com")], domain="custom.domain", transport="quic")

    parsed = json.loads(p.generate_client_config(state.users[0], state))
    outbound = parsed["outbounds"][0]

    assert outbound["server"] == "custom.domain"
    assert outbound["server_port"] == 443
    assert outbound["quic"] is True
    assert outbound["tls"]["server_name"] == "custom.domain"
    assert outbound["tls"]["alpn"] == ["h3"]


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


def test_tcp_client_link_is_unchanged():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")], domain="custom.domain")
    link = p.client_link(state.users[0], state)

    assert link == (
        "tt://a%40x.com:"
        f"{p._derive_password('uuid-a')}@custom.domain:443"
        "?security=tls&sni=custom.domain&alpn=h2#a%40x.com"
    )


def test_client_links_both_preserve_tt_scheme():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com")], transport="both")

    links = p.client_links(state.users[0], state)

    assert len(links) == 2
    assert all(link.startswith("tt://") for link in links)
    assert any("alpn=h2" in link for link in links)
    assert any("alpn=h3" in link for link in links)


def test_validate_config_rejects_quic_conflict():
    p = TrustTunnelPlugin()
    state = _state(
        [_user("a@x.com")], transport="quic", naive_enabled=True,
        naive_network="quic",
    )

    errors = p.validate_config(state, require_cert=False)

    assert any("UDP/443" in error for error in errors)


def test_connected_clients_does_not_invent_traffic():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com")])
    output = "ESTAB 0 0 127.0.0.1:20445 198.51.100.8:55000\n"
    result = MagicMock(returncode=0, stdout=output)

    with patch("shutil.which", return_value="/usr/bin/ss"), \
         patch("subprocess.run", return_value=result):
        clients = p.connected_clients(state)

    assert len(clients) == 1
    assert clients[0]["rx"] == 0
    assert clients[0]["tx"] == 0
    assert "198.51.100.8" in clients[0]["email"]


def test_on_user_add():
    """Добавляет учетные данные в credentials."""
    p = TrustTunnelPlugin()
    state = _state()
    user = _user("a@x.com", uuid="uuid-a")
    
    p.on_user_add(user, state)
    assert "trusttunnel" in user.credentials
    assert user.credentials["trusttunnel"]["username"] == "a@x.com"
    assert len(user.credentials["trusttunnel"]["password"]) > 0


def test_legacy_state_without_transport_defaults_to_tcp():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com")])
    state.protocols["trusttunnel"].config.pop("transport")

    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    assert [inbound["tag"] for inbound in frag.inbounds] == ["trusttunnel-in"]


def test_set_transport_rolls_back_after_apply_failure():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com")], transport="tcp")

    with patch.object(p, "_resolve_certs", return_value=("cert.pem", "key.pem")), \
         patch("hydra.core.orchestrator.apply_config", side_effect=[False, True]) as apply, \
         patch("hydra.core.state.save_state"):
        changed = p.set_transport(state, "quic")

    assert changed is False
    assert state.protocols["trusttunnel"].config["transport"] == "tcp"
    assert apply.call_count == 2


def test_certbot_restores_services_and_firewall_on_exception():
    p = TrustTunnelPlugin()
    calls = []
    rule_added = False

    def fake_run(cmd, **kwargs):
        nonlocal rule_added
        calls.append(cmd)
        result = MagicMock(returncode=0, stdout="")
        if cmd[:3] == ["systemctl", "is-active", "caddy-l4"]:
            result.stdout = "active\n"
        if cmd and cmd[0] == "certbot":
            raise OSError("certbot crashed")
        if cmd and cmd[0] == "iptables" and "-C" in cmd:
            result.returncode = 0 if rule_added else 1
        if cmd and cmd[0] == "iptables" and "-I" in cmd:
            rule_added = True
        if cmd and cmd[0] == "iptables" and "-D" in cmd:
            rule_added = False
        return result

    with patch("pathlib.Path.exists", return_value=False), \
         patch("shutil.which", return_value="/usr/bin/certbot"), \
         patch("hydra.utils.firewall.is_ufw_active", return_value=False), \
         patch("subprocess.run", side_effect=fake_run):
        assert p._obtain_cert_certbot("tt.example.com") is False

    assert ["systemctl", "start", "caddy-l4"] in calls
    assert any(
        cmd[:5] == ["iptables", "-t", "filter", "-D", "INPUT"]
        and "temp-certbot" in cmd
        for cmd in calls
    )




