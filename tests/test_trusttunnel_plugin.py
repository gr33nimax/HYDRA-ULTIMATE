"""tests/test_trusttunnel_plugin.py — Тесты для TrustTunnel plugin."""
from __future__ import annotations

import json
import base64
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _decode_deep_link(link: str) -> dict[int, list[bytes]]:
    assert link.startswith("tt://?")
    payload = link.removeprefix("tt://?")
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    fields: dict[int, list[bytes]] = {}
    index = 0
    while index < len(raw):
        tag_size = 1 << (raw[index] >> 6)
        tag = int.from_bytes(raw[index:index + tag_size], "big") & ((1 << (tag_size * 8 - 2)) - 1)
        index += tag_size
        length_size = 1 << (raw[index] >> 6)
        length = int.from_bytes(raw[index:index + length_size], "big") & ((1 << (length_size * 8 - 2)) - 1)
        index += length_size
        value = raw[index:index + length]
        fields.setdefault(tag, []).append(value)
        index += length
    assert index == len(raw)
    return fields


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
    assert outbound["tls"]["alpn"] == ["h2"]


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
    """Генерирует официальный TrustTunnel deep link."""
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")], domain="custom.domain")
    user = state.users[0]
    
    link = p.client_link(user, state)
    fields = _decode_deep_link(link)
    assert fields[0] == [b"\x01"]
    assert fields[1] == [b"custom.domain"]
    assert fields[2] == [b"custom.domain:443"]
    assert fields[5] == [b"a@x.com"]
    assert fields[6] == [p._derive_password("uuid-a").encode()]
    assert fields[9] == [b"\x01"]
    assert fields[12] == [b"a@x.com TrustTunnel"]


def test_tcp_client_link_uses_official_query_payload_form():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")], domain="custom.domain")
    link = p.client_link(state.users[0], state)

    assert link.startswith("tt://?")
    assert "=" not in link


def test_client_links_both_encode_h2_and_h3():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com")], transport="both")

    links = p.client_links(state.users[0], state)

    assert len(links) == 2
    assert all(link.startswith("tt://?") for link in links)
    assert [_decode_deep_link(link)[9] for link in links] == [[b"\x01"], [b"\x02"]]


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
    assert _decode_deep_link(p.client_link(state.users[0], state))[9] == [b"\x01"]


def test_set_transport_only_updates_desired_state():
    p = TrustTunnelPlugin()
    state = _state([_user("a@x.com")], transport="tcp")

    with patch.object(p, "_resolve_certs", return_value=("cert.pem", "key.pem")):
        changed = p.set_transport(
            state,
            "quic",
        )

    assert changed is True
    assert state.protocols["trusttunnel"].config["transport"] == "quic"




