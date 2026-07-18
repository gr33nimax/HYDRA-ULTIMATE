"""tests/test_shadowtls_plugin.py — Tests for ShadowTLS plugin."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.shadowtls.plugin import ShadowTLSPlugin
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _state(users=None, handshake_sni="google.com", naive_enabled=False, naive_domain="naive.example.com"):
    s = AppState()
    s.network.domain = naive_domain
    s.network.server_ip = "203.0.113.10"
    s.protocols["naive"] = PluginState(enabled=naive_enabled)
    s.protocols["shadowtls"] = PluginState(enabled=True, config={"handshake_sni": handshake_sni})
    if users:
        s.users = users
    return s


def _user(email, uuid="u1", blocked=False):
    return User(email=email, uuid=uuid, blocked=blocked)


def test_meta():
    p = ShadowTLSPlugin()
    assert p.meta.name == "shadowtls"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False


def test_configure_returns_inbound():
    """configure() generates ConfigFragment with shadowtls and trojan inbounds."""
    p = ShadowTLSPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")], naive_enabled=True)

    frag = p.configure(state)

    assert isinstance(frag, ConfigFragment)
    assert len(frag.inbounds) == 2
    
    stls = [i for i in frag.inbounds if i["type"] == "shadowtls"][0]
    trojan = [i for i in frag.inbounds if i["type"] == "trojan"][0]

    assert stls["tag"] == "shadowtls-in"
    assert stls["listen"] == "127.0.0.1"
    assert stls["listen_port"] == 20446
    assert stls["version"] == 3
    assert stls["detour"] == "shadowtls-trojan-in"
    assert stls["strict_mode"] is True
    assert stls["handshake"]["server"] == "google.com"

    assert trojan["tag"] == "shadowtls-trojan-in"
    assert trojan["listen"] == "127.0.0.1"
    assert trojan["listen_port"] == 0


def test_configure_users_in_inbounds():
    """All active users are in shadowtls and trojan users list."""
    p = ShadowTLSPlugin()
    state = _state([
        _user("a@x.com", uuid="u1"),
        _user("b@x.com", uuid="u2"),
    ])

    frag = p.configure(state)
    stls = [i for i in frag.inbounds if i["type"] == "shadowtls"][0]
    trojan = [i for i in frag.inbounds if i["type"] == "trojan"][0]

    names_stls = [u["name"] for u in stls["users"]]
    names_trojan = [u["name"] for u in trojan["users"]]

    assert "a@x.com" in names_stls
    assert "b@x.com" in names_stls
    assert "a@x.com" in names_trojan
    assert "b@x.com" in names_trojan


def test_shadowtls_and_trojan_use_independent_passwords():
    """The transport and the inner proxy are separate authentication layers."""
    p = ShadowTLSPlugin()
    user = _user("a@x.com", uuid="uuid-a")
    state = _state([user])

    frag = p.configure(state)
    stls = next(i for i in frag.inbounds if i["type"] == "shadowtls")
    trojan = next(i for i in frag.inbounds if i["type"] == "trojan")
    client = json.loads(p.generate_client_config(user, state))
    stls_out = next(o for o in client["outbounds"] if o["type"] == "shadowtls")
    trojan_out = next(o for o in client["outbounds"] if o["type"] == "trojan")

    assert stls["users"][0]["password"] != trojan["users"][0]["password"]
    assert stls_out["password"] == stls["users"][0]["password"]
    assert trojan_out["password"] == trojan["users"][0]["password"]


def test_configure_skips_blocked():
    """Blocked users do not get included in the configure output."""
    p = ShadowTLSPlugin()
    state = _state([
        _user("a@x.com", uuid="u1"),
        _user("b@x.com", uuid="u2", blocked=True),
    ])

    frag = p.configure(state)
    stls = [i for i in frag.inbounds if i["type"] == "shadowtls"][0]
    assert len(stls["users"]) == 1
    assert stls["users"][0]["name"] == "a@x.com"


def test_configure_empty_no_sni():
    """Empty config fragment returned when no handshake_sni is configured."""
    p = ShadowTLSPlugin()
    state = _state([_user("a@x.com")])
    state.protocols["shadowtls"].config["handshake_sni"] = ""

    frag = p.configure(state)
    assert frag.inbounds == []


def test_configure_empty_no_users():
    """Empty config fragment returned when there are no users."""
    p = ShadowTLSPlugin()
    state = _state([])

    frag = p.configure(state)
    assert frag.inbounds == []


def test_install_checks_singbox():
    """install() checks if sing-box is installed."""
    p = ShadowTLSPlugin()
    with patch("hydra.core.singbox.is_installed", return_value=True):
        assert p.install() is True
    with patch("hydra.core.singbox.is_installed", return_value=False):
        assert p.install() is False


def test_on_user_add_sets_credentials():
    """on_user_add sets stls_password and trojan_password in user credentials."""
    p = ShadowTLSPlugin()
    user = _user("a@x.com", uuid="uuid-a")
    state = _state([user])
    p.on_user_add(user, state)

    assert "shadowtls" in user.credentials
    assert user.credentials["shadowtls"]["username"] == "a@x.com"
    assert len(user.credentials["shadowtls"]["stls_password"]) > 0
    assert len(user.credentials["shadowtls"]["trojan_password"]) > 0


def test_client_link_valid():
    """client_link() returns a valid trojan:// link with shadow-tls plugin."""
    p = ShadowTLSPlugin()
    state = _state()
    user = _user("a@x.com", uuid="uuid-a")
    link = p.client_link(user, state)

    assert link.startswith("trojan://")
    assert "@203.0.113.10:443" in link
    assert "naive.example.com" not in link
    assert "plugin=shadow-tls" in link
    assert "plugin-opts=" in link


def test_generate_client_config_json():
    """generate_client_config() returns valid client sing-box JSON configuration."""
    p = ShadowTLSPlugin()
    state = _state()
    user = _user("a@x.com", uuid="uuid-a")
    cfg = p.generate_client_config(user, state)

    parsed = json.loads(cfg)
    trojan_out = [o for o in parsed["outbounds"] if o["type"] == "trojan"][0]
    stls_out = [o for o in parsed["outbounds"] if o["type"] == "shadowtls"][0]

    assert trojan_out["server_port"] == 443
    assert trojan_out["server"] == "203.0.113.10"
    assert trojan_out["detour"] == stls_out["tag"]
    assert stls_out["tls"]["server_name"] == "google.com"
    assert stls_out["version"] == 3


def test_domain_conflict_check():
    """A local handshake SNI is rejected before firewall changes."""
    p = ShadowTLSPlugin()
    state = _state(naive_enabled=False, naive_domain="conflict.com")
    state.protocols["shadowtls"].config["handshake_sni"] = ""

    with patch("hydra.ui.tui.prompt", return_value="conflict.com"), \
         patch("hydra.utils.firewall.open_tcp") as mock_open, \
         patch("subprocess.run") as mock_run:
        with pytest.raises(ValueError) as excinfo:
            p.on_enable(state)
        assert "принадлежит этому серверу" in str(excinfo.value)
        mock_open.assert_not_called()


def test_existing_local_handshake_sni_is_rejected():
    p = ShadowTLSPlugin()
    state = _state(handshake_sni="NAIVE.EXAMPLE.COM.")

    with patch("hydra.utils.firewall.open_tcp") as mock_open, \
         patch("subprocess.run"):
        with pytest.raises(ValueError, match="циклическое подключение"):
            p.on_enable(state)
        mock_open.assert_not_called()


def test_client_link_formats_ipv6_server_ip():
    p = ShadowTLSPlugin()
    state = _state()
    state.network.server_ip = "2001:db8::10"

    link = p.client_link(_user("a@x.com", uuid="uuid-a"), state)

    assert "@[2001:db8::10]:443" in link


def test_on_enable_opens_firewall():
    """on_enable() opens tcp port 443 and sets enable flag."""
    p = ShadowTLSPlugin()
    state = _state()

    with patch("hydra.utils.firewall.open_tcp") as mock_open, \
         patch("subprocess.run") as mock_run:
        p.on_enable(state)
        mock_open.assert_called_once_with(443, "shadowtls")
        assert state.protocols["shadowtls"].enabled is True


def test_on_disable_defers_rebuild():
    """on_disable() sets enabled flag to False and removes rules."""
    p = ShadowTLSPlugin()
    state = _state()

    with patch("subprocess.run") as mock_run:
        p.on_disable(state)
        assert state.protocols["shadowtls"].enabled is False


def test_status_delegates_to_singbox():
    """status() returns accurate runtime status of the plugin."""
    p = ShadowTLSPlugin()
    with patch("hydra.core.singbox.is_installed", return_value=True), \
         patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.state.load_state") as mock_load, \
         patch.object(p, "_get_total_traffic", return_value=1024):
        state = _state(naive_enabled=True)
        mock_load.return_value = state

        status = p.status()
        assert status.installed is True
        assert status.running is True
        assert status.enabled is True
        assert status.port == 20446
        assert status.info["Общий трафик"] == "1.00 KB"
