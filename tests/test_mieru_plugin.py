"""tests/test_mieru_plugin.py — Тесты для Mieru plugin v2 (sing-box inbound)."""
import json
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.mieru.plugin import MieruPlugin
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User


def _state(users=None):
    s = AppState()
    if users: s.users = users
    return s

def _user(email, uuid="u1", blocked=False):
    return User(email=email, uuid=uuid, blocked=blocked)


def test_meta():
    p = MieruPlugin()
    assert p.meta.name == "mieru"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False


def test_configure_returns_inbound():
    """configure() генерит ConfigFragment с mieru inbound."""
    p = MieruPlugin()
    frag = p.configure(_state([_user("a@x.com", uuid="uuid-a")]))

    assert isinstance(frag, ConfigFragment)
    assert len(frag.inbounds) == 1
    assert frag.inbounds[0]["type"] == "mieru"
    assert frag.inbounds[0]["tag"] == "mieru-in"
    assert frag.inbounds[0]["listen_port"] == 2012
    assert frag.inbounds[0]["transport"] == "TCP"
    assert frag.inbounds[0]["traffic_pattern"] == "GgQIARAK"
    assert len(frag.inbounds[0]["users"]) == 1


def test_configure_no_tproxy():
    """mieru НЕ использует TPROXY — трафик напрямую в sing-box."""
    p = MieruPlugin()
    frag = p.configure(_state([_user("a@x.com")]))
    assert frag.nft_tproxy_ports == []


def test_configure_listen_ports_range():
    """При range портов появляется listen_ports."""
    p = MieruPlugin()
    frag = p.configure(_state([_user("a@x.com")]))
    assert "listen_ports" in frag.inbounds[0]
    assert frag.inbounds[0]["listen_ports"] == ["2012-2022"]


def test_configure_users_in_inbound():
    """Все незаблокированные юзеры попадают в inbound.users."""
    p = MieruPlugin()
    frag = p.configure(_state([
        _user("a@x.com", uuid="u1"),
        _user("b@x.com", uuid="u2"),
    ]))
    names = [u["name"] for u in frag.inbounds[0]["users"]]
    assert len(names) == 2
    assert all(n.startswith("u") for n in names)


def test_configure_skips_blocked():
    """Blocked юзеры не попадают в inbound."""
    p = MieruPlugin()
    frag = p.configure(_state([
        _user("a@x.com", uuid="u1"),
        _user("b@x.com", uuid="u2", blocked=True),
    ]))
    assert len(frag.inbounds[0]["users"]) == 1


def test_configure_empty_no_users():
    """Без юзеров — пустой ConfigFragment."""
    p = MieruPlugin()
    frag = p.configure(_state([]))
    assert frag.inbounds == []
    assert frag.nft_tproxy_ports == []


def test_install_checks_singbox():
    """install() делегирует в singbox.is_installed()."""
    p = MieruPlugin()
    with patch("hydra.core.singbox.is_installed", return_value=True):
        assert p.install() is True
    with patch("hydra.core.singbox.is_installed", return_value=False):
        assert p.install() is False


def test_on_user_add_sets_credentials():
    """on_user_add записывает username/password в credentials."""
    p = MieruPlugin()
    user = _user("a@x.com", uuid="uuid-a")
    p.on_user_add(user, _state([user]))
    assert "mieru" in user.credentials
    assert user.credentials["mieru"]["username"].startswith("u")
    assert len(user.credentials["mieru"]["password"]) > 0


def test_deterministic_creds():
    """Одинаковый uuid → одинаковые креды."""
    p = MieruPlugin()
    assert p._derive_username("same") == p._derive_username("same")
    assert p._derive_password("same") == p._derive_password("same")
    assert p._derive_username("aaa") != p._derive_username("bbb")


def test_client_link_valid():
    """client_link() начинается с mierus://."""
    p = MieruPlugin()
    link = p.client_link(_user("a@x.com", uuid="uuid-a"), _state())
    assert link.startswith("mierus://")
    assert "port=2012" in link
    assert "protocol=TCP" in link
    assert "multiplexing=MULTIPLEXING_HIGH" in link


def test_generate_client_config_valid_json():
    """generate_client_config() возвращает валидный sing-box JSON."""
    p = MieruPlugin()
    cfg = p.generate_client_config(_user("a@x.com", uuid="uuid-a"), _state())
    parsed = json.loads(cfg)
    mieru_out = [o for o in parsed["outbounds"] if o["type"] == "mieru"]
    assert len(mieru_out) == 1
    assert mieru_out[0]["server_port"] == 2012
    assert mieru_out[0]["transport"] == "TCP"


def test_on_enable_opens_firewall():
    """on_enable() открывает порты."""
    p = MieruPlugin()
    with patch("hydra.utils.firewall.open_range") as mock:
        p.on_enable(_state())
        mock.assert_called_once_with("tcp", 2012, 2022, "mieru")


def test_on_disable_closes_firewall():
    """on_disable() закрывает порты."""
    p = MieruPlugin()
    with patch("hydra.utils.firewall.close_range") as mock:
        p.on_disable(_state())
        mock.assert_called_once_with("tcp", 2012, 2022)


def test_status_delegates_to_singbox():
    """status() проверяет sing-box, не mita."""
    p = MieruPlugin()
    with patch("hydra.core.singbox.is_installed", return_value=True), \
         patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.state.load_state") as mock_load:
        from hydra.core.state import PluginState
        state = _state()
        state.protocols["mieru"] = PluginState(enabled=True)
        mock_load.return_value = state
        s = p.status()
        assert s.installed is True
        assert s.running is True
        assert s.port == 2012
