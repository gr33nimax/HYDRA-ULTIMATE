"""tests/test_slipgate_plugin.py — Тесты для SlipGate plugin v2."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.slipgate.plugin import SlipGatePlugin, DNS_PORT
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _make_state(users: list | None = None, domain: str = "t.example.com") -> AppState:
    state = AppState()
    state.network.domain = domain
    state.protocols["slipgate"] = PluginState(enabled=True, port=DNS_PORT, config={})
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


def test_plugin_meta():
    p = SlipGatePlugin()
    assert p.meta.name == "slipgate"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is True


def test_configure_returns_fragment_with_dns_port():
    """configure возвращает ConfigFragment с nft_tproxy_ports=[53]."""
    p = SlipGatePlugin()
    state = _make_state([_make_user("a@x.com")])
    frag = p.configure(state)
    assert isinstance(frag, ConfigFragment)
    assert frag.nft_tproxy_ports == [DNS_PORT]


def test_configure_empty_when_no_domain():
    """Без домена configure возвращает пустой фрагмент."""
    p = SlipGatePlugin()
    state = _make_state([_make_user("a@x.com")], domain="")
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == []


def test_client_link_valid_uri():
    """client_link начинается с slipnet://."""
    p = SlipGatePlugin()
    state = _make_state([_make_user("a@x.com")])
    link = p.client_link(_make_user("a@x.com"), state)
    assert link.startswith("slipnet://")
    assert "domain=t.example.com" in link


def test_client_link_empty_without_domain():
    """Без домена client_link возвращает пустую строку."""
    p = SlipGatePlugin()
    state = _make_state([_make_user("a@x.com")], domain="")
    assert p.client_link(_make_user("a@x.com"), state) == ""


def test_generate_client_config_contains_link():
    """generate_client_config возвращает JSON с полем link."""
    p = SlipGatePlugin()
    state = _make_state([_make_user("a@x.com")])
    cfg = p.generate_client_config(_make_user("a@x.com"), state)
    import json
    parsed = json.loads(cfg)
    assert parsed["protocol"] == "slipgate"
    assert parsed["link"].startswith("slipnet://")


def test_generate_client_config_empty_without_domain():
    """Без домена generate_client_config возвращает пустую строку."""
    p = SlipGatePlugin()
    state = _make_state([_make_user("a@x.com")], domain="")
    assert p.generate_client_config(_make_user("a@x.com"), state) == ""


def test_on_user_add_is_noop():
    """on_user_add — no-op для single-instance плагина."""
    p = SlipGatePlugin()
    user = _make_user("a@x.com")
    state = _make_state([user])
    p.on_user_add(user, state)
    assert "slipgate" not in user.credentials


def test_status_returns_plugin_status():
    """status возвращает PluginStatus без ошибок."""
    p = SlipGatePlugin()
    with patch.object(SlipGatePlugin, "_installed", return_value=True), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="active tunnel\n")
        s = p.status()
        assert s.installed is True
        assert s.port == DNS_PORT


def test_traffic_returns_empty():
    """traffic возвращает пустой словарь (не реализован)."""
    p = SlipGatePlugin()
    assert p.traffic(_make_state([])) == {}


def test_connected_clients_returns_list():
    """connected_clients возвращает список туннелей."""
    p = SlipGatePlugin()
    with patch.object(SlipGatePlugin, "_installed", return_value=True), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="mytunnel     DNSTT    active  53/udp\nother  Slipstream  active  53/udp\n",
        )
        clients = p.connected_clients()
        assert len(clients) == 2
        assert clients[0]["tunnel"].startswith("mytunnel")


def test_connected_clients_empty_when_not_installed():
    """Без установки connected_clients пуст."""
    p = SlipGatePlugin()
    with patch.object(SlipGatePlugin, "_installed", return_value=False):
        assert p.connected_clients() == []
