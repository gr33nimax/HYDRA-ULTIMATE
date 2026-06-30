"""tests/test_awg_plugin.py — Тесты для AmneziaWG plugin v2."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin, AWG_CONF, AWG_INTERFACE
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User


FAKE_CONF = """[Interface]
PrivateKey = sFk7RkMx9J0XJ7WpP8mF0Q==
Address = 10.66.66.1/24
ListenPort = 51820
Jc = 4
Jmin = 40
Jmax = 70
S1 = 8
S2 = 72
MTU = 1420
"""


def _make_state(users: list | None = None) -> AppState:
    state = AppState()
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


def test_plugin_meta():
    p = AmneziaWGPlugin()
    assert p.meta.name == "amneziawg"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False


def test_configure_returns_route_rule():
    p = AmneziaWGPlugin()
    state = _make_state([_make_user("a@x.com")])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf, \
         patch.object(p, "_awg") as mock_awg:
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = FAKE_CONF
        mock_awg.return_value = MagicMock(stdout="mock_pubkey\n", returncode=0)

        frag = p.configure(state)

        assert isinstance(frag, ConfigFragment)
        assert len(frag.route_rules) == 1
        assert "ip_cidr" in frag.route_rules[0]
        assert frag.nft_tproxy_ports == []
        assert frag.inbounds == []
        assert frag.outbounds == []


def test_configure_no_side_effects():
    p = AmneziaWGPlugin()
    state = _make_state([_make_user("a@x.com")])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf, \
         patch.object(p, "_awg") as mock_awg:
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = FAKE_CONF
        mock_awg.return_value = MagicMock(stdout="mock_pubkey\n", returncode=0)

        p.configure(state)
        mock_conf.write_text.assert_not_called()


def test_configure_empty_when_no_conf():
    p = AmneziaWGPlugin()
    state = _make_state([_make_user("a@x.com")])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf:
        mock_conf.exists.return_value = False

        frag = p.configure(state)
        assert frag.route_rules == []
        assert frag.inbounds == []


def test_traffic_uses_state():
    p = AmneziaWGPlugin()
    user_a = _make_user("a@x.com", uuid="uuid-a")
    user_a.credentials["amneziawg"] = {"public_key": "pub_a"}
    state = _make_state([user_a])

    with patch.object(p, "_installed", return_value=True), \
         patch.object(p, "_is_up", return_value=True), \
         patch.object(p, "_awg") as mock_awg:
        def fake_awg(*args, _input="", **kw):
            if args[0] == "pubkey" and _input:
                return MagicMock(stdout="pub_a\n", returncode=0)
            if args[:2] == ("show", AWG_INTERFACE) and args[2] == "transfer":
                return MagicMock(stdout="pub_a\t1000\t500\npub_unknown\t200\t100\n", returncode=0)
            return MagicMock(stdout="", returncode=1)
        mock_awg.side_effect = fake_awg

        result = p.traffic(state)
        assert result.get("a@x.com") == 1500
        assert "?" not in result


def test_on_user_add_triggers_apply():
    p = AmneziaWGPlugin()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf, \
         patch.object(p, "_awg") as mock_awg, \
         patch.object(p, "_is_up", return_value=True), \
         patch("hydra.plugins.amneziawg.plugin.subprocess.run") as mock_run:
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = FAKE_CONF
        mock_awg.return_value = MagicMock(stdout="mock_pubkey\n", returncode=0)
        mock_run.return_value = MagicMock(returncode=0)

        p.on_user_add(user, state)
        mock_conf.write_text.assert_called_once()


def test_on_user_remove_reconfigures():
    p = AmneziaWGPlugin()
    user = _make_user("a@x.com")
    state = _make_state([user])

    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf, \
         patch.object(p, "_awg") as mock_awg, \
         patch.object(p, "_is_up", return_value=True):
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = FAKE_CONF
        mock_awg.return_value = MagicMock(stdout="mock_pubkey\n", returncode=0)

        state.users = []
        p.on_user_remove(user, state)
        mock_conf.write_text.assert_called_once()


def test_connected_clients_returns_list():
    p = AmneziaWGPlugin()
    with patch.object(p, "_installed", return_value=True), \
         patch.object(p, "_is_up", return_value=True), \
         patch.object(p, "_awg") as mock_awg:
        mock_awg.return_value = MagicMock(
            stdout="interface\tpriv\tpub\t1234\npub_key\tendpoint\t:51820\t10.66.66.2/32\t1000000\t500\t200\t1234\n",
            returncode=0,
        )
        p._peer_map = {"pub_key": "a@x.com"}
        clients = p.connected_clients()
        assert len(clients) >= 1
        assert clients[0]["email"] == "a@x.com"
        assert "pubkey" in clients[0]


def test_resolve_network_avoids_conflicts():
    from hydra.core.state import PluginState
    p = AmneziaWGPlugin()
    state = _make_state()
    # Эмулируем конфликт: WDTT занял 10.66.66.0/16
    state.protocols["wdtt"] = PluginState(enabled=True, config={"network": "10.66.66.0/16"})
    state.protocols["amneziawg"] = PluginState(enabled=True, config={})

    # Если awg0.conf не существует, должен выбрать первую свободную сеть (10.67.67.0/24)
    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf:
        mock_conf.exists.return_value = False
        net = p._resolve_network(state)
        assert net == "10.67.67.0/24"
        assert state.protocols["amneziawg"].config["network"] == "10.67.67.0/24"

    # Если в awg0.conf прописана конфликтующая сеть (10.66.66.1/24), он должен проигнорировать её и выбрать свободную (10.67.67.0/24)
    with patch("hydra.plugins.amneziawg.plugin.AWG_CONF") as mock_conf:
        mock_conf.exists.return_value = True
        mock_conf.read_text.return_value = "Address = 10.66.66.1/24"
        # Сбрасываем старую сохраненную сеть
        state.protocols["amneziawg"].config = {}
        net = p._resolve_network(state)
        assert net == "10.67.67.0/24"
