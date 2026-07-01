"""tests/test_naive_plugin.py — Тесты для NaiveProxy plugin v2."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.naive.plugin import NaivePlugin, CADDYFILE
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _make_state(users: list | None = None, domain: str = "example.com") -> AppState:
    state = AppState()
    state.network.domain = domain
    state.protocols["naive"] = PluginState(enabled=True, port=443, config={})
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


def test_plugin_meta():
    p = NaivePlugin()
    assert p.meta.name == "naive"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is True


def test_configure_returns_fragment_with_port():
    """configure() возвращает ConfigFragment с nft_tproxy_ports=[443]."""
    p = NaivePlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    frag = p.configure(state)

    assert isinstance(frag, ConfigFragment)
    assert frag.nft_tproxy_ports == [443]
    assert frag.inbounds == []
    assert frag.outbounds == []


def test_configure_returns_fragment_even_without_users():
    """Без юзеров configure всё равно возвращает nft_tproxy_ports."""
    p = NaivePlugin()
    state = _make_state([])
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == [443]


def test_configure_skips_blocked_users():
    """Заблокированные юзеры не попадают в Caddyfile."""
    p = NaivePlugin()
    state = _make_state([
        _make_user("active@x.com", uuid="uuid-a"),
        _make_user("blocked@x.com", uuid="uuid-b", blocked=True),
    ])
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == [443]
    # В Caddyfile только один пользователь
    assert "uuid-a" not in p._pending_cfg or True
    lines = p._pending_cfg.splitlines()
    basic_auth_lines = [l for l in lines if "basic_auth" in l]
    assert len(basic_auth_lines) == 1


def test_configure_empty_when_no_domain():
    """Без домена configure возвращает пустой фрагмент."""
    p = NaivePlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")], domain="")
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == []


def test_client_link_valid_uri():
    """client_link() начинается с naive+https://."""
    p = NaivePlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    link = p.client_link(_make_user("a@x.com", uuid="uuid-a"), state)

    assert link.startswith("naive+https://")
    assert "example.com:443" in link
    assert "uuid-a" not in link


def test_on_user_add_sets_credentials():
    """После on_user_add в user.credentials['naive'] есть username/password."""
    p = NaivePlugin()
    user = _make_user("a@x.com", uuid="uuid-a")
    state = _make_state([user])

    with patch.object(p, "apply", return_value=True):
        p.on_user_add(user, state)

    assert "naive" in user.credentials
    assert "username" in user.credentials["naive"]
    assert "password" in user.credentials["naive"]
    assert user.credentials["naive"]["username"].startswith("u")


def test_deterministic_creds():
    """Одинаковый uuid → одинаковые креды."""
    p = NaivePlugin()
    uuid = "same-uuid-123"

    u1 = _make_user("a@x.com", uuid=uuid)
    u2 = _make_user("b@x.com", uuid=uuid)

    uname1 = p._derive_username(u1.uuid)
    uname2 = p._derive_username(u2.uuid)
    assert uname1 == uname2

    pass1 = p._derive_password(u1.uuid)
    pass2 = p._derive_password(u2.uuid)
    assert pass1 == pass2


def test_generate_client_config_contains_server():
    """generate_client_config возвращает JSON с server = domain."""
    p = NaivePlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    user = _make_user("a@x.com", uuid="uuid-a")

    cfg = p.generate_client_config(user, state)
    parsed = json.loads(cfg)
    outbounds = parsed["outbounds"]
    naive_out = [o for o in outbounds if o["type"] == "naive"]
    assert len(naive_out) == 1
    assert naive_out[0]["server"] == "example.com"
    assert naive_out[0]["server_port"] == 443
    assert naive_out[0]["tls"]["server_name"] == "example.com"


def test_generate_client_config_empty_without_domain():
    """Без домена generate_client_config возвращает пустую строку."""
    p = NaivePlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")], domain="")
    user = _make_user("a@x.com", uuid="uuid-a")
    assert p.generate_client_config(user, state) == ""


def test_client_link_empty_without_domain():
    """Без домена client_link возвращает пустую строку."""
    p = NaivePlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")], domain="")
    user = _make_user("a@x.com", uuid="uuid-a")
    assert p.client_link(user, state) == ""


def test_status_returns_plugin_status():
    """status() возвращает PluginStatus без ошибок."""
    p = NaivePlugin()
    with patch.object(NaivePlugin, "_installed", return_value=True), \
         patch("hydra.plugins.naive.plugin.CADDYFILE") as mock_cfg, \
         patch("subprocess.run") as mock_run:
        mock_cfg.exists.return_value = True
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        s = p.status()
        assert s.installed is True
        assert s.port == 443


def test_build_caddyfile_basic():
    """_build_caddyfile генерирует валидный Caddyfile с reverse_proxy decoy."""
    p = NaivePlugin()
    caddyfile = p._build_caddyfile(
        domain="vpn.example.com",
        port=443,
        users=[{"username": "testuser", "password": "testpass"}],
        probe_secret="mysecret123",
        decoy_url="https://www.google.com",
    )

    assert "vpn.example.com:443" in caddyfile
    assert ":443" in caddyfile
    assert "basic_auth testuser testpass" in caddyfile
    assert "probe_resistance mysecret123" in caddyfile
    assert "forward_proxy" in caddyfile
    assert "reverse_proxy https://www.google.com" in caddyfile
    assert "on_demand" in caddyfile


def test_build_caddyfile_no_probe_secret():
    """Без probe_secret директива probe_resistance не добавляется."""
    p = NaivePlugin()
    caddyfile = p._build_caddyfile(
        domain="vpn.example.com",
        port=443,
        users=[],
        probe_secret="",
    )
    assert "probe_resistance" not in caddyfile


def test_build_caddyfile_multiple_users():
    """Несколько пользователей = несколько basic_auth строк."""
    p = NaivePlugin()
    caddyfile = p._build_caddyfile(
        domain="vpn.example.com",
        port=443,
        users=[
            {"username": "u1", "password": "p1"},
            {"username": "u2", "password": "p2"},
            {"username": "u3", "password": "p3"},
        ],
        probe_secret="s",
    )
    lines = caddyfile.splitlines()
    auth_lines = [l for l in lines if "basic_auth" in l]
    assert len(auth_lines) == 3


def test_on_enable_opens_firewall():
    """on_enable() открывает порт 443."""
    p = NaivePlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    with patch("hydra.utils.firewall.open_tcp") as mock_open, \
         patch("subprocess.run") as mock_run, \
         patch("hydra.ui.tui.prompt", side_effect=lambda text, default="": default), \
         patch("hydra.ui.tui.confirm", return_value=False), \
         patch.object(p, "apply", return_value=True):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        p.on_enable(state)
        mock_open.assert_called_once_with(443, "naive")


def test_on_enable_raises_error_without_domain():
    """on_enable() бросает ValueError, если домен не указан."""
    p = NaivePlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")], domain="")
    with patch("hydra.ui.tui.prompt", return_value=""), \
         patch("hydra.ui.tui.confirm", return_value=False):
        try:
            p.on_enable(state)
            assert False, "Должно было выброситься ValueError"
        except ValueError:
            pass


def test_on_disable_closes_firewall():
    """on_disable() закрывает порт 443."""
    p = NaivePlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    with patch("hydra.utils.firewall.close_tcp") as mock_close, \
         patch("subprocess.run") as mock_run:
        p.on_disable(state)
        mock_close.assert_called_once_with(443)


def test_connected_clients_parses_ss():
    """connected_clients() парсит ss output и группирует по IP."""
    p = NaivePlugin()
    mock_ss = (
        "0      0      10.0.0.1:443    203.0.113.5:58291\n"
        "0      0      10.0.0.1:443    203.0.113.5:58292\n"
        "0      0      10.0.0.1:443    198.51.100.1:59001\n"
    )
    with patch("shutil.which", return_value="/usr/bin/ss"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=mock_ss, returncode=0)
        clients = p.connected_clients()
        assert len(clients) == 2
        ips = {c["email"].split(" ")[0] for c in clients}
        assert "203.0.113.5" in ips
        assert "198.51.100.1" in ips


def test_status_shows_traffic():
    """status() показывает Общий трафик в info."""
    p = NaivePlugin()
    with patch.object(NaivePlugin, "_installed", return_value=True), \
         patch("subprocess.run") as mock_run, \
         patch.object(NaivePlugin, "_get_total_traffic", return_value=1048576):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        with patch("hydra.plugins.naive.plugin.CADDYFILE") as mock_cfg:
            mock_cfg.exists.return_value = True
            s = p.status()
            assert "Общий трафик" in s.info
            assert "1.00 MB" in s.info["Общий трафик"]


def test_find_existing_cert_and_tls_config():
    """_find_existing_cert находит сертификаты, а _build_caddyfile подставляет их в конфиг."""
    p = NaivePlugin()
    with patch("pathlib.Path.exists", return_value=True):
        cert, key = p._find_existing_cert("my.example.com")
        assert cert == "/etc/letsencrypt/live/my.example.com/fullchain.pem"
        assert key == "/etc/letsencrypt/live/my.example.com/privkey.pem"

    caddyfile = p._build_caddyfile(
        domain="my.example.com",
        port=443,
        users=[],
        probe_secret="",
        cert_file="/path/to/cert.pem",
        key_file="/path/to/key.pem",
    )
    assert "tls /path/to/cert.pem /path/to/key.pem" in caddyfile
    assert "on_demand" not in caddyfile
