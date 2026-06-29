"""tests/test_webdav_plugin.py — Тесты для WebDAV Tunnel plugin v2."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.webdav.plugin import WebdavPlugin, DEFAULT_PORT
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _make_state(users: list | None = None, mode: str = "selfhosted") -> AppState:
    state = AppState()
    state.network.domain = "example.com"
    state.protocols["webdav"] = PluginState(
        enabled=True, port=DEFAULT_PORT,
        config={"mode": mode, "login": "admin", "password": "secret123"},
    )
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1") -> User:
    return User(email=email, uuid=uuid)


def test_plugin_meta():
    p = WebdavPlugin()
    assert p.meta.name == "webdav"
    assert p.meta.category == PluginCategory.TRANSPORT


def test_configure_returns_fragment_with_port():
    """configure возвращает ConfigFragment с nft_tproxy_ports."""
    p = WebdavPlugin()
    state = _make_state([_make_user("a@x.com")])
    frag = p.configure(state)
    assert isinstance(frag, ConfigFragment)
    assert frag.nft_tproxy_ports == [DEFAULT_PORT]


def test_configure_empty_for_external_mode():
    """В external режиме configure возвращает пустой фрагмент (нет порта)."""
    p = WebdavPlugin()
    state = _make_state([_make_user("a@x.com")], mode="external")
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == []


def test_client_link_selfhosted():
    """client_link в selfhosted режиме содержит webdav://."""
    p = WebdavPlugin()
    state = _make_state([_make_user("a@x.com")], mode="selfhosted")
    link = p.client_link(_make_user("a@x.com"), state)
    assert link.startswith("webdav://")
    assert "admin:secret123" in link
    assert str(DEFAULT_PORT) in link


def test_client_link_external():
    """client_link в external режиме содержит webdavs:// если URL https."""
    p = WebdavPlugin()
    state = _make_state([_make_user("a@x.com")], mode="external")
    state.protocols["webdav"].config["webdav_url"] = "https://dav.example.com"
    link = p.client_link(_make_user("a@x.com"), state)
    assert link.startswith("webdavs://")


def test_client_link_external_no_url():
    """Без webdav_url client_link возвращает пустую строку."""
    p = WebdavPlugin()
    state = _make_state([_make_user("a@x.com")], mode="external")
    state.protocols["webdav"].config["webdav_url"] = ""
    assert p.client_link(_make_user("a@x.com"), state) == ""


def test_on_user_add_is_noop():
    """on_user_add — no-op для single-login плагина."""
    p = WebdavPlugin()
    user = _make_user("a@x.com")
    state = _make_state([user])
    p.on_user_add(user, state)
    assert "webdav" not in user.credentials


def test_generate_client_config_contains_link():
    """generate_client_config возвращает JSON с полем link."""
    p = WebdavPlugin()
    state = _make_state([_make_user("a@x.com")])
    cfg = p.generate_client_config(_make_user("a@x.com"), state)
    import json
    parsed = json.loads(cfg)
    assert parsed["protocol"] == "webdav"
    assert parsed["link"].startswith("webdav://")


def test_gen_login_password():
    """_gen_login и _gen_password возвращают строки."""
    p = WebdavPlugin()
    login = p._gen_login()
    pw = p._gen_password()
    assert len(login) >= 5
    assert len(pw) == 20


def test_status_returns_plugin_status():
    """status возвращает PluginStatus без ошибок."""
    p = WebdavPlugin()
    with patch.object(WebdavPlugin, "_installed", return_value=True), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        s = p.status()
        assert s.installed is True
        assert s.port == DEFAULT_PORT


def test_traffic_returns_empty():
    """traffic возвращает пустой словарь."""
    p = WebdavPlugin()
    assert p.traffic(_make_state([])) == {}
