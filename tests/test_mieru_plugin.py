"""tests/test_mieru_plugin.py — Тесты для Mieru plugin v2."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.mieru.plugin import MieruPlugin, SERVER_CFG
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User


def _make_state(users: list | None = None) -> AppState:
    state = AppState()
    if users:
        state.users = users
    return state


def _make_user(email: str, uuid: str = "u1", blocked: bool = False) -> User:
    return User(email=email, uuid=uuid, blocked=blocked)


def test_plugin_meta():
    p = MieruPlugin()
    assert p.meta.name == "mieru"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is False


def test_configure_returns_fragment_with_port():
    """configure() возвращает ConfigFragment с nft_tproxy_ports=[2012]."""
    p = MieruPlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    frag = p.configure(state)

    assert isinstance(frag, ConfigFragment)
    assert frag.nft_tproxy_ports == [2012]
    assert frag.inbounds == []
    assert frag.outbounds == []


def test_configure_empty_when_no_users():
    """Без юзеров configure возвращает пустой фрагмент."""
    p = MieruPlugin()
    state = _make_state([])
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == []


def test_configure_skips_blocked_users():
    """Заблокированные юзеры не попадают в конфиг."""
    p = MieruPlugin()
    state = _make_state([
        _make_user("active@x.com", uuid="uuid-a"),
        _make_user("blocked@x.com", uuid="uuid-b", blocked=True),
    ])
    frag = p.configure(state)
    assert frag.nft_tproxy_ports == [2012]
    cfg_users = p._pending_cfg.get("users", [])
    usernames = [u["name"] for u in cfg_users]
    # Заблокированный юзер не должен быть в конфиге
    assert len(usernames) == 1
    # username детерминирован от uuid, не от email
    assert all("blocked" not in u for u in usernames)


def test_client_link_valid_uri():
    """client_link() начинается с mierus://."""
    p = MieruPlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    link = p.client_link(_make_user("a@x.com", uuid="uuid-a"), state)

    assert link.startswith("mierus://")
    assert "multiplexing=MULTIPLEXING_HIGH" in link
    assert "uuid-a" not in link  # пароль детерминированный, но не uuid


def test_on_user_add_sets_credentials():
    """После on_user_add в user.credentials['mieru'] есть username/password."""
    p = MieruPlugin()
    user = _make_user("a@x.com", uuid="uuid-a")
    state = _make_state([user])

    with patch.object(p, "apply", return_value=True):
        p.on_user_add(user, state)

    assert "mieru" in user.credentials
    assert "username" in user.credentials["mieru"]
    assert "password" in user.credentials["mieru"]
    assert user.credentials["mieru"]["username"].startswith("u")


def test_deterministic_creds():
    """Одинаковый uuid → одинаковые креды."""
    p = MieruPlugin()
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
    """generate_client_config возвращает JSON с server."""
    p = MieruPlugin()
    state = _make_state([_make_user("a@x.com", uuid="uuid-a")])
    user = _make_user("a@x.com", uuid="uuid-a")

    cfg = p.generate_client_config(user, state)
    import json
    parsed = json.loads(cfg)
    outbounds = parsed["outbounds"]
    mieru_out = [o for o in outbounds if o["type"] == "mieru"]
    assert len(mieru_out) == 1
    assert mieru_out[0]["server_port"] == 2012
    assert mieru_out[0]["multiplexing"] == "MULTIPLEXING_HIGH"


def test_status_returns_plugin_status():
    """status() возвращает PluginStatus без ошибок."""
    p = MieruPlugin()
    with patch.object(MieruPlugin, "_installed", return_value=True), \
         patch("hydra.plugins.mieru.plugin.SERVER_CFG") as mock_cfg, \
         patch("subprocess.run") as mock_run:
        mock_cfg.exists.return_value = True
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        s = p.status()
        assert s.installed is True
        assert s.port == 2012
