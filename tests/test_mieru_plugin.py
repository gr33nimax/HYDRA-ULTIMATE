"""tests/test_mieru_plugin.py — Тесты для Mieru plugin v2 (sing-box inbound)."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
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
    assert "a@x.com" in names
    assert "b@x.com" in names


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
    assert user.credentials["mieru"]["username"] == "a@x.com"
    assert len(user.credentials["mieru"]["password"]) > 0


def test_deterministic_creds():
    """Одинаковый email/uuid → одинаковые креды."""
    p = MieruPlugin()
    u1 = _user("a@x.com", uuid="same")
    u2 = _user("a@x.com", uuid="same")
    assert p._derive_username(u1) == p._derive_username(u2)
    assert p._derive_password("same") == p._derive_password("same")


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
    assert mieru_out[0]["traffic_pattern"] == "GgQIARAK"


def test_on_enable_opens_firewall():
    """on_enable() открывает порты."""
    p = MieruPlugin()
    with patch("hydra.utils.firewall.open_range") as mock, \
         patch("subprocess.run") as mock_run:
        p.on_enable(_state())
        mock.assert_called_once_with("tcp", 2012, 2022, "mieru")


def test_on_disable_closes_firewall():
    """on_disable() закрывает порты."""
    p = MieruPlugin()
    with patch("hydra.utils.firewall.close_range") as mock, \
         patch("subprocess.run") as mock_run:
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


def test_connected_clients_with_ss():
    """connected_clients() парсит вывод ss с группировкой по IP."""
    p = MieruPlugin()
    
    mock_ss_output = (
        "0      0             146.103.126.78:2012        109.252.12.34:58291\n"
        "0      0             146.103.126.78:2012        109.252.12.34:58292\n"
        "0      0             [::1]:2015                 [::1]:58293\n"
    )
    
    import subprocess
    mock_res = MagicMock(spec=subprocess.CompletedProcess)
    mock_res.returncode = 0
    mock_res.stdout = mock_ss_output
    
    with patch("shutil.which", return_value="/usr/bin/ss"), \
         patch("subprocess.run", return_value=mock_res):
        clients = p.connected_clients()
        # Сгруппировано: 109.252.12.34 (2 сессии) и ::1 (1 сессия)
        assert len(clients) == 2
        
        # Первая сессия: порт 2012 с 2 TCP каналами
        assert clients[0]["email"] == "109.252.12.34 (2 TCP)"
        assert clients[0]["online"] is True
        
        # Вторая сессия: порт 2015 с 1 TCP каналом
        assert clients[1]["email"] == "::1 (1 TCP)"
        assert clients[1]["online"] is True


def test_traffic_iptables():
    """traffic() возвращает пустой словарь, статус содержит Общий трафик."""
    p = MieruPlugin()
    
    import subprocess
    def side_effect(args, **kwargs):
        res = MagicMock(spec=subprocess.CompletedProcess)
        res.returncode = 0
        if "INPUT" in args:
            res.stdout = "      250     1250000 INPUT      all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* mieru-rx-2012 */\n"
        elif "OUTPUT" in args:
            res.stdout = "      300     1500000 OUTPUT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* mieru-tx-2012 */\n"
        else:
            res.stdout = ""
        return res
        
    with patch("subprocess.run", side_effect=side_effect), \
         patch("hydra.core.singbox.is_installed", return_value=True), \
         patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.state.load_state") as mock_load:
        
        from hydra.core.state import PluginState
        state = _state([_user("a@x.com")])
        state.protocols["mieru"] = PluginState(enabled=True)
        mock_load.return_value = state
        
        tr = p.traffic(state)
        assert tr == {}
        
        st = p.status()
        assert st.info == {"Общий трафик": "2.62 MB"}


def test_mieru_presets_change_configure():
    """Тест изменения пресета обфускации и его влияния на configure()."""
    from hydra.core.state import PluginState
    p = MieruPlugin()
    
    # 1. Сначала проверяем medium
    state = _state([_user("a@x.com")])
    state.protocols["mieru"] = PluginState(enabled=True, config={"traffic_preset": "medium"})
    frag = p.configure(state)
    assert frag.inbounds[0]["traffic_pattern"] == "GgQIARAKIggIARABGAYgCCoFCEAQgAE="

    # 2. Проверяем disabled
    state = _state([_user("a@x.com")])
    state.protocols["mieru"] = PluginState(enabled=True, config={"traffic_preset": "disabled"})
    frag = p.configure(state)
    assert frag.inbounds[0]["traffic_pattern"] == "GgIIACoECAAQAA=="


def test_mieru_set_preset_saves_and_applies():
    """set_preset() сохраняет пресет в state и применяет конфиг."""
    p = MieruPlugin()
    state = _state([_user("a@x.com")])
    
    with patch("hydra.core.state.save_state") as mock_save, \
         patch("hydra.core.orchestrator.apply_config", return_value=True) as mock_apply:
        
        ok = p.set_preset(state, "medium")
        assert ok is True
        assert state.protocols["mieru"].config["traffic_preset"] == "medium"
        mock_save.assert_called_once_with(state)
        mock_apply.assert_called_once_with(state)


def test_mieru_client_link_includes_preset():
    """client_link() содержит корректный query-параметр traffic-pattern."""
    from hydra.core.state import PluginState
    p = MieruPlugin()
    
    state = _state()
    state.protocols["mieru"] = PluginState(enabled=True, config={"traffic_preset": "medium"})
    
    link = p.client_link(_user("a@x.com", uuid="uuid-a"), state)
    assert "traffic-pattern=GgQIARAKIggIARABGAYgCCoFCEAQgAE%3D" in link




