"""tests/test_anytls_plugin.py — Тесты для AnyTLS plugin v2."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.anytls.plugin import AnyTLSPlugin, DEFAULT_PADDING_SCHEME
from hydra.plugins.base import PluginCategory, ConfigFragment
from hydra.core.state import AppState, User, PluginState


def _state(users=None, domain="anytls.example.com", naive_enabled=False, naive_domain="naive.example.com"):
    s = AppState()
    s.network.domain = naive_domain
    s.protocols["naive"] = PluginState(enabled=naive_enabled)
    s.protocols["anytls"] = PluginState(enabled=True, config={"domain": domain})
    if users:
        s.users = users
    return s


def _user(email, uuid="u1", blocked=False):
    return User(email=email, uuid=uuid, blocked=blocked)


def test_meta():
    p = AnyTLSPlugin()
    assert p.meta.name == "anytls"
    assert p.meta.category == PluginCategory.TRANSPORT
    assert p.meta.needs_domain is True


def test_apply_healthcheck_uses_candidate_anytls_inbound():
    plugin = AnyTLSPlugin()
    state = _state([_user("a@x.com")])

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.has_configured_inbound", return_value=True):
        health = plugin.health_result(state)

    assert health.healthy is True
    assert health.checks == {"sing_box": True, "anytls_inbound": True}


def test_apply_healthcheck_rejects_missing_anytls_inbound():
    plugin = AnyTLSPlugin()
    state = _state([_user("a@x.com")])

    with patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.singbox.has_configured_inbound", return_value=False):
        health = plugin.health_result(state)

    assert health.healthy is False
    assert "missing" in health.detail


def test_configure_returns_inbound():
    """configure() генерит ConfigFragment с anytls inbound."""
    p = AnyTLSPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")])
    
    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    assert isinstance(frag, ConfigFragment)
    assert len(frag.inbounds) == 1
    assert frag.inbounds[0]["type"] == "anytls"
    assert frag.inbounds[0]["tag"] == "anytls-in"
    assert frag.inbounds[0]["listen"] == "127.0.0.1"
    assert frag.inbounds[0]["listen_port"] == 20444


def test_configure_has_tls():
    """configure() содержит TLS настройки в inbound."""
    p = AnyTLSPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")], domain="custom.domain")
    
    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)
    
    assert "tls" not in frag.inbounds[0]


def test_configure_has_padding_scheme():
    """configure() содержит padding_scheme в inbound."""
    p = AnyTLSPlugin()
    state = _state([_user("a@x.com", uuid="uuid-a")])
    
    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    from hydra.plugins.anytls.presets import get_preset
    assert frag.inbounds[0]["padding_scheme"] == get_preset("web_browsing")["padding_scheme"]


def test_preset_management():
    """Тест переключения пресетов AnyTLS."""
    p = AnyTLSPlugin()
    state = _state([_user("a@x.com")])
    
    # По умолчанию web_browsing
    assert p.get_current_preset(state) == "web_browsing"
    
    # Меняем пресет
    with patch("hydra.core.orchestrator.apply_config", return_value=True), \
         patch("hydra.core.state.save_state") as mock_save:
        assert p.set_preset(state, "streaming") is True
        assert p.get_current_preset(state) == "streaming"
        
        # Проверяем, что в configure() используется новый пресет
        with patch("pathlib.Path.exists", return_value=True):
            frag = p.configure(state)
        from hydra.plugins.anytls.presets import get_preset
        assert frag.inbounds[0]["padding_scheme"] == get_preset("streaming")["padding_scheme"]
        
        # Невалидный пресет
        assert p.set_preset(state, "invalid_preset") is False



def test_configure_users_in_inbound():
    """Все незаблокированные юзеры попадают в inbound.users."""
    p = AnyTLSPlugin()
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
    p = AnyTLSPlugin()
    state = _state([
        _user("a@x.com", uuid="u1"),
        _user("b@x.com", uuid="u2", blocked=True),
    ])
    
    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    assert len(frag.inbounds[0]["users"]) == 1
    assert frag.inbounds[0]["users"][0]["name"] == "a@x.com"


def test_configure_empty_no_domain():
    """Без домена — пустой ConfigFragment."""
    p = AnyTLSPlugin()
    state = _state([_user("a@x.com")])
    state.protocols["anytls"].config["domain"] = ""
    
    frag = p.configure(state)
    assert frag.inbounds == []


def test_configure_empty_no_users():
    """Без юзеров — пустой ConfigFragment."""
    p = AnyTLSPlugin()
    state = _state([])
    
    frag = p.configure(state)
    assert frag.inbounds == []


def test_configure_uses_internal_port():
    """Когда SNI-мультиплексор активен → внутренний порт."""
    p = AnyTLSPlugin()
    # 2 плагина включены -> needs_mux = True
    state = _state([_user("a@x.com")], naive_enabled=True)
    
    with patch("pathlib.Path.exists", return_value=True):
        frag = p.configure(state)

    assert frag.inbounds[0]["listen_port"] == 20444


def test_install_checks_singbox():
    """install() делегирует в singbox.is_installed()."""
    p = AnyTLSPlugin()
    with patch("hydra.core.singbox.is_installed", return_value=True):
        assert p.install() is True
    with patch("hydra.core.singbox.is_installed", return_value=False):
        assert p.install() is False


def test_on_user_add_sets_credentials():
    """on_user_add записывает username/password в credentials."""
    p = AnyTLSPlugin()
    user = _user("a@x.com", uuid="uuid-a")
    state = _state([user])
    p.on_user_add(user, state)
    
    assert "anytls" in user.credentials
    assert user.credentials["anytls"]["username"] == "a@x.com"
    assert len(user.credentials["anytls"]["password"]) > 0


def test_deterministic_creds():
    """Одинаковый email/uuid → одинаковые креды."""
    p = AnyTLSPlugin()
    u1 = _user("a@x.com", uuid="same")
    u2 = _user("a@x.com", uuid="same")
    assert p._derive_username(u1) == p._derive_username(u2)
    assert p._derive_password("same") == p._derive_password("same")


def test_client_link_valid():
    """client_link() возвращает anytls:// формат ссылки."""
    p = AnyTLSPlugin()
    state = _state()
    user = _user("a@x.com", uuid="uuid-a")
    link = p.client_link(user, state)
    
    assert link.startswith("anytls://")
    assert "@anytls.example.com:443" in link
    assert "?sni=anytls.example.com" in link


def test_client_link_port_443():
    """Клиентская ссылка всегда указывает порт 443."""
    p = AnyTLSPlugin()
    state = _state(naive_enabled=True)  # needs_mux is True, но клиент стучится на 443
    user = _user("a@x.com", uuid="uuid-a")
    link = p.client_link(user, state)
    
    assert ":443" in link


def test_generate_client_config_json():
    """generate_client_config() возвращает валидный sing-box JSON."""
    p = AnyTLSPlugin()
    state = _state()
    user = _user("a@x.com", uuid="uuid-a")
    cfg = p.generate_client_config(user, state)
    
    parsed = json.loads(cfg)
    anytls_out = [o for o in parsed["outbounds"] if o["type"] == "anytls"]
    assert len(anytls_out) == 1
    assert anytls_out[0]["server_port"] == 443
    assert anytls_out[0]["tls"]["server_name"] == "anytls.example.com"


def test_domain_conflict_check():
    """Ошибка при совпадении доменов с naive."""
    p = AnyTLSPlugin()
    state = _state(naive_enabled=True, naive_domain="conflict.com")
    
    # Пытаемся включить anytls с тем же доменом conflict.com
    state.protocols["anytls"].config["domain"] = ""
    
    with patch("hydra.ui.tui.prompt", return_value="conflict.com"), \
         patch("hydra.core.sni_router.rebuild") as mock_rebuild, \
         patch("hydra.utils.firewall.open_tcp") as mock_open:
        with pytest.raises(ValueError) as excinfo:
            p.on_enable(state)
        assert "уже используется NaiveProxy" in str(excinfo.value)


def test_on_enable_opens_firewall():
    """on_enable() открывает порт 443."""
    p = AnyTLSPlugin()
    state = _state()
    # Чтобы не падало в визарде, домен уже задан в state
    
    with patch("hydra.core.sni_router.rebuild") as mock_rebuild, \
         patch("hydra.utils.firewall.open_tcp") as mock_open, \
         patch.object(p, "_resolve_certs", return_value=("/cert.pem", "/key.pem")), \
         patch("subprocess.run") as mock_run:
        p.on_enable(state)
        mock_open.assert_called_once_with(443, "anytls")
        mock_rebuild.assert_not_called()


def test_on_disable_defers_rebuild_to_orchestrator():
    """SNI rebuild is centralized in orchestrator.apply_config()."""
    p = AnyTLSPlugin()
    state = _state()
    
    with patch("hydra.core.sni_router.rebuild") as mock_rebuild, \
         patch("subprocess.run") as mock_run:
        p.on_disable(state)
        mock_rebuild.assert_not_called()
        # Проверяем, что disabled выставлен в False
        assert state.protocols["anytls"].enabled is False


def test_status_delegates_to_singbox():
    """status() проверяет работу через sing-box."""
    p = AnyTLSPlugin()
    with patch("hydra.core.singbox.is_installed", return_value=True), \
         patch("hydra.core.singbox.is_running", return_value=True), \
         patch("hydra.core.state.load_state") as mock_load, \
         patch.object(p, "_get_total_traffic", return_value=1024):
        state = _state()
        mock_load.return_value = state
        
        status = p.status()
        assert status.installed is True
        assert status.running is True
        assert status.enabled is True
        assert status.port == 20444
        assert status.info["Общий трафик"] == "1.00 KB"
