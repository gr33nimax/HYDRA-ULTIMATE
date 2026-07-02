"""tests/test_sni_router.py — Тесты для SNI-мультиплексора (HAProxy)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.core.sni_router import (
    needs_mux,
    get_effective_port,
    _generate_config,
    rebuild,
    stop,
    _INTERNAL_PORTS,
)
from hydra.core.state import AppState, PluginState


def _state(naive_enabled=False, anytls_enabled=False, naive_domain="naive.com", anytls_domain="anytls.com"):
    s = AppState()
    s.network.domain = naive_domain
    s.protocols["naive"] = PluginState(enabled=naive_enabled)
    s.protocols["anytls"] = PluginState(enabled=anytls_enabled, config={"domain": anytls_domain})
    return s


def test_needs_mux_single_plugin():
    """needs_mux() -> False когда активен 0 или 1 плагин."""
    s = _state(naive_enabled=False, anytls_enabled=False)
    assert needs_mux(s) is False

    s = _state(naive_enabled=True, anytls_enabled=False)
    assert needs_mux(s) is False

    s = _state(naive_enabled=False, anytls_enabled=True)
    assert needs_mux(s) is False


def test_needs_mux_two_plugins():
    """needs_mux() -> True когда активны оба плагина."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    assert needs_mux(s) is True


def test_get_effective_port_no_mux():
    """Если мультиплексор не нужен, оба плагина слушают порт 443 напрямую."""
    s = _state(naive_enabled=True, anytls_enabled=False)
    assert get_effective_port("naive", s) == 443
    assert get_effective_port("anytls", s) == 443


def test_get_effective_port_with_mux():
    """Если мультиплексор нужен, плагины переключаются на внутренние порты."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    assert get_effective_port("naive", s) == 10443
    assert get_effective_port("anytls", s) == 10444


def test_generate_config_two_backends():
    """Генерация конфига HAProxy для двух бэкендов."""
    backends = [
        {"name": "naive", "domain": "naive.com", "port": 10443},
        {"name": "anytls", "domain": "anytls.com", "port": 10444},
    ]
    cfg = _generate_config(backends)
    
    assert "bind *:443" in cfg
    assert "backend bk_naive" in cfg
    assert "backend bk_anytls" in cfg
    assert "server naive 127.0.0.1:10443" in cfg
    assert "server anytls 127.0.0.1:10444" in cfg


def test_config_has_sni_rules():
    """Конфиг содержит правила ssl_sni."""
    backends = [
        {"name": "naive", "domain": "naive.com", "port": 10443},
        {"name": "anytls", "domain": "anytls.com", "port": 10444},
    ]
    cfg = _generate_config(backends)
    
    assert "req_ssl_sni -i naive.com" in cfg
    assert "req_ssl_sni -i anytls.com" in cfg


def test_rebuild_starts_haproxy():
    """rebuild() генерирует конфиг и запускает службу haproxy."""
    s = _state(naive_enabled=True, anytls_enabled=True)
    
    mock_cfg = MagicMock()
    mock_cfg_dir = MagicMock()
    with patch("hydra.core.sni_router.is_installed", return_value=True), \
         patch("hydra.core.sni_router.HAPROXY_CFG", mock_cfg), \
         patch("hydra.core.sni_router.HAPROXY_CFG_DIR", mock_cfg_dir), \
         patch("subprocess.run") as mock_run, \
         patch("hydra.plugins.registry.get") as mock_registry_get:
        
        # Настраиваем mock для naive плагина, чтобы проверить, что он переконфигурируется
        mock_plugin = MagicMock()
        mock_registry_get.return_value = mock_plugin
        
        mock_run.return_value = MagicMock(returncode=0)
        
        assert rebuild(s) is True
        
        # Проверяем запись конфига
        mock_cfg.write_text.assert_called_once()
        # Проверяем, что naive плагин был настроен и применен
        mock_plugin.configure.assert_called_once_with(s)
        mock_plugin.apply.assert_called_once_with(s)
        # Проверяем, что haproxy был перезапущен
        mock_run.assert_any_call(["systemctl", "restart", "haproxy"], capture_output=True)



def test_rebuild_stops_when_single():
    """rebuild() останавливает haproxy при 0-1 активном бэкенде."""
    s = _state(naive_enabled=True, anytls_enabled=False)
    
    with patch("hydra.core.sni_router.is_installed", return_value=True), \
         patch("subprocess.run") as mock_run:
        
        mock_run.return_value = MagicMock(returncode=0)
        assert rebuild(s) is True
        
        # Проверяем, что haproxy был остановлен
        mock_run.assert_any_call(["systemctl", "stop", "haproxy"], capture_output=True)


def test_internal_ports_unique():
    """Все порты в пуле _INTERNAL_PORTS уникальны."""
    ports = list(_INTERNAL_PORTS.values())
    assert len(ports) == len(set(ports))
