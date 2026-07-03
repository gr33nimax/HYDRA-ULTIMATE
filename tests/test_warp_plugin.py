"""tests/test_warp_plugin.py — Тесты для плагина Cloudflare WARP."""
from pathlib import Path
import sys
from unittest.mock import patch, MagicMock
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.warp.plugin import WarpPlugin, WGCF_PROFILE, WARP_EXTERNAL_CACHE
from hydra.core.state import AppState, PluginState


def test_is_ip_or_cidr():
    assert WarpPlugin._is_ip_or_cidr("1.1.1.1") is True
    assert WarpPlugin._is_ip_or_cidr("192.168.1.0/24") is True
    assert WarpPlugin._is_ip_or_cidr("2001:db8::/32") is True
    assert WarpPlugin._is_ip_or_cidr("google.com") is False
    assert WarpPlugin._is_ip_or_cidr("1.2.3.256") is False


def test_is_valid_domain():
    assert WarpPlugin._is_valid_domain("google.com") is True
    assert WarpPlugin._is_valid_domain("openai.com") is True
    assert WarpPlugin._is_valid_domain(".claude.ai") is True
    assert WarpPlugin._is_valid_domain("invalid_domain") is False
    assert WarpPlugin._is_valid_domain("http://google.com") is False


@patch("hydra.plugins.warp.plugin.WarpPlugin._load_warp_config")
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_configure(mock_cache, mock_load_config):
    mock_load_config.return_value = {
        "private_key": "test_private_key",
        "addresses": ["172.16.0.2/32"]
    }
    
    # Мокаем существование кэша внешних правил (не существует для базового теста)
    mock_cache.exists.return_value = False

    p = WarpPlugin()
    state = AppState()
    
    # 1. Тест с дефолтными настройками
    frag = p.configure(state)
    assert len(frag.outbounds) == 1
    assert frag.outbounds[0]["type"] == "wireguard"
    assert frag.outbounds[0]["tag"] == "warp"
    assert frag.outbounds[0]["private_key"] == "test_private_key"
    
    # Дефолтные домены должны быть в правилах
    assert len(frag.route_rules) == 1
    assert "domain" in frag.route_rules[0]
    assert "openai.com" in frag.route_rules[0]["domain"]
    assert frag.route_rules[0]["outbound"] == "warp"

    # 2. Тест с кастомными доменами и IP из state
    ps = state.protocols.setdefault("warp", PluginState())
    ps.config = {
        "domains": ["mycustomdomain.org"],
        "ips": ["8.8.8.8", "1.1.1.1/32"]
    }
    
    frag = p.configure(state)
    assert len(frag.route_rules) == 2
    
    # Правило доменов
    domain_rule = next(r for r in frag.route_rules if "domain" in r)
    assert domain_rule["domain"] == ["mycustomdomain.org"]
    
    # Правило IP
    ip_rule = next(r for r in frag.route_rules if "ip_cidr" in r)
    assert set(ip_rule["ip_cidr"]) == {"8.8.8.8", "1.1.1.1/32"}


@patch("urllib.request.urlopen")
@patch("hydra.core.state.load_state")
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_update_external_rules(mock_cache_path, mock_load_state, mock_urlopen):
    # Мок ответа сервера
    mock_response = MagicMock()
    mock_response.read.return_value = b"""# Comments
openai.com
1.1.1.1
// Another comment
192.168.0.0/16
invalid_domain_name
"""
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # Мок состояния
    mock_state = AppState()
    ps = mock_state.protocols.setdefault("warp", PluginState())
    ps.config = {"external_url": "https://example.com/rules.txt"}
    mock_load_state.return_value = mock_state

    # Мок пути кэша
    mock_file = MagicMock()
    mock_cache_path.parent = mock_file
    mock_cache_path.exists.return_value = True

    p = WarpPlugin()
    
    # Вызываем метод
    ok, msg = p.update_external_rules()
    
    assert ok is True
    assert "Успешно загружено: 1 доменов, 2 IP" in msg
    
    # Проверяем, что записан валидный JSON с нашими доменами и IP через mock_cache_path
    mock_cache_path.write_text.assert_called_once()
    written_data = json.loads(mock_cache_path.write_text.call_args[0][0])
    assert written_data["domains"] == ["openai.com"]
    assert set(written_data["ips"]) == {"1.1.1.1", "192.168.0.0/16"}
