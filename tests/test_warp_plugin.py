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
    assert len(frag.outbounds) == 0
    
    assert len(frag.endpoints) == 1
    assert frag.endpoints[0]["type"] == "wireguard"
    assert frag.endpoints[0]["tag"] == "warp"
    assert frag.endpoints[0]["private_key"] == "test_private_key"
    
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
    ps.config = {
        "list_targets": {
            "ext:russia": "warp"
        }
    }
    mock_load_state.return_value = mock_state

    # Мок пути кэша
    mock_file = MagicMock()
    mock_cache_path.parent = mock_file
    mock_cache_path.exists.return_value = True

    p = WarpPlugin()
    
    # Вызываем метод
    ok, msg = p.update_external_rules()
    
    assert ok is True
    assert "Обновлено списков: 1/1" in msg
    
    # Проверяем, что записан валидный JSON с нашими доменами и IP через mock_cache_path
    mock_cache_path.write_text.assert_called_once()
    written_data = json.loads(mock_cache_path.write_text.call_args[0][0])
    assert written_data["russia"]["domains"] == ["openai.com"]
    assert set(written_data["russia"]["ips"]) == {"1.1.1.1", "192.168.0.0/16"}


@patch("hydra.plugins.warp.plugin.socket.gethostbyname")
@patch("hydra.plugins.warp.plugin.WARP_PROFILES_DIR")
def test_custom_profiles(mock_profiles_dir, mock_gethostbyname, tmp_path):
    # Настраиваем временный каталог для профилей
    mock_profiles_dir.mkdir.return_value = None
    mock_profiles_dir.glob.return_value = [tmp_path / "russia.conf"]
    
    # Записываем тестовый конфиг
    conf_content = """
[Interface]
PrivateKey = my_private_key
Address = 172.16.0.2/32, 2606:4700:110::1/128
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = my_peer_public_key
Endpoint = ru0.tribukvy.ltd:4500
AllowedIPs = 0.0.0.0/0
"""
    russia_conf = tmp_path / "russia.conf"
    russia_conf.write_text(conf_content, encoding="utf-8")
    
    # Настраиваем моки
    mock_gethostbyname.return_value = "195.195.195.195"
    
    p = WarpPlugin()
    state = AppState()
    ps = state.protocols.setdefault("warp", PluginState())
    ps.config = {
        "list_targets": {
            "local:russia": "warp_russia"
        },
        "local_lists": {
            "russia": {
                "domains": ["yandex.ru"],
                "ips": ["95.0.0.0/8"]
            }
        }
    }
    
    frag = p.configure(state)
    
    assert len(frag.endpoints) == 1
    endpoint = frag.endpoints[0]
    assert endpoint["type"] == "wireguard"
    assert endpoint["tag"] == "warp_russia"
    assert endpoint["address"] == ["172.16.0.2/32", "2606:4700:110::1/128"]
    assert endpoint["private_key"] == "my_private_key"
    assert endpoint["mtu"] == 1280
    assert endpoint["amnezia"]["jc"] == 4
    assert endpoint["amnezia"]["jmin"] == 40
    assert endpoint["amnezia"]["jmax"] == 70
    assert endpoint["amnezia"]["s1"] == 0
    assert endpoint["amnezia"]["s2"] == 0
    assert endpoint["amnezia"]["h1"] == 1
    assert endpoint["amnezia"]["h2"] == 2
    assert endpoint["amnezia"]["h3"] == 3
    assert endpoint["amnezia"]["h4"] == 4
    
    # Должен содержать один peer
    assert len(endpoint["peers"]) == 1
    peer = endpoint["peers"][0]
    assert peer["address"] == "195.195.195.195"
    assert peer["port"] == 4500
    assert peer["public_key"] == "my_peer_public_key"
    
    # Должно быть 2 правила маршрутизации
    assert len(frag.route_rules) == 2
    domain_rule = next(r for r in frag.route_rules if "domain" in r)
    assert domain_rule["domain"] == ["yandex.ru"]
    assert domain_rule["outbound"] == "warp_russia"
    
    ip_rule = next(r for r in frag.route_rules if "ip_cidr" in r)
    assert ip_rule["ip_cidr"] == ["95.0.0.0/8"]
    assert ip_rule["outbound"] == "warp_russia"
