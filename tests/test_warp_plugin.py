"""tests/test_warp_plugin.py — Тесты для плагина Cloudflare WARP."""
import copy
from pathlib import Path
import sys
from unittest.mock import patch, MagicMock
import json
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.plugins.warp.plugin import WarpPlugin, WGCF_PROFILE, WARP_EXTERNAL_CACHE
from hydra.core.state import AppState, PluginState


def test_runtime_actions_are_declared_public_capabilities():
    assert set(WarpPlugin.meta.capabilities.actions) == {
        "delete_local_profile",
        "recreate_local_profile",
        "remove_local_profile",
        "restore_local_profile",
        "snapshot_local_profile",
        "update_external_rules",
    }


def test_manager_observation_and_profile_deletion_are_plugin_owned(tmp_path):
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    profile = profiles_dir / "russia.conf"
    profile.write_text(
        "[Interface]\nS1 = 0\nH4 = 300\n",
        encoding="utf-8",
    )
    default_profile = tmp_path / "wgcf-profile.conf"
    default_profile.write_text("[Interface]\n", encoding="utf-8")

    with (
        patch("hydra.plugins.warp.plugin.WARP_PROFILES_DIR", profiles_dir),
        patch("hydra.plugins.warp.plugin.WGCF_PROFILE", default_profile),
    ):
        observation = WarpPlugin.manager_observation()
        assert observation["default_profile_exists"] is True
        assert observation["profiles"] == [
            {
                "name": "russia",
                "is_amnezia": True,
                "h4_warning": True,
            },
        ]
        assert WarpPlugin.delete_local_profile(name="russia") is True

    assert not profile.exists()


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
    assert WarpPlugin._is_valid_domain(".ru") is True
    assert WarpPlugin._is_valid_domain(".su") is True
    assert WarpPlugin._is_valid_domain(".рф") is True
    assert WarpPlugin._is_valid_domain(".xn--p1ai") is True
    assert WarpPlugin._is_valid_domain("invalid_domain") is False
    assert WarpPlugin._is_valid_domain("http://google.com") is False


def test_install_preloads_all_external_lists_when_profile_exists():
    plugin = WarpPlugin()
    with patch("hydra.plugins.warp.plugin.WGCF_PROFILE") as profile, \
         patch("hydra.plugins.warp.plugin.WGCF_BIN") as binary, \
         patch.object(plugin, "preload_external_rules", return_value=(True, "ok")) as preload:
        profile.exists.return_value = True
        binary.exists.return_value = True
        assert plugin.install() is True
    preload.assert_called_once_with()


def test_install_keeps_valid_profile_when_external_list_preload_fails(tmp_path):
    plugin = WarpPlugin()
    log_path = tmp_path / "warp_install.log"
    with (
        patch("hydra.plugins.warp.plugin.WGCF_PROFILE") as profile,
        patch("hydra.plugins.warp.plugin.WGCF_BIN") as binary,
        patch("hydra.plugins.warp.plugin.runtime.install", return_value=True),
        patch.object(
            plugin,
            "preload_external_rules",
            return_value=(False, "github timeout"),
        ),
        patch("hydra.plugins.warp.plugin.WARP_INSTALL_LOG", log_path),
    ):
        profile.exists.return_value = False
        binary.exists.return_value = False
        assert plugin.install() is True

    assert "github timeout" in log_path.read_text(encoding="utf-8")


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
    assert frag.outbounds[0] == {"type": "selector", "tag": "warp", "outbounds": ["warp_ep"]}
    
    assert len(frag.endpoints) == 1
    assert frag.endpoints[0]["type"] == "wireguard"
    assert frag.endpoints[0]["tag"] == "warp_ep"
    assert frag.endpoints[0]["private_key"] == "test_private_key"
    
    # Дефолтные домены должны быть в правилах
    assert len(frag.route_rules) == 1
    assert "domain_suffix" in frag.route_rules[0]
    assert "openai.com" in frag.route_rules[0]["domain_suffix"]
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
    domain_rule = next(r for r in frag.route_rules if "domain_suffix" in r)
    assert domain_rule["domain_suffix"] == ["mycustomdomain.org"]
    
    # Правило IP
    ip_rule = next(r for r in frag.route_rules if "ip_cidr" in r)
    assert set(ip_rule["ip_cidr"]) == {"8.8.8.8", "1.1.1.1/32"}


@patch(
    "hydra.plugins.warp.plugin.WarpPlugin._load_warp_config",
    return_value={
        "private_key": "private",
        "addresses": ["172.16.0.2/32"],
    },
)
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_configure_normalizes_legacy_settings_without_mutating_state(
    cache,
    _load_config,
):
    cache.exists.return_value = False
    state = AppState(
        protocols={
            "warp": PluginState(
                enabled=True,
                config={
                    "domains": ["example.com"],
                    "enabled_external_lists": ["russia"],
                },
            ),
        },
    )
    before = copy.deepcopy(state)

    WarpPlugin().configure(state)

    assert state == before


@patch("urllib.request.urlopen")
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
@patch("hydra.plugins.warp.plugin.HOST")
def test_update_external_rules(mock_host, mock_cache_path, mock_urlopen):
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
    # Мок пути кэша
    mock_file = MagicMock()
    mock_cache_path.parent = mock_file
    mock_cache_path.exists.return_value = True

    p = WarpPlugin()
    
    # Вызываем метод
    ok, msg = p.update_external_rules(mock_state)
    
    assert ok is True
    assert "Обновлено списков: 1/1" in msg
    
    # Проверяем, что записан валидный JSON с нашими доменами и IP через mock_cache_path
    mock_host.atomic_write.assert_called_once()
    written_data = json.loads(mock_host.atomic_write.call_args.args[1])
    assert written_data["russia"]["domains"] == ["openai.com"]
    assert set(written_data["russia"]["ips"]) == {"1.1.1.1", "192.168.0.0/16"}
    assert written_data["updated_at"] == written_data["last_attempt_at"]


@patch("urllib.request.urlopen")
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
@patch("hydra.plugins.warp.plugin.HOST")
def test_partial_external_update_is_not_marked_fresh(mock_host, mock_cache, urlopen):
    state = AppState()
    state.protocols["warp"] = PluginState(config={
        "list_targets": {"ext:russia": "warp", "ext:geoblock": "warp"},
    })
    mock_cache.exists.return_value = False

    response = MagicMock()
    response.read.return_value = b"openai.com\n"
    response.__enter__.return_value = response
    urlopen.side_effect = [response, OSError("temporary failure")]

    ok, _ = WarpPlugin().update_external_rules(state)

    assert ok is False
    written = json.loads(mock_host.atomic_write.call_args.args[1])
    assert "last_attempt_at" in written
    assert "updated_at" not in written


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
I1 = test_i1_value

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
    
    assert len(frag.outbounds) == 1
    assert frag.outbounds[0] == {"type": "selector", "tag": "warp_russia", "outbounds": ["warp_russia_ep"]}
    
    assert len(frag.endpoints) == 1
    endpoint = frag.endpoints[0]
    assert endpoint["type"] == "wireguard"
    assert endpoint["tag"] == "warp_russia_ep"
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
    assert endpoint["amnezia"]["i1"] == "test_i1_value"
    
    # Должен содержать один peer
    assert len(endpoint["peers"]) == 1
    peer = endpoint["peers"][0]
    assert peer["address"] == "195.195.195.195"
    assert peer["port"] == 4500
    assert peer["public_key"] == "my_peer_public_key"
    
    # Должно быть 2 правила маршрутизации
    assert len(frag.route_rules) == 2
    domain_rule = next(r for r in frag.route_rules if "domain_suffix" in r)
    assert domain_rule["domain_suffix"] == ["yandex.ru"]
    assert domain_rule["outbound"] == "warp_russia"
    
    ip_rule = next(r for r in frag.route_rules if "ip_cidr" in r)
    assert ip_rule["ip_cidr"] == ["95.0.0.0/8"]
    assert ip_rule["outbound"] == "warp_russia"


@patch("hydra.plugins.warp.plugin.WarpPlugin._load_warp_config", return_value=None)
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_direct_rules_are_not_dropped(mock_cache, _mock_profile):
    mock_cache.exists.return_value = False
    state = AppState()
    state.protocols["warp"] = PluginState(config={
        "local_lists": {"bypass": {"domains": ["Example.COM"], "ips": []}},
        "list_targets": {"local:bypass": "direct"},
    })

    fragment = WarpPlugin().configure(state)

    assert fragment.outbounds == []
    assert fragment.route_rules == [{"domain_suffix": ["example.com"], "outbound": "direct"}]


@patch("hydra.plugins.warp.plugin.WarpPlugin._load_warp_config", return_value=None)
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_russia_external_list_always_includes_all_russian_tlds(mock_cache, _mock_profile):
    mock_cache.exists.return_value = False
    state = AppState()
    state.protocols["warp"] = PluginState(config={
        "list_targets": {"ext:russia": "direct"},
    })

    fragment = WarpPlugin().configure(state)

    assert fragment.route_rules == [{
        "domain_suffix": [".ru", ".su", ".xn--p1ai", ".рф"],
        "outbound": "direct",
    }]


@patch("hydra.plugins.warp.plugin.WarpPlugin._load_warp_config", return_value=None)
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_configure_rejects_route_to_missing_warp_outbound(mock_cache, _mock_profile):
    mock_cache.exists.return_value = False
    state = AppState()
    state.protocols["warp"] = PluginState(
        enabled=True,
        config={
            "local_lists": {
                "google": {"domains": ["gemini.google.com"], "ips": []},
            },
            "list_targets": {"local:google": "warp"},
        },
    )

    with pytest.raises(
        ValueError,
        match=r"local:google.*warp.*not configured",
    ):
        WarpPlugin().configure(state)


def test_parse_endpoint_supports_ipv6_and_rejects_invalid_ports():
    assert WarpPlugin._parse_endpoint("[2001:db8::1]:2408") == ("2001:db8::1", 2408)
    assert WarpPlugin._parse_endpoint("host.example:0") is None
    assert WarpPlugin._parse_endpoint("host.example:not-a-port") is None


def test_wireguard_parser_ignores_unknown_sections_and_requires_keys():
    plugin = WarpPlugin()
    assert plugin._parse_wg_conf("[Unknown]\nFoo = bar") is None
    assert plugin._parse_wg_conf("[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = host:1") is None


def test_wireguard_parser_preserves_repeated_ipv4_and_ipv6_lines():
    parsed = WarpPlugin()._parse_wg_conf(
        "[Interface]\nPrivateKey = private\n"
        "Address = 172.16.0.2/32\nAddress = 2606:4700:110::2/128\n"
        "[Peer]\nPublicKey = public\nEndpoint = engage.cloudflareclient.com:2408\n"
        "AllowedIPs = 0.0.0.0/0\nAllowedIPs = ::/0\n"
    )

    assert parsed["interface"]["address"] == "172.16.0.2/32, 2606:4700:110::2/128"
    assert parsed["peer"]["allowedips"] == "0.0.0.0/0, ::/0"


def test_load_wgcf_profile_uses_peer_values(tmp_path):
    profile = tmp_path / "wgcf-profile.conf"
    profile.write_text(
        "[Interface]\nPrivateKey = private\nAddress = 172.16.0.2/32\nMTU = 1320\n"
        "[Peer]\nPublicKey = current-public\nEndpoint = [2001:db8::1]:2408\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n",
        encoding="utf-8",
    )

    with patch("hydra.plugins.warp.plugin.WGCF_PROFILE", profile):
        loaded = WarpPlugin()._load_warp_config()

    assert loaded == {
        "private_key": "private",
        "addresses": ["172.16.0.2/32"],
        "endpoint": "[2001:db8::1]:2408",
        "public_key": "current-public",
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "mtu": "1320",
    }


def test_restore_local_profile_restores_both_credentials(tmp_path):
    profile = tmp_path / "wgcf-profile.conf"
    account = tmp_path / "wgcf-account.toml"
    profile.write_bytes(b"old-profile")
    account.write_bytes(b"old-account")

    with (
        patch("hydra.plugins.warp.plugin.WGCF_PROFILE", profile),
        patch("hydra.plugins.warp.plugin.WGCF_ACCOUNT", account),
        patch("hydra.plugins.warp.plugin.HOST") as host,
    ):
        snapshot = WarpPlugin.snapshot_local_profile()
        profile.write_bytes(b"new-profile")
        account.write_bytes(b"new-account")
        WarpPlugin.restore_local_profile(snapshot)

    assert host.atomic_write.call_args_list[0].args[1] == b"old-profile"
    assert host.atomic_write.call_args_list[1].args[1] == b"old-account"
