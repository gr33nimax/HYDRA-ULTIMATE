"""tests/test_warp_plugin.py — Тесты для плагина Cloudflare WARP."""

import copy
from datetime import datetime
from pathlib import Path
from typing import cast
import sys
from unittest.mock import patch, MagicMock
import json
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.core.singbox_config import generate_config
from hydra.plugins.warp import observation, parsing
from hydra.plugins.warp.plugin import WarpPlugin, WARP_EXTERNAL_CACHE
from hydra.core.state import AppState, PluginState


def test_rules_cache_without_an_enabled_source_is_due(tmp_path):
    cache = tmp_path / "warp_external.json"
    cache.write_text(
        json.dumps(
            {
                "russia": {"domains": [], "ips": []},
                "updated_at": datetime.now().isoformat(),
            },
        ),
        encoding="utf-8",
    )

    assert observation.external_rules_update_due(cache, enabled_keys=("russia",)) is False
    assert observation.external_rules_update_due(cache, enabled_keys=("refilter",)) is True


def test_due_query_sees_sources_missing_from_the_cache(tmp_path):
    cache = tmp_path / "warp_external.json"
    cache.write_text(
        json.dumps({"updated_at": datetime.now().isoformat()}),
        encoding="utf-8",
    )
    state = AppState(
        protocols={
            "warp": PluginState(
                config={"list_targets": {"ext:refilter": "warp"}},
            ),
        },
    )

    with patch("hydra.plugins.warp.maintenance.WARP_EXTERNAL_CACHE", cache):
        assert WarpPlugin.external_rules_update_due(state=state) is True
        assert WarpPlugin.external_rules_update_due() is False


def test_runtime_actions_are_declared_public_capabilities():
    assert set(WarpPlugin.meta.capabilities.actions) == {
        "delete_local_profile",
        "update_external_rules",
        "register_masque_scanner",
        "scan_masque_endpoints",
    }
    assert "set_masque_endpoint" in WarpPlugin.meta.capabilities.commands


def test_manager_observation_and_profile_deletion_are_plugin_owned(tmp_path):
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    profile = profiles_dir / "russia.conf"
    profile.write_text(
        "[Interface]\nS1 = 0\nH4 = 300\n",
        encoding="utf-8",
    )
    with patch("hydra.plugins.warp.plugin.WARP_PROFILES_DIR", profiles_dir):
        observation = WarpPlugin.manager_observation()
        assert observation["profiles"] == [
            {
                "name": "russia",
                "is_amnezia": True,
                "h4_warning": True,
            },
        ]
        assert WarpPlugin.delete_local_profile(name="russia") is True

    assert not profile.exists()


def test_uninstall_removes_the_legacy_wgcf_artifacts(tmp_path):
    binary = tmp_path / "wgcf"
    profile = tmp_path / "wgcf-profile.conf"
    account = tmp_path / "wgcf-account.toml"
    install_log = tmp_path / "warp_install.log"
    for path in (binary, profile, account, install_log):
        path.write_text("x", encoding="utf-8")
    cache = tmp_path / "warp_external.json"
    cache.write_text("{}", encoding="utf-8")

    with (
        patch(
            "hydra.plugins.warp.plugin.LEGACY_WGCF_PATHS",
            (binary, profile, account, install_log),
        ),
        patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE", cache),
    ):
        assert WarpPlugin().uninstall() is True

    assert not any(path.exists() for path in (binary, profile, account, install_log))
    assert cache.exists()  # reinstall must retain selected external rules


def test_is_ip_or_cidr():
    assert parsing.is_ip_or_cidr("1.1.1.1") is True
    assert parsing.is_ip_or_cidr("192.168.1.0/24") is True
    assert parsing.is_ip_or_cidr("2001:db8::/32") is True
    assert parsing.is_ip_or_cidr("google.com") is False
    assert parsing.is_ip_or_cidr("1.2.3.256") is False


def test_is_valid_domain():
    assert parsing.is_valid_domain("google.com") is True
    assert parsing.is_valid_domain("openai.com") is True
    assert parsing.is_valid_domain(".claude.ai") is True
    assert parsing.is_valid_domain(".ru") is True
    assert parsing.is_valid_domain(".su") is True
    assert parsing.is_valid_domain(".рф") is True
    assert parsing.is_valid_domain(".xn--p1ai") is True
    assert parsing.is_valid_domain("invalid_domain") is False
    assert parsing.is_valid_domain("http://google.com") is False


def test_install_does_not_erase_cached_selected_routes(tmp_path):
    cache = tmp_path / "warp_external.json"
    cache.write_text('{"youtube": {"domains": ["youtube.com"], "ips": []}}', encoding="utf-8")
    with (
        patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE", cache),
        patch("hydra.plugins.warp.plugin.catalog.refresh_due", return_value=False),
    ):
        assert WarpPlugin().install() is True
    assert json.loads(cache.read_text(encoding="utf-8"))["youtube"]["domains"] == ["youtube.com"]


def test_install_preloads_all_external_lists():
    plugin = WarpPlugin()
    with patch.object(
        plugin,
        "preload_external_rules",
        return_value=(True, "ok"),
    ) as preload:
        assert plugin.install() is True
    preload.assert_called_once_with()


def test_install_survives_external_list_preload_failure():
    plugin = WarpPlugin()
    with patch.object(
        plugin,
        "preload_external_rules",
        return_value=(False, "github timeout"),
    ) as preload:
        assert plugin.install() is True
    preload.assert_called_once_with()


@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_configure(mock_cache):
    # Мокаем существование кэша внешних правил (не существует для базового теста)
    mock_cache.exists.return_value = False

    p = WarpPlugin()
    state = AppState()

    # 1. Тест с дефолтными настройками
    frag = p.configure(state)
    assert frag.endpoints == []
    assert frag.outbounds == [
        {"type": "masque", "tag": "warp_masque"},
        {"type": "selector", "tag": "warp", "outbounds": ["warp_masque"]},
    ]
    # Дефолтные домены должны быть в правилах
    assert len(frag.route_rules) == 1
    assert "domain_suffix" in frag.route_rules[0]
    default_suffixes = frag.route_rules[0]["domain_suffix"]
    assert isinstance(default_suffixes, list)
    assert "openai.com" in default_suffixes
    assert frag.route_rules[0]["outbound"] == "warp"

    # 2. Тест с кастомными доменами и IP из state
    ps = state.protocols.setdefault("warp", PluginState())
    ps.config = {"domains": ["mycustomdomain.org"], "ips": ["8.8.8.8", "1.1.1.1/32"]}

    frag = p.configure(state)
    assert len(frag.route_rules) == 2

    # Правило доменов
    domain_rule = next(r for r in frag.route_rules if "domain_suffix" in r)
    assert domain_rule["domain_suffix"] == ["mycustomdomain.org"]

    # Правило IP
    ip_rule = next(r for r in frag.route_rules if "ip_cidr" in r)
    ip_cidrs = ip_rule["ip_cidr"]
    assert isinstance(ip_cidrs, list)
    assert set(ip_cidrs) == {"8.8.8.8", "1.1.1.1/32"}


@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_configure_normalizes_legacy_settings_without_mutating_state(
    cache,
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

    with pytest.raises(ValueError, match="russia.*cache"):
        WarpPlugin().configure(state)

    assert state == before


@patch("hydra.plugins.warp.plugin.catalog.refresh_due", return_value=False)
@patch("urllib.request.urlopen")
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
@patch("hydra.plugins.warp.plugin.HOST")
def test_update_external_rules(mock_host, mock_cache_path, mock_urlopen, _refresh):
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
    ps.config = {"list_targets": {"ext:youtube": "warp"}}
    # Мок пути кэша
    mock_file = MagicMock()
    mock_cache_path.parent = mock_file
    mock_cache_path.exists.return_value = True

    p = WarpPlugin()

    # Вызываем метод
    with patch(
        "hydra.plugins.warp.plugin.catalog.load_sources",
        return_value={"youtube": {"name": "YouTube", "url": "https://example.test/youtube.txt"}},
    ):
        ok, msg = p.update_external_rules(mock_state)

    assert ok is True
    assert "Обновлено списков: 1/1" in msg

    # Проверяем, что записан валидный JSON с нашими доменами и IP через mock_cache_path
    mock_host.atomic_write.assert_called_once()
    written_data = json.loads(mock_host.atomic_write.call_args.args[1])
    assert written_data["youtube"]["domains"] == ["openai.com"]
    assert set(written_data["youtube"]["ips"]) == {"1.1.1.1", "192.168.0.0/16"}
    assert written_data["updated_at"] == written_data["last_attempt_at"]


@patch("hydra.plugins.warp.plugin.catalog.refresh_due", return_value=False)
@patch("urllib.request.urlopen")
@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
@patch("hydra.plugins.warp.plugin.HOST")
def test_partial_external_update_is_not_marked_fresh(mock_host, mock_cache, urlopen, _refresh):
    state = AppState()
    state.protocols["warp"] = PluginState(
        config={
            "list_targets": {"ext:youtube": "warp", "ext:netflix": "warp"},
        }
    )
    mock_cache.exists.return_value = False

    response = MagicMock()
    response.read.return_value = b"openai.com\n"
    response.__enter__.return_value = response
    urlopen.side_effect = [response, OSError("temporary failure")]

    with patch(
        "hydra.plugins.warp.plugin.catalog.load_sources",
        return_value={
            "youtube": {"name": "YouTube", "url": "https://example.test/youtube.txt"},
            "netflix": {"name": "Netflix", "url": "https://example.test/netflix.txt"},
        },
    ):
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
        "list_targets": {"local:russia": "warp_russia"},
        "local_lists": {"russia": {"domains": ["yandex.ru"], "ips": ["95.0.0.0/8"]}},
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
    amnezia = endpoint["amnezia"]
    assert isinstance(amnezia, dict)
    assert amnezia["jc"] == 4
    assert amnezia["jmin"] == 40
    assert amnezia["jmax"] == 70
    assert amnezia["s1"] == 0
    assert amnezia["s2"] == 0
    assert amnezia["h1"] == 1
    assert amnezia["h2"] == 2
    assert amnezia["h3"] == 3
    assert amnezia["h4"] == 4
    assert amnezia["i1"] == "test_i1_value"

    # Должен содержать один peer
    peers = endpoint["peers"]
    assert isinstance(peers, list)
    assert len(peers) == 1
    peer = peers[0]
    assert isinstance(peer, dict)
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


def test_specific_direct_route_precedes_overlapping_warp_route():
    from hydra.plugins.warp.configuration import render_route_rules
    from hydra.plugins.warp.parsing import is_ip_or_cidr, is_valid_domain

    rules = render_route_rules(
        {
            "list_targets": {"local:broad": "warp", "local:specific": "direct"},
            "local_lists": {
                "broad": {"domains": ["example.com"], "ips": ["10.0.0.0/8"]},
                "specific": {"domains": ["app.example.com"], "ips": ["10.0.0.1/32"]},
            },
        },
        {},
        {"direct", "warp"},
        russia_suffixes=[],
        validate_domain=is_valid_domain,
        validate_ip=is_ip_or_cidr,
    )
    assert next(i for i, rule in enumerate(rules) if "app.example.com" in rule.get("domain_suffix", [])) < next(
        i for i, rule in enumerate(rules) if "example.com" in rule.get("domain_suffix", [])
    )
    assert next(i for i, rule in enumerate(rules) if "10.0.0.1/32" in rule.get("ip_cidr", [])) < next(
        i for i, rule in enumerate(rules) if "10.0.0.0/8" in rule.get("ip_cidr", [])
    )


def test_same_domain_with_direct_and_warp_routes_prioritizes_direct():
    from hydra.plugins.warp.configuration import render_route_rules
    from hydra.plugins.warp.parsing import is_ip_or_cidr, is_valid_domain

    rules = render_route_rules(
        {
            "list_targets": {"local:proxy": "warp", "local:exclude": "direct"},
            "local_lists": {
                "proxy": {"domains": ["example.com"], "ips": []},
                "exclude": {"domains": ["example.com"], "ips": []},
            },
        },
        {},
        {"direct", "warp"},
        russia_suffixes=[],
        validate_domain=is_valid_domain,
        validate_ip=is_ip_or_cidr,
    )
    assert rules == [
        {"domain_suffix": ["example.com"], "outbound": "direct"},
        {"domain_suffix": ["example.com"], "outbound": "warp"},
    ]


def test_enabled_external_source_missing_from_cache_rejects_config(tmp_path):
    from hydra.plugins.warp.configuration import configure_warp
    from hydra.plugins.warp.parsing import is_ip_or_cidr, is_valid_domain, parse_endpoint, parse_wg_conf

    state = AppState(protocols={"warp": PluginState(enabled=True, config={"list_targets": {"ext:youtube": "warp"}})})
    with pytest.raises(ValueError, match="youtube.*cache"):
        configure_warp(
            state,
            profiles_dir=tmp_path,
            external_cache=tmp_path / "missing.json",
            default_domains=[],
            russia_suffixes=[],
            parse_config=parse_wg_conf,
            parse_endpoint=parse_endpoint,
            validate_domain=is_valid_domain,
            validate_ip=is_ip_or_cidr,
            resolve_host=lambda value: value,
        )


@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_direct_rules_are_not_dropped(mock_cache):
    mock_cache.exists.return_value = False
    state = AppState()
    state.protocols["warp"] = PluginState(
        config={
            "local_lists": {"bypass": {"domains": ["Example.COM"], "ips": []}},
            "list_targets": {"local:bypass": "direct"},
        }
    )

    fragment = WarpPlugin().configure(state)

    assert fragment.outbounds == []
    assert fragment.route_rules == [{"domain_suffix": ["example.com"], "outbound": "direct"}]


@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_removed_aggregate_route_is_rejected(mock_cache):
    mock_cache.exists.return_value = False
    state = AppState()
    state.protocols["warp"] = PluginState(
        config={
            "list_targets": {"ext:category-ai": "direct"},
        }
    )

    with pytest.raises(ValueError, match="category-ai.*no longer supported"):
        WarpPlugin().configure(state)


def test_existing_russian_category_route_renders_with_cached_source(tmp_path):
    cache = tmp_path / "warp_external.json"
    cache.write_text(json.dumps({"category-ru": {"domains": ["yandex.ru"], "ips": []}}), encoding="utf-8")
    state = AppState(
        protocols={
            "warp": PluginState(
                enabled=True,
                config={"list_targets": {"ext:category-ru": "direct"}},
            )
        }
    )
    with (
        patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE", cache),
        patch("hydra.plugins.warp.plugin.WARP_PROFILES_DIR", tmp_path / "profiles"),
    ):
        fragment = WarpPlugin().configure(state)
    assert fragment.outbounds == []
    suffixes = {
        suffix
        for rule in fragment.route_rules
        if rule["outbound"] == "direct"
        for suffix in cast(list[str], rule.get("domain_suffix") or [])
    }
    assert {"yandex.ru", ".ru", ".su", ".рф", ".xn--p1ai"} <= suffixes


@patch("hydra.plugins.warp.plugin.WARP_EXTERNAL_CACHE")
def test_configure_rejects_route_to_missing_relay_outbound(mock_cache):
    mock_cache.exists.return_value = False
    state = AppState()
    state.protocols["warp"] = PluginState(
        enabled=True,
        config={
            "local_lists": {
                "google": {"domains": ["gemini.google.com"], "ips": []},
            },
            "list_targets": {"local:google": "warp_finland"},
        },
    )

    with pytest.raises(
        ValueError,
        match=r"local:google.*warp_finland.*not configured",
    ):
        WarpPlugin().configure(state)


def test_parse_endpoint_supports_ipv6_and_rejects_invalid_ports():
    assert parsing.parse_endpoint("[2001:db8::1]:2408") == ("2001:db8::1", 2408)
    assert parsing.parse_endpoint("host.example:0") is None
    assert parsing.parse_endpoint("host.example:not-a-port") is None


def test_wireguard_parser_ignores_unknown_sections_and_requires_keys():
    plugin = WarpPlugin()
    assert parsing.parse_wg_conf("[Unknown]\nFoo = bar") is None
    assert parsing.parse_wg_conf("[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = host:1") is None


def test_enabled_warp_keeps_the_device_profile_in_the_core_cache():
    state = AppState(protocols={"warp": PluginState(enabled=True)})

    config = generate_config(state, {})

    assert config["experimental"]["cache_file"] == {
        "enabled": True,
        "store_masque_config": True,
    }


def test_disabled_warp_does_not_ask_for_the_core_cache():
    state = AppState(protocols={"warp": PluginState(enabled=False)})

    config = generate_config(state, {})

    assert "experimental" not in config


def test_wireguard_parser_preserves_repeated_ipv4_and_ipv6_lines():
    parsed = parsing.parse_wg_conf(
        "[Interface]\nPrivateKey = private\n"
        "Address = 172.16.0.2/32\nAddress = 2606:4700:110::2/128\n"
        "[Peer]\nPublicKey = public\nEndpoint = engage.cloudflareclient.com:2408\n"
        "AllowedIPs = 0.0.0.0/0\nAllowedIPs = ::/0\n"
    )

    assert parsed is not None
    assert parsed["interface"]["address"] == "172.16.0.2/32, 2606:4700:110::2/128"
    assert parsed["peer"]["allowedips"] == "0.0.0.0/0, ::/0"
