import base64
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from hydra.core.state import AppState, PluginState
from hydra.plugins.warp.clash_import import (
    ClashImportError, discover_warp_yaml_sources, import_clash_warp_bundle,
    load_or_refresh_warp_bundle,
)
from hydra.plugins.warp.plugin import WarpPlugin


PRIVATE_KEY = base64.b64encode(b"p" * 32).decode()
PUBLIC_KEY = base64.b64encode(b"P" * 32).decode()


def _yaml() -> str:
    return f"""
warp-common: &warp-common
  type: wireguard
  ip: 172.16.0.2
  private-key: {PRIVATE_KEY}
  public-key: {PUBLIC_KEY}
  allowed-ips: [0.0.0.0/0, '::/0']
  mtu: 1280
  amnezia-wg-option:
    jc: 4
    jmin: 40
    jmax: 70
    s1: 0
    i1: <b 0x0102>
proxies:
  - name: Netherlands
    <<: *warp-common
    server: nl.example.com
    port: 4500
    reserved: [1, 2, 3]
  - name: Unsupported MASQUE
    type: masque
    server: 192.0.2.1
    port: 443
"""


def test_import_clash_bundle_and_generate_groups(tmp_path):
    source = tmp_path / "ultimate.yaml"
    destination = tmp_path / "ultimate.json"
    source.write_text(_yaml(), encoding="utf-8")

    bundle = import_clash_warp_bundle(source, destination)
    assert len(bundle["endpoints"]) == 1
    assert bundle["skipped_unsupported"] == 1
    assert bundle["warnings"] == []
    imported = bundle["endpoints"][0]
    assert imported["name"] == "Netherlands"
    assert imported["peer"]["reserved"] == [1, 2, 3]
    assert imported["amnezia"]["i1"] == "<b 0x0102>"

    profiles = tmp_path / "profiles"
    profiles.mkdir()
    state = AppState()
    state.protocols["warp"] = PluginState(
        enabled=True,
        config={
            "local_lists": {"test": {"domains": ["example.org"], "ips": []}},
            "list_targets": {"local:test": imported["tag"]},
        },
    )
    with (
        patch("hydra.plugins.warp.plugin.WARP_ULTIMATE_BUNDLE", destination),
        patch("hydra.plugins.warp.plugin.WARP_PROFILES_DIR", profiles),
        patch.object(WarpPlugin, "_load_warp_config", return_value=None),
        patch.object(WarpPlugin, "_resolve_endpoint_host", return_value="192.0.2.10"),
    ):
        fragment = WarpPlugin().configure(state)

    assert fragment.endpoints[0]["peers"][0]["address"] == "192.0.2.10"
    assert fragment.endpoints[0]["peers"][0]["reserved"] == [1, 2, 3]
    assert any(item["tag"] == "warp_ultimate" for item in fragment.outbounds)
    assert fragment.route_rules[0]["outbound"] == imported["tag"]


def test_import_rejects_invalid_key_without_replacing_bundle(tmp_path):
    source = tmp_path / "bad.yaml"
    destination = tmp_path / "ultimate.json"
    destination.write_text('{"old": true}', encoding="utf-8")
    source.write_text(_yaml().replace(PRIVATE_KEY, "not-base64"), encoding="utf-8")

    with pytest.raises(ClashImportError, match="импорт отменён"):
        import_clash_warp_bundle(source, destination)
    assert destination.read_text(encoding="utf-8") == '{"old": true}'


def test_direct_route_is_not_discarded(tmp_path):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    state = AppState()
    state.protocols["warp"] = PluginState(
        enabled=True,
        config={
            "local_lists": {"bypass": {"domains": ["example.org"], "ips": []}},
            "list_targets": {"local:bypass": "direct"},
        },
    )
    with (
        patch("hydra.plugins.warp.plugin.WARP_ULTIMATE_BUNDLE", tmp_path / "missing.json"),
        patch("hydra.plugins.warp.plugin.WARP_PROFILES_DIR", profiles),
        patch.object(WarpPlugin, "_load_warp_config", return_value=None),
    ):
        fragment = WarpPlugin().configure(state)
    assert fragment.route_rules == [{"domain_suffix": ["example.org"], "outbound": "direct"}]


def test_yaml_is_auto_discovered_and_refreshed(tmp_path):
    configs = tmp_path / "configs"
    configs.mkdir()
    source = configs / "my-warp-profile.yml"
    destination = configs / "ultimate.json"
    source.write_text(_yaml(), encoding="utf-8")

    first = load_or_refresh_warp_bundle(destination)
    assert first["source_file"] == source.name
    assert first["endpoints"][0]["name"] == "Netherlands"
    assert discover_warp_yaml_sources(configs) == [source]
    assert not (configs / "ultimate.yaml").exists()

    source.write_text(_yaml().replace("Netherlands", "Finland"), encoding="utf-8")
    second = load_or_refresh_warp_bundle(destination)
    assert second["source_sha256"] != first["source_sha256"]
    assert second["endpoints"][0]["name"] == "Finland"


def test_auto_discovery_rejects_multiple_yaml_files(tmp_path):
    (tmp_path / "one.yaml").write_text(_yaml(), encoding="utf-8")
    (tmp_path / "two.yml").write_text(_yaml(), encoding="utf-8")
    with pytest.raises(ClashImportError, match="несколько YAML-файлов"):
        load_or_refresh_warp_bundle(tmp_path / "ultimate.json")


def test_imports_rule_provider_metadata(tmp_path):
    source = tmp_path / "rules.yaml"
    source.write_text(_yaml() + """
rule-providers:
  youtube:
    type: http
    behavior: classical
    url: https://example.com/youtube.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    format: mrs
    url: https://example.com/private.mrs
rules:
  - RULE-SET,youtube,YouTube
  - RULE-SET,private,DIRECT
""", encoding="utf-8")
    bundle = import_clash_warp_bundle(source, tmp_path / "ultimate.json")
    providers = {item["name"]: item for item in bundle["rule_providers"]}
    assert providers["youtube"]["supported"] is True
    assert providers["youtube"]["route_group"] == "YouTube"
    assert providers["private"]["supported"] is False
    assert "MRS" in providers["private"]["unsupported_reason"]


def test_tui_selected_location_becomes_selector_default(tmp_path):
    source = tmp_path / "ultimate.yaml"
    destination = tmp_path / "ultimate.json"
    source.write_text(_yaml(), encoding="utf-8")
    bundle = import_clash_warp_bundle(source, destination)
    second = json.loads(json.dumps(bundle["endpoints"][0]))
    second["tag"] = "warp_ultimate_second"
    second["name"] = "Finland"
    bundle["endpoints"].append(second)
    destination.write_text(json.dumps(bundle), encoding="utf-8")

    state = AppState()
    state.protocols["warp"] = PluginState(
        enabled=True,
        config={
            "ultimate_selected_tag": second["tag"],
            "local_lists": {"test": {"domains": ["example.org"], "ips": []}},
            "list_targets": {"local:test": "warp_ultimate"},
        },
    )
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    with (
        patch("hydra.plugins.warp.plugin.WARP_ULTIMATE_BUNDLE", destination),
        patch("hydra.plugins.warp.plugin.WARP_PROFILES_DIR", profiles),
        patch.object(WarpPlugin, "_load_warp_config", return_value=None),
        patch.object(WarpPlugin, "_resolve_endpoint_host", return_value="192.0.2.10"),
    ):
        fragment = WarpPlugin().configure(state)
    selector = next(item for item in fragment.outbounds if item["tag"] == "warp_ultimate")
    assert selector["default"] == second["tag"]
