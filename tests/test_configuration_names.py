from __future__ import annotations

import base64
import json
import urllib.parse

import pytest

from hydra.contracts.vless_cdn import CLIENT_LABEL
from hydra.core.configuration_names import (
    apply_json_configuration_name,
    configuration_name_key,
)
from hydra.core.state_models import AppState, User, validate_state
from hydra.core.state_models import PluginState
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.shadowtls.plugin import ShadowTLSPlugin
from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin
from hydra.services.configuration_names import ConfigurationNameService
from hydra.services.subscriptions.access import SubscriptionPluginService
from hydra.services.subscriptions.links import tag_client_link


def test_user_name_overrides_global_then_builtin_default() -> None:
    state = AppState(users=[User(email="u@example.com", uuid="u")])
    names = ConfigurationNameService()
    user = state.users[0]

    assert names.resolve(state, user, "trusttunnel:quic", "TrustTunnel QUIC") == "TrustTunnel QUIC"
    names.set_global(state, "trusttunnel:quic", "Основной VPN")
    assert names.resolve(state, user, "trusttunnel:quic", "TrustTunnel QUIC") == "Основной VPN"
    names.set_user(state, user.email, "trusttunnel:quic", "Домашний")
    assert names.resolve(state, user, "trusttunnel:quic", "TrustTunnel QUIC") == "Домашний"


def test_empty_name_deletes_override_and_names_are_validated() -> None:
    state = AppState(users=[User(email="u@example.com", uuid="u")])
    names = ConfigurationNameService()
    names.set_global(state, "naive:https", "  Naive \u2713  ")
    names.set_user(state, "u@example.com", "naive:https", "Персональный")
    names.set_user(state, "u@example.com", "naive:https", "  ")

    assert state.configuration_names == {"naive:https": "Naive \u2713"}
    assert state.users[0].configuration_name_overrides == {}
    validate_state(state)
    with pytest.raises(ValueError, match="control"):
        names.set_global(state, "naive:https", "bad\nname")
    with pytest.raises(ValueError, match="128"):
        names.set_global(state, "naive:https", "x" * 129)


def test_old_state_without_name_fields_loads_with_empty_defaults(tmp_path, monkeypatch) -> None:
    from hydra.core import state as storage

    monkeypatch.setattr(storage, "STATE_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_FILE", tmp_path / "state.json")
    storage.STATE_FILE.write_text(
        '{"format_version": 1, "revision": 0, "core": {"users": [{"email": "u", "uuid": "u"}]}, "features": {}}',
        encoding="utf-8",
    )

    loaded = storage.load_state()
    assert loaded.configuration_names == {}
    assert loaded.users[0].configuration_name_overrides == {}

    ConfigurationNameService().set_global(loaded, "naive:https", "Общий")
    ConfigurationNameService().set_user(loaded, "u", "naive:https", "Личный")
    storage.save_state(loaded)
    reloaded = storage.load_state()
    assert reloaded.configuration_names == {"naive:https": "Общий"}
    assert reloaded.users[0].configuration_name_overrides == {"naive:https": "Личный"}


def _subscription_plugins(*plugins):
    by_name = {plugin.meta.name: plugin for plugin in plugins}
    return SubscriptionPluginService(
        enabled_plugins=lambda _state, _category: list(plugins),
        get_plugin=by_name.get,
    )


def _named_state() -> tuple[AppState, User]:
    user = User(email="alice@example.com", uuid="user-1")
    state = AppState(users=[user])
    state.network.server_ip = "203.0.113.10"
    state.protocols = {
        "anytls": PluginState(enabled=True, config={"domain": "any.example"}),
        "shadowtls": PluginState(
            enabled=True,
            config={"handshake_sni": "www.example.com"},
        ),
        "trusttunnel": PluginState(
            enabled=True,
            config={"domain": "tt.example", "transport": "both"},
        ),
    }
    return state, user


def test_json_name_updates_primary_and_all_profile_references() -> None:
    payload = json.dumps(
        {
            "outbounds": [
                {"type": "test", "tag": "primary", "password": "primary"},
                {
                    "type": "selector",
                    "tag": "choice",
                    "outbounds": ["primary", "direct"],
                    "default": "primary",
                },
                {"type": "direct", "tag": "direct"},
            ],
            "route": {"final": "primary", "rules": [{"outbound": "primary"}]},
        }
    )

    named = json.loads(
        apply_json_configuration_name(
            payload,
            key="anytls",
            global_names={"anytls": "Общее"},
            user_names={"anytls": "Личное"},
        )
    )

    assert named["outbounds"][0]["tag"] == "Личное"
    assert named["outbounds"][0]["password"] == "primary"
    assert named["route"]["final"] == "Личное"
    assert named["route"]["rules"][0]["outbound"] == "Личное"
    assert named["outbounds"][1]["outbounds"][0] == "Личное"
    assert named["outbounds"][1]["default"] == "Личное"


def test_json_name_uses_first_primary_and_stable_collision_suffix() -> None:
    payload = json.dumps(
        {
            "outbounds": [
                {"type": "test", "tag": "primary", "password": "keep"},
                {"type": "direct", "tag": "direct"},
            ],
        }
    )

    named = json.loads(
        apply_json_configuration_name(
            payload,
            key="anytls",
            global_names={"anytls": "direct"},
            user_names={},
        )
    )

    assert named["outbounds"][0]["tag"] == "direct (2)"
    assert named["outbounds"][0]["password"] == "keep"
    assert (
        apply_json_configuration_name(
            "[]",
            key="anytls",
            global_names={"anytls": "Named"},
            user_names={},
        )
        == "[]"
    )
    assert configuration_name_key("amneziawg", {"profile": "mobile"}) == "amneziawg:mobile"


def test_subscription_configs_and_links_use_protocol_specific_names() -> None:
    state, user = _named_state()
    user.configuration_name_overrides.update(
        {
            "anytls": "Личный AnyTLS",
            "shadowtls": "Личный ShadowTLS",
            "trusttunnel:quic": "Личный TT QUIC",
        }
    )
    state.configuration_names.update(
        {
            "anytls": "Общий AnyTLS",
            "shadowtls": "Общий ShadowTLS",
            "trusttunnel:tcp": "Общий TT TCP",
            "trusttunnel:quic": "Общий TT QUIC",
        }
    )
    anytls = AnyTLSPlugin()
    shadowtls = ShadowTLSPlugin()
    trusttunnel = TrustTunnelPlugin()
    plugins = _subscription_plugins(anytls, shadowtls, trusttunnel)

    anytls_config = json.loads(plugins.client_config(anytls, user, state))
    shadowtls_config = json.loads(plugins.singbox_client_config(shadowtls, user, state))
    trusttunnel_config = json.loads(plugins.client_config(trusttunnel, user, state))

    anytls_primary = next(item for item in anytls_config["outbounds"] if item["type"] == "anytls")
    shadowtls_primary = next(item for item in shadowtls_config["outbounds"] if item["type"] == "trojan")
    assert anytls_primary["tag"] == "Личный AnyTLS"
    assert anytls_config["route"]["final"] == "Личный AnyTLS"
    assert shadowtls_primary["tag"] == "Личный ShadowTLS"
    assert shadowtls_config["route"]["final"] == "Личный ShadowTLS"
    assert shadowtls_primary["password"] == ShadowTLSPlugin()._derive_trojan_password(user.uuid)
    assert {item["tag"] for item in trusttunnel_config["outbounds"]} >= {
        "Общий TT TCP",
        "Личный TT QUIC",
    }

    anytls_link = plugins.client_link(anytls, user, state)
    shadowtls_link = plugins.client_link(shadowtls, user, state)
    trusttunnel_links = plugins.client_links(trusttunnel, user, state)
    assert tag_client_link(anytls_link, user, state).endswith("#%D0%9B%D0%B8%D1%87%D0%BD%D1%8B%D0%B9%20AnyTLS")
    assert tag_client_link(shadowtls_link, user, state).endswith("#%D0%9B%D0%B8%D1%87%D0%BD%D1%8B%D0%B9%20ShadowTLS")
    raw_links = [
        base64.urlsafe_b64decode(link.removeprefix("tt://?") + "=" * (-len(link.removeprefix("tt://?")) % 4))
        for link in trusttunnel_links
    ]
    assert "Общий TT TCP".encode() in raw_links[0]
    assert "Личный TT QUIC".encode() in raw_links[1]


def test_native_links_keep_variant_names_distinct_and_rename_awg() -> None:
    state, user = _named_state()
    state.configuration_names.update(
        {
            "naive": "Домашний Naive",
            "amneziawg:desktop": "Домашний AWG",
        }
    )
    links = [
        "naive+https://u:p@example.com:443#old",
        "naive+quic://u:p@example.com:443#old",
        "wg://example.com:51820?private_key=x#alice%40example.com%20AWG%20Desktop",
    ]

    assert [
        urllib.parse.unquote(urllib.parse.urlsplit(tag_client_link(link, user, state)).fragment) for link in links
    ] == ["Домашний Naive", "Домашний Naive QUIC", "Домашний AWG"]


def test_a_cdn_vless_link_is_not_named_like_an_ordinary_xhttp_one() -> None:
    """У обычного VLESS и у VLESS за CDN тип `xhttp` одинаков: имена обязаны различаться."""
    state, user = _named_state()
    extra = urllib.parse.quote(json.dumps({"uplinkHTTPMethod": "GET"}))
    plain = "vless://u@example.com:443?type=xhttp&path=%2Fapi#old"
    cdn = f"vless://u@cdn.example.com:443?type=xhttp&path=%2Fapi&extra={extra}#old"

    plain_name = urllib.parse.unquote(urllib.parse.urlsplit(tag_client_link(plain, user, state)).fragment)
    cdn_name = urllib.parse.unquote(urllib.parse.urlsplit(tag_client_link(cdn, user, state)).fragment)

    assert plain_name == f"{user.email} VLESS XHTTP"
    assert cdn_name == f"{user.email} {CLIENT_LABEL}"
    assert plain_name != cdn_name


def test_a_family_override_still_keeps_the_cdn_profile_apart() -> None:
    """Общее имя для семейства VLESS не должно схлопывать оба профиля в одно."""
    state, user = _named_state()
    state.configuration_names.update({"vless": "Мой VLESS"})
    extra = urllib.parse.quote(json.dumps({"uplinkHTTPMethod": "GET"}))
    plain = "vless://u@example.com:443?type=xhttp#old"
    cdn = f"vless://u@cdn.example.com:443?type=xhttp&extra={extra}#old"

    assert urllib.parse.unquote(urllib.parse.urlsplit(tag_client_link(plain, user, state)).fragment) == "Мой VLESS"
    assert (
        urllib.parse.unquote(urllib.parse.urlsplit(tag_client_link(cdn, user, state)).fragment)
        == f"{user.email} {CLIENT_LABEL}"
    )


def test_an_exact_cdn_override_does_not_rename_ordinary_vless() -> None:
    state, user = _named_state()
    state.configuration_names.update({"vless:cdn": "Мой CDN"})
    extra = urllib.parse.quote(json.dumps({"uplinkHTTPMethod": "GET"}))
    plain = "vless://u@example.com:443?type=xhttp#old"
    cdn = f"vless://u@cdn.example.com:443?type=xhttp&extra={extra}#old"

    assert urllib.parse.unquote(urllib.parse.urlsplit(tag_client_link(plain, user, state)).fragment) == (
        f"{user.email} VLESS XHTTP"
    )
    assert urllib.parse.unquote(urllib.parse.urlsplit(tag_client_link(cdn, user, state)).fragment) == "Мой CDN"
