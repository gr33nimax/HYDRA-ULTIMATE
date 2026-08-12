"""Hydra Subscription v2 generation and HTTP adapter contracts."""
from __future__ import annotations

import base64
from io import BytesIO
import json
from unittest.mock import MagicMock, patch

import pytest

from hydra.contracts import ConfigFragment
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.base import BasePlugin, PluginCategory, PluginMeta, PluginStatus
from hydra.plugins.calls.plugin import CallsPlugin
from hydra.plugins.wdtt.plugin import WdttPlugin
from hydra.services.subscriptions.generator import (
    SUPPORTED_SUBSCRIPTION_FORMATS,
    SubscriptionPluginService,
    generate_hydrabox_subscription,
    get_subscription_urls,
)
from hydra.services.subscriptions.server import SubscriptionHandler
from hydra.services.subscriptions.jwe import (
    JWE_MEDIA_TYPE,
    decrypt_hydrabox_subscription,
    encrypt_hydrabox_subscription,
)


TEST_JWE_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


class _HydraBoxTransport(BasePlugin):
    meta = PluginMeta(
        name="shadowtls",
        display_name="ShadowTLS",
        description="ShadowTLS test transport",
        category=PluginCategory.TRANSPORT,
    )

    def __init__(self, payload: str) -> None:
        self.payload = payload

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        return True

    def status(self, state=None) -> PluginStatus:
        return PluginStatus(installed=True, enabled=True, running=True)

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def generate_singbox_client_config(self, user, state) -> str:
        return self.payload


class _CallsSource:
    def __init__(self, links: list[str], *, supported: bool = True) -> None:
        self.links = links
        self.supported = supported

    def load_native_join_links(self) -> list[str]:
        return list(self.links)

    def multi_user_supported(self) -> bool:
        return self.supported

    def singbox_running(self) -> bool:
        return True


def _plugins(*items: BasePlugin) -> SubscriptionPluginService:
    return SubscriptionPluginService(
        enabled_plugins=lambda state, category: list(items),
        get_plugin=lambda name: next(
            (item for item in items if item.meta.name == name),
            None,
        ),
    )


def _state() -> tuple[AppState, User]:
    user = User(
        email="alice@example.com",
        uuid="customer-main",
        created_at="2026-08-01T00:00:00+00:00",
        hydrabox_jwe_key=TEST_JWE_KEY,
    )
    state = AppState(revision=7, users=[user])
    state.network.sub_domain = "subscriptions.example.com"
    return state, user


def _shadowtls_payload(*, tag: str = "provider-main") -> str:
    return json.dumps({
        "log": {"level": "info"},
        "inbounds": [{"type": "mixed", "tag": "mixed-in"}],
        "outbounds": [
            {
                "type": "trojan",
                "tag": tag,
                "server": "vpn.example.com",
                "server_port": 443,
                "password": "secret",
                "detour": "provider-shadowtls",
            },
            {
                "type": "shadowtls",
                "tag": "provider-shadowtls",
                "server": "transport.example.com",
                "server_port": 443,
                "version": 3,
                "password": "transport-secret",
            },
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": tag},
    })


def test_hydrabox_subscription_builds_strict_remote_runtime_and_profiles():
    state, user = _state()

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(_HydraBoxTransport(_shadowtls_payload())),
    )

    assert subscription["api_version"] == "hydra.io/subscription/v2"
    assert subscription["kind"] == "Subscription"
    assert subscription["identity"] == {
        "issuer": "https://subscriptions.example.com",
        "id": "customer-main",
        "channel": "stable",
        "sequence": (7 << 16) | 2,
    }
    assert subscription["validity"] == {
        "issued_at": "2026-08-01T00:00:00Z",
    }
    assert subscription["requirements"] == {
        "core": {
            "id": "io.hydrabox.hydracore",
            "api_version": 2,
            "remote_policy": 2,
            "features": [],
        },
        "client": {
            "subscription_contract": 2,
            "min_version": "0.4.0-beta.1",
            "features": [
                "automatic-permissions",
                "multi-resource",
                "secure-storage",
                "subscription-jwe",
            ],
        },
    }
    resource = subscription["resources"][0]
    assert resource["format"] == "sing-box-json"
    assert resource["requested_permissions"] == ["network.outbound"]
    assert set(resource["document"]) == {"outbounds"}
    assert [
        outbound["tag"]
        for outbound in resource["document"]["outbounds"]
    ] == ["provider-main", "provider-shadowtls"]
    assert subscription["profiles"] == [{
        "id": subscription["default_profile"],
        "resource": resource["id"],
        "name": "ShadowTLS",
        "entrypoint": {
            "section": "outbounds",
            "tag": "provider-main",
        },
        "enabled": True,
    }]
    json.dumps(subscription, allow_nan=False)


def test_hydrabox_subscription_does_not_publish_plugin_description():
    state, user = _state()
    description = "AnyTLS: TLS-shaped tunnel с padding scheme (sing-box inbound)"
    plugin = _HydraBoxTransport(_shadowtls_payload())
    plugin.meta = PluginMeta(
        name="anytls",
        description=description,
        category=PluginCategory.TRANSPORT,
    )

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(plugin),
    )

    assert subscription["profiles"][0]["name"] == "anytls"
    assert description not in json.dumps(subscription, ensure_ascii=False)


def test_hydrabox_sequence_advances_after_publisher_payload_change():
    state, user = _state()
    legacy_sequence = state.revision

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(_HydraBoxTransport(_shadowtls_payload())),
    )

    assert subscription["identity"]["sequence"] > legacy_sequence

    state.revision += 1
    updated = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(_HydraBoxTransport(_shadowtls_payload())),
    )
    assert (
        updated["identity"]["sequence"]
        > subscription["identity"]["sequence"]
    )


def test_hydrabox_subscription_exports_wireguard_as_userspace_endpoint():
    state, user = _state()
    extended_amnezia = {
        "i1": "value-i1",
        "i2": "value-i2",
        "i3": "value-i3",
        "i4": "value-i4",
        "i5": "value-i5",
        "j1": "value-j1",
        "j2": "value-j2",
        "j3": "value-j3",
        "itime": 1234,
    }
    endpoint = {
        "type": "wireguard",
        "tag": "provider-wg",
        "address": ["10.0.0.2/32"],
        "private_key": "private",
        "amnezia": {
            "jc": 4,
            "jmin": 40,
            "jmax": 120,
            **extended_amnezia,
        },
        "peers": [{
            "address": "wg.example.com",
            "port": 51820,
            "public_key": "public",
            "allowed_ips": ["0.0.0.0/0", "::/0"],
        }],
    }
    plugin = _HydraBoxTransport(json.dumps({
        "endpoints": [endpoint],
        "route": {"final": "provider-wg"},
    }))
    plugin.meta = PluginMeta(
        name="amneziawg",
        display_name="AmneziaWG",
        description="WireGuard test transport",
    )

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(plugin),
    )

    resource = subscription["resources"][0]
    exported = resource["document"]["endpoints"][0]
    assert exported["tag"] == "provider-wg"
    assert exported["system"] is False
    assert {
        key: exported["amnezia"][key] for key in extended_amnezia
    } == extended_amnezia
    assert subscription["profiles"][0]["entrypoint"] == {
        "section": "endpoints",
        "tag": "provider-wg",
    }
    assert resource["requested_permissions"] == [
        "network.endpoint.wireguard",
    ]


def test_hydrabox_subscription_compares_fractional_expiry_as_time():
    state, user = _state()
    user.expiry_date = "2026-08-01T00:00:00.500000Z"

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(_HydraBoxTransport(_shadowtls_payload())),
    )

    assert subscription["validity"]["expires_at"] == (
        "2026-08-01T00:00:00.500000Z"
    )


def test_hydrabox_subscription_normalizes_date_only_expiry():
    state, user = _state()
    user.expiry_date = "2026-08-02"

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(_HydraBoxTransport(_shadowtls_payload())),
    )

    assert subscription["validity"]["expires_at"] == "2026-08-02T23:59:59Z"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            '{"outbounds":[{"type":"trojan","tag":"first",'
            '"tag":"second"}]}',
            "duplicate JSON key",
        ),
        (
            json.dumps({"outbounds": [{
                "type": "trojan",
                "tag": "provider-main",
                "command": "/usr/bin/unsafe",
            }]}),
            "local authority field",
        ),
    ],
)
def test_hydrabox_subscription_rejects_unsafe_plugin_projection(
    payload: str,
    message: str,
):
    state, user = _state()

    with pytest.raises(ValueError, match=message):
        generate_hydrabox_subscription(
            user,
            state,
            plugins=_plugins(_HydraBoxTransport(payload)),
        )


def test_hydra_v2_keeps_equal_native_tags_isolated_by_resource():
    state, user = _state()
    first = _HydraBoxTransport(_shadowtls_payload())
    second = _HydraBoxTransport(json.dumps({
        "outbounds": [{
            "type": "vless",
            "tag": "provider-main",
            "server": "vless.example.com",
            "server_port": 443,
            "uuid": user.uuid,
        }],
        "route": {"final": "provider-main"},
    }))
    second.meta = PluginMeta(
        name="vless",
        display_name="VLESS",
        description="VLESS test transport",
    )

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(first, second),
    )

    assert len(subscription["resources"]) == 2
    assert {
        resource["document"]["outbounds"][0]["tag"]
        for resource in subscription["resources"]
    } == {"provider-main"}
    assert {profile["resource"] for profile in subscription["profiles"]} == {
        resource["id"] for resource in subscription["resources"]
    }


@pytest.mark.parametrize(
    ("outbounds", "message"),
    [
        (
            [{"type": "trojan", "tag": "main", "detour": "missing"}],
            "references missing tag",
        ),
        (
            [
                {"type": "trojan", "tag": "first", "detour": "second"},
                {"type": "shadowtls", "tag": "second", "detour": "first"},
            ],
            "cyclic runtime reference",
        ),
        (
            [{"type": "trojan", "tag": "select"}],
            "reserved Hydra tag",
        ),
    ],
)
def test_hydrabox_subscription_rejects_invalid_runtime_graph(
    outbounds: list[dict],
    message: str,
):
    state, user = _state()

    with pytest.raises(ValueError, match=message):
        generate_hydrabox_subscription(
            user,
            state,
            plugins=_plugins(_HydraBoxTransport(json.dumps({
                "outbounds": outbounds,
            }))),
        )


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"system": True}, "system WireGuard"),
    ],
)
def test_hydrabox_subscription_rejects_unsafe_wireguard_options(
    extra: dict,
    message: str,
):
    state, user = _state()
    endpoint = {
        "type": "wireguard",
        "tag": "provider-wg",
        "address": ["10.0.0.2/32"],
        "private_key": "private",
        "peers": [],
        **extra,
    }

    with pytest.raises(ValueError, match=message):
        generate_hydrabox_subscription(
            user,
            state,
            plugins=_plugins(_HydraBoxTransport(json.dumps({
                "endpoints": [endpoint],
            }))),
        )


def test_hydrabox_http_response_is_flattened_jwe_only():
    state, user = _state()
    handler = object.__new__(SubscriptionHandler)

    content, content_type, suffix = handler._subscription(
        "hydrabox",
        user,
        state,
        _plugins(_HydraBoxTransport(_shadowtls_payload())),
    )

    assert content_type == JWE_MEDIA_TYPE
    assert suffix == "subscription.hydra.jwe.json"
    envelope = json.loads(content)
    assert set(envelope) == {
        "protected", "encrypted_key", "iv", "ciphertext", "tag",
    }
    assert envelope["encrypted_key"] == ""
    protected = json.loads(base64.urlsafe_b64decode(
        envelope["protected"] + "=" * (-len(envelope["protected"]) % 4),
    ))
    assert protected == {
        "alg": "dir",
        "enc": "A256GCM",
        "typ": "hydra-subscription+jwe",
        "cty": "application/vnd.hydra.subscription+json",
    }
    assert decrypt_hydrabox_subscription(content, TEST_JWE_KEY)["api_version"] == (
        "hydra.io/subscription/v2"
    )


def test_hydrabox_format_is_public_and_generation_failure_is_fail_closed():
    state, user = _state()
    assert "hydrabox" in SUPPORTED_SUBSCRIPTION_FORMATS
    assert get_subscription_urls(user, state)["hydrabox"].endswith(
        f"?format=hydrabox#hydra-key={TEST_JWE_KEY}",
    )

    handler = object.__new__(SubscriptionHandler)
    handler.plugins = _plugins()
    handler.path = "/sub/customer-main?format=hydrabox"
    handler.headers = {
        "User-Agent": "HydraBox/0.4.0-beta.1",
        "X-Hydra-HWID": "hbx1_" + "A" * 43,
    }
    handler.client_address = ("203.0.113.10", 12345)
    handler.wfile = BytesIO()
    errors: list[tuple[int, str]] = []
    handler._send_error = lambda code, message: errors.append((code, message))
    handler._subscription = lambda *_args: (_ for _ in ()).throw(
        ValueError("unsafe runtime"),
    )

    with patch(
        "hydra.services.subscriptions.server.register_subscription_device",
        return_value=(state, user, "allowed"),
    ):
        handler.do_GET()

    assert errors == [(500, "Subscription generation failed")]
    assert handler.wfile.getvalue() == b""


def test_hydrabox_jwe_uses_unique_ivs_and_rejects_tampering():
    state, user = _state()
    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(_HydraBoxTransport(_shadowtls_payload())),
    )

    first = encrypt_hydrabox_subscription(subscription, TEST_JWE_KEY)
    second = encrypt_hydrabox_subscription(subscription, TEST_JWE_KEY)

    assert json.loads(first)["iv"] != json.loads(second)["iv"]
    tampered = json.loads(first)
    tampered["tag"] = ("A" if tampered["tag"][0] != "A" else "B") + tampered["tag"][1:]
    with pytest.raises(Exception):
        decrypt_hydrabox_subscription(
            json.dumps(tampered, separators=(",", ":")),
            TEST_JWE_KEY,
        )


def test_hydrabox_jwe_rejects_wrong_key_and_kid():
    state, user = _state()
    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(_HydraBoxTransport(_shadowtls_payload())),
    )
    payload = encrypt_hydrabox_subscription(
        subscription,
        TEST_JWE_KEY,
        iv=bytes(range(12)),
    )

    with pytest.raises(ValueError, match="kid mismatch"):
        decrypt_hydrabox_subscription(payload, TEST_JWE_KEY, expected_kid="wrong")
    wrong_key = "_" * 43
    with pytest.raises(Exception):
        decrypt_hydrabox_subscription(payload, wrong_key)


def test_hydra_v2_subscription_includes_only_multi_user_calls_config():
    state, user = _state()
    state.network.server_ip = "203.0.113.10"
    state.protocols["calls"] = PluginState(
        installed=True,
        enabled=True,
        config={
            "mode": "multi_user",
            "listen_port": 56002,
            "obfs_password": "o" * 43,
            "workers": 2,
            "max_workers_per_session": 4,
        },
    )
    links = [
        "https://vk.com/call/join/one",
        "https://vk.com/call/join/two",
    ]
    plugin = CallsPlugin(_CallsSource(links))

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(plugin),
    )

    resource = subscription["resources"][0]
    outbound = resource["document"]["outbounds"][0]
    assert resource["requested_permissions"] == ["network.outbound"]
    assert outbound["mode"] == "multi_user"
    assert outbound["multipath_profile"] == "adaptive"
    assert outbound["join_links"] == links
    assert outbound["user"] == user.email
    assert "join_link" not in outbound
    assert subscription["requirements"]["core"]["features"] == [
        "call",
        "call_vk_adaptive_multipath",
        "call_vk_multi_user",
    ]
    assert subscription["profiles"][0] == {
        "id": subscription["default_profile"],
        "resource": resource["id"],
        "name": "Обход БС",
        "entrypoint": {"section": "outbounds", "tag": "call-vk-out"},
        "enabled": True,
    }
    assert "cookies" not in json.dumps(subscription)


def test_hydra_v2_calls_projection_fails_closed_without_room_pool():
    state, user = _state()
    state.network.server_ip = "203.0.113.10"
    state.protocols["calls"] = PluginState(
        installed=True,
        enabled=True,
        config={"mode": "multi_user", "obfs_password": "o" * 43},
    )

    with pytest.raises(ValueError, match="failed to generate calls"):
        generate_hydrabox_subscription(
            user,
            state,
            plugins=_plugins(CallsPlugin(_CallsSource([]))),
        )


def test_hydra_v2_calls_requires_exact_hydracore_feature():
    state, user = _state()
    state.network.server_ip = "203.0.113.10"
    state.protocols["calls"] = PluginState(
        installed=True,
        enabled=True,
        config={
            "mode": "multi_user",
            "listen_port": 56002,
            "obfs_password": "o" * 43,
            "workers": 2,
            "max_workers_per_session": 4,
        },
    )
    links = [
        "https://vk.com/call/join/one",
        "https://vk.com/call/join/two",
    ]
    with pytest.raises(ValueError, match="failed to generate calls"):
        generate_hydrabox_subscription(
            user,
            state,
            plugins=_plugins(CallsPlugin(_CallsSource(links, supported=False))),
        )


def test_hydra_v2_never_reads_or_publishes_qwdtt_artifacts():
    state, user = _state()
    state.network.server_ip = "203.0.113.10"
    state.protocols["calls"] = PluginState(
        installed=True,
        enabled=True,
        config={"mode": "multi_user", "obfs_password": "o" * 43},
    )
    state.protocols["wdtt"] = PluginState(installed=True, enabled=True)
    calls = CallsPlugin(_CallsSource(["https://vk.com/call/join/native"]))
    qwdtt = WdttPlugin()
    qwdtt.generate_singbox_client_config = MagicMock(
        side_effect=AssertionError("qWDTT must not enter Hydra v2"),
    )

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(calls, qwdtt),
    )

    qwdtt.generate_singbox_client_config.assert_not_called()
    encoded = json.dumps(subscription)
    assert "qwdtt" not in encoded.lower()
    assert "main_password" not in encoded
    assert [profile["name"] for profile in subscription["profiles"]] == [
        "Обход БС",
    ]


@pytest.mark.parametrize(
    ("headers", "message"),
    [
        ({"X-Hydra-HWID": "hbx1_" + "A" * 43}, "HydraBox User-Agent"),
        ({"User-Agent": "HydraBox/0.4.0-beta.1"}, "HWID header"),
        (
            {"User-Agent": "HydraBox/0.3.0", "X-Hydra-HWID": "android-id"},
            "X-Hydra-HWID",
        ),
    ],
)
def test_hydrabox_http_rejects_missing_or_invalid_identity(headers, message):
    handler = object.__new__(SubscriptionHandler)
    handler.plugins = _plugins(_HydraBoxTransport(_shadowtls_payload()))
    handler.path = "/sub/customer-main?format=hydrabox"
    handler.headers = headers
    handler.client_address = ("203.0.113.10", 12345)
    errors: list[tuple[int, str]] = []
    handler._send_error = lambda code, detail: errors.append((code, detail))

    handler.do_GET()

    assert len(errors) == 1
    assert errors[0][0] == 400
    assert message in errors[0][1]
