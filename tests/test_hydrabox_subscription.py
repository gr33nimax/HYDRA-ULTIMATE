"""HydraBox Subscription v1 generation and HTTP adapter contracts."""
from __future__ import annotations

from io import BytesIO
import json
from unittest.mock import patch

import pytest

from hydra.contracts import ConfigFragment
from hydra.core.state_models import AppState, User
from hydra.plugins.base import BasePlugin, PluginCategory, PluginMeta, PluginStatus
from hydra.services.subscriptions.generator import (
    SUPPORTED_SUBSCRIPTION_FORMATS,
    SubscriptionPluginService,
    generate_hydrabox_subscription,
    get_subscription_urls,
)
from hydra.services.subscriptions.server import SubscriptionHandler


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

    assert subscription["api_version"] == "hydrabox.io/subscription/v1"
    assert subscription["kind"] == "SubscriptionData"
    assert subscription["issuer"] == "https://subscriptions.example.com"
    assert subscription["subscription_id"] == "customer-main"
    assert subscription["channel"] == "stable"
    assert subscription["sequence"] == 7
    assert subscription["issued_at"] == "2026-08-01T00:00:00Z"
    assert set(subscription["runtime"]["document"]) == {"outbounds"}
    assert [
        outbound["tag"]
        for outbound in subscription["runtime"]["document"]["outbounds"]
    ] == ["provider-main", "provider-shadowtls"]
    assert subscription["profiles"] == [{
        "id": subscription["default_profile_id"],
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

    exported = subscription["runtime"]["document"]["endpoints"][0]
    assert exported["tag"] == "provider-wg"
    assert exported["system"] is False
    assert {
        key: exported["amnezia"][key] for key in extended_amnezia
    } == extended_amnezia
    assert subscription["profiles"][0]["entrypoint"] == {
        "section": "endpoints",
        "tag": "provider-wg",
    }


def test_hydrabox_subscription_compares_fractional_expiry_as_time():
    state, user = _state()
    user.expiry_date = "2026-08-01T00:00:00.500000Z"

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(_HydraBoxTransport(_shadowtls_payload())),
    )

    assert subscription["expires_at"] == "2026-08-01T00:00:00.500000Z"


def test_hydrabox_subscription_normalizes_date_only_expiry():
    state, user = _state()
    user.expiry_date = "2026-08-02"

    subscription = generate_hydrabox_subscription(
        user,
        state,
        plugins=_plugins(_HydraBoxTransport(_shadowtls_payload())),
    )

    assert subscription["expires_at"] == "2026-08-02T23:59:59Z"


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


def test_hydrabox_subscription_rejects_duplicate_native_tags():
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

    with pytest.raises(ValueError, match="duplicate native tag"):
        generate_hydrabox_subscription(
            user,
            state,
            plugins=_plugins(first, second),
        )


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
            "reserved HydraBox tag",
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


def test_hydrabox_http_response_uses_native_media_type_and_raw_json():
    state, user = _state()
    handler = object.__new__(SubscriptionHandler)

    content, content_type, suffix = handler._subscription(
        "hydrabox",
        user,
        state,
        _plugins(_HydraBoxTransport(_shadowtls_payload())),
    )

    assert content_type == (
        "application/vnd.hydrabox.subscription+json; charset=utf-8"
    )
    assert suffix == "subscription.hbx.json"
    assert json.loads(content)["api_version"] == "hydrabox.io/subscription/v1"
    assert not content.startswith("ey")


def test_hydrabox_format_is_public_and_generation_failure_is_fail_closed():
    state, user = _state()
    assert "hydrabox" in SUPPORTED_SUBSCRIPTION_FORMATS
    assert get_subscription_urls(user, state)["hydrabox"].endswith(
        "?format=hydrabox",
    )

    handler = object.__new__(SubscriptionHandler)
    handler.plugins = _plugins()
    handler.path = "/sub/customer-main?format=hydrabox"
    handler.headers = {"User-Agent": "HydraBox/1.0"}
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
