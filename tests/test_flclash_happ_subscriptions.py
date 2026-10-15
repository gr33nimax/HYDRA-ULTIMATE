"""Client import formats must not contain foreign native containers."""

from __future__ import annotations

import base64
import json
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hydra.core.state import AppState, User, save_state
from hydra.plugins.base import PluginMeta, PluginCategory
from hydra.services.subscriptions.metadata import get_subscription_urls, resolve_subscription_format
from hydra.services.subscriptions.server import SubscriptionHandler


def _plugins(links):
    access = MagicMock()
    access.enabled_transports.return_value = [
        SimpleNamespace(
            meta=PluginMeta(
                name="test",
                description="test",
                category=PluginCategory.TRANSPORT,
                version="1",
            )
        )
    ]
    access.client_links.return_value = links
    access.get.return_value = None
    return access


@pytest.mark.parametrize(
    ("agent", "expected"),
    [
        ("FlClash/0.8.92", "clash"),
        ("ClashMetaForAndroid/2.11", "clash"),
        ("clash.meta", "clash"),
        ("mihomo/1.19", "clash"),
        ("Happ/3.4.0", "happ"),
    ],
)
def test_client_negotiation_and_explicit_override(agent, expected):
    assert resolve_subscription_format(None, agent) == expected
    assert resolve_subscription_format("auto", agent) == expected
    assert resolve_subscription_format("base64", agent) == "base64"


def test_manual_urls_offer_both_clients():
    state = AppState()
    state.network.sub_domain = "sub.example.org"
    urls = get_subscription_urls(User(email="alice", uuid="token"), state)
    assert urls["flclash"].endswith("?format=clash")
    assert urls["happ"].endswith("?format=happ")


def test_happ_preserves_vless_extra_and_removes_foreign_links():
    from hydra.services.subscriptions.links import generate_happ_sub

    link = "vless://id@example.org:443?type=xhttp&extra=%7B%22noSSEHeader%22%3Atrue%7D#name"
    result = generate_happ_sub(
        User(email="alice", uuid="token"),
        AppState(),
        plugins=_plugins(
            [
                link,
                "sn://config?foreign",
                "naive+https://u:p@host:443",
                "wg://foreign",
                "tt://u:p@host:443",
                "anytls://p@host:443",
                "snell://foreign",
                "trojan://p@host:443?plugin=shadow-tls&version=3",
                "hy2://p@host:8443#hy2",
            ]
        ),
    )
    lines = base64.b64decode(result).decode().splitlines()
    assert len(lines) == 2
    assert lines[0].split("#")[0] == link.split("#")[0]
    assert lines[1].startswith("hy2://")


def test_clash_uses_real_yaml_schema_and_preserves_tls_reality_and_obfs():
    from hydra.services.subscriptions.clash import generate_clash_config

    config = generate_clash_config(
        User(email="alice", uuid="token"),
        AppState(),
        plugins=_plugins(
            [
                "vless://id@[2001:db8::1]:443?type=xhttp&path=%2Fapi&mode=stream-up&security=reality"
                "&sni=cover.example&pbk=public&sid=abcd&fp=chrome#vless",
                "hysteria2://p%40ss@hy.example:8443?sni=cert.example&obfs=salamander&obfs-password=obfs&alpn=h3#hy",
                "anytls://p@tls.example:443?sni=tls.example#tls",
                "sn://config?foreign",
                "trojan://p@host:443?plugin=shadow-tls",
            ]
        ),
    )
    vless, hy2, anytls = config["proxies"]
    assert vless["server"] == "2001:db8::1"
    assert vless["uuid"] == "id"
    assert vless["tls"] is True
    assert vless["servername"] == "cover.example"
    assert vless["reality-opts"] == {"public-key": "public", "short-id": "abcd"}
    assert vless["client-fingerprint"] == "chrome"
    assert vless["xhttp-opts"] == {"path": "/api", "mode": "stream-up"}
    assert hy2["type"] == "hysteria2"
    assert hy2["password"] == "p@ss"
    assert hy2["obfs"] == "salamander"
    assert hy2["obfs-password"] == "obfs"
    assert hy2["sni"] == "cert.example"
    assert hy2["alpn"] == ["h3"]
    assert anytls["type"] == "anytls"
    names = [proxy["name"] for proxy in config["proxies"]]
    assert config["proxy-groups"][0]["proxies"] == names
    assert config["rules"] == ["MATCH,HYDRA"]


def test_clash_does_not_downgrade_unknown_transport_or_drop_extra():
    from hydra.services.subscriptions.clash import generate_clash_config

    with pytest.raises(ValueError, match="compatible"):
        generate_clash_config(
            User(email="alice", uuid="token"),
            AppState(),
            plugins=_plugins(
                [
                    "vless://id@host:443?type=unsupported",
                    "vless://id@host:443?type=xhttp&extra=broken-json",
                    "vless://id@host:443?type=xhttp&extra=%7B%22uplinkHTTPMethod%22%3A%22GET%22%7D",
                    "vless://id@host:443?type=xhttp&extra=%7B%22unknownFeature%22%3Atrue%7D",
                    "hysteria2://p@host:bad",
                    "sn://awg?foreign",
                ]
            ),
        )


@pytest.mark.parametrize("reserved", ["HYDRA", "DIRECT", "REJECT", "GLOBAL", "REJECT-DROP", "PASS", "COMPATIBLE"])
def test_clash_names_are_unique_and_cannot_shadow_routing_targets(reserved):
    from hydra.services.subscriptions.clash import generate_clash_config

    state = AppState(configuration_names={"vless": reserved})
    config = generate_clash_config(
        User(email="alice", uuid="token"),
        state,
        plugins=_plugins(
            [
                "vless://id@one:443#HYDRA",
                "vless://id@two:443#HYDRA",
                "vless://id@three:443#DIRECT",
                "vless://id@four:443#HYDRA%20%282%29",
            ]
        ),
    )
    names = [proxy["name"] for proxy in config["proxies"]]
    assert len(set(names)) == 4
    assert names[0] == f"{reserved} (2)"
    assert not {"HYDRA", "DIRECT", "REJECT", "GLOBAL", "REJECT-DROP", "PASS", "COMPATIBLE"}.intersection(names)
    assert config["proxy-groups"][0]["proxies"] == names


def test_both_formats_include_only_profiles_from_injected_node_reader():
    from hydra.services.subscriptions.clash import generate_clash_config
    from hydra.services.subscriptions.links import generate_happ_sub
    from hydra.services.subscriptions.node_exports import NodeSubscriptionProfile

    user, state = User(email="alice", uuid="token"), AppState()
    reader = MagicMock()
    reader.profiles_for_user.return_value = (
        NodeSubscriptionProfile(
            "node",
            "vless",
            "direct",
            "Node",
            "node:key",
            ("vless://id@remote:443#Node",),
            (),
        ),
    )
    access = _plugins([])
    clash = generate_clash_config(user, state, plugins=access, node_exports=reader)
    happ = generate_happ_sub(user, state, plugins=access, node_exports=reader)
    assert clash["proxies"][0]["name"] == "Node"
    assert clash["proxies"][0]["server"] == "remote"
    assert base64.b64decode(happ).decode() == "vless://id@remote:443#Node\n"
    assert all(call.args == (user, state) for call in reader.profiles_for_user.call_args_list)


@pytest.mark.parametrize(
    ("agent", "query", "mime", "suffix"),
    [
        ("FlClash/0.8.92", "", "application/yaml", "clash.yaml"),
        ("Happ/3.4.0", "", "text/plain", "happ.txt"),
        ("curl/8", "?format=clash", "application/yaml", "clash.yaml"),
        ("curl/8", "?format=flclash", "application/yaml", "clash.yaml"),
        ("curl/8", "?format=happ", "text/plain", "happ.txt"),
    ],
)
def test_http_download_negotiates_client_payload(agent, query, mime, suffix):
    user = User(email="alice", uuid="token")
    save_state(AppState(users=[user]))
    handler = object.__new__(SubscriptionHandler)
    handler.plugins = _plugins(["vless://id@host:443?security=tls&sni=host#node"])
    handler.path = "/sub/token" + query
    handler.headers = {"User-Agent": agent, "X-HWID": "test-device"}
    handler.client_address = ("203.0.113.1", 12345)
    handler.wfile = BytesIO()
    handler.send_response = MagicMock()
    headers = {}
    handler.send_header = lambda key, value: headers.update({key: value})
    handler.end_headers = lambda: None
    handler.do_GET()
    handler.send_response.assert_called_once_with(200)
    assert headers["Content-Type"].startswith(mime)
    assert headers["Content-Disposition"].endswith(suffix + '"')
    assert "Subscription-Userinfo" in headers
    if suffix == "clash.yaml":
        assert json.loads(handler.wfile.getvalue())["proxies"][0]["type"] == "vless"
    else:
        assert base64.b64decode(handler.wfile.getvalue()).decode().startswith("vless://")


def test_subscription_menu_prints_real_flclash_and_happ_urls():
    from unittest.mock import patch

    from hydra.ui import menus

    user = User(email="alice", uuid="token")
    state = AppState(users=[user])
    state.network.sub_domain = "sub.example.org"
    app = MagicMock()
    app.admin.unit_active.return_value = True
    app.admin.subscription_certificate.return_value = ("cert", "key")

    with (
        patch.object(menus, "clear"),
        patch.object(menus, "title"),
        patch.object(menus, "panel"),
        patch.object(menus, "prompt"),
        patch("builtins.print") as output,
    ):
        menus._show_subscription_links(state, user, app)

    rendered = [call.args[0] for call in output.call_args_list if call.args]
    assert "https://sub.example.org/sub/token?format=clash" in rendered
    assert "https://sub.example.org/sub/token?format=happ" in rendered
    assert all(url in rendered for url in get_subscription_urls(user, state).values())
