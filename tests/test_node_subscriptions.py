import base64
import json
from collections.abc import Sequence
from typing import Any

from hydra.contracts.node_export import NodeClientExport, NodeClientExportUser, NodeClientProfile
from hydra.core.configuration_names import apply_json_configuration_name
from hydra.core.state_models import AppState, User
from hydra.plugins.base import BasePlugin, PluginStatus
from hydra.core.state_nodes import NodeConfig
from hydra.services.subscriptions.client_configs import (
    generate_nekobox_sub,
    generate_singbox_config,
    generate_throne_sub,
)
from hydra.services.subscriptions.hydrabox import generate_hydrabox_subscription
from hydra.services.subscriptions.links import generate_base64_sub, generate_shadowrocket_sub
from hydra.services.subscriptions.node_exports import node_profile_name_key, node_profiles_for_user


class EmptyPlugins:
    def enabled_transports(self, state: AppState) -> Sequence[BasePlugin]:
        return []

    def get(self, name: str) -> BasePlugin | None:
        return None

    def status(self, plugin: BasePlugin, state: AppState) -> PluginStatus:
        raise AssertionError("no plugin should be queried")

    def client_link(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> str:
        raise AssertionError("no plugin should be queried")

    def client_links(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> list[str]:
        raise AssertionError("no plugin should be queried")

    def client_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> str:
        raise AssertionError("no plugin should be queried")

    def singbox_client_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        *,
        apply_name: bool = True,
    ) -> str:
        raise AssertionError("no plugin should be queried")

    def profiles(self, plugin: BasePlugin, state: AppState) -> list[dict[str, Any]]:
        raise AssertionError("no plugin should be queried")


class LocalExports:
    def __init__(self, export):
        self.export = export
        self.reads = []

    def published_export(self, state, node_id):
        self.reads.append(node_id)
        return self.export


def _fixture(*, override=True):
    user = User(email="alice@example.com", uuid="user-1")
    node = NodeConfig(
        id="de-1",
        name="Germany",
        region="DE",
        address="node.example.com",
        generation=7,
        published_generation=7,
        desired_digest="b" * 64,
        published_digest="a" * 64,
        profile_names={"vless": "Node VLESS", "shadowtls": "Node ShadowTLS"},
    )
    vless = NodeClientProfile(
        protocol="vless",
        links=("vless://user-1@node.example.com:443?encryption=none",),
        singbox=(
            {
                "outbounds": [
                    {
                        "type": "vless",
                        "tag": "vless-node",
                        "server": "node.example.com",
                        "server_port": 443,
                        "uuid": "user-1",
                    },
                ],
                "route": {"final": "vless-node"},
            },
        ),
    )
    shadowtls = NodeClientProfile(
        protocol="shadowtls",
        links=("trojan://user-1@node.example.com:443?plugin=shadow-tls",),
        singbox=(
            {
                "outbounds": [
                    {
                        "type": "shadowtls",
                        "tag": "shadowtls-node",
                        "server": "node.example.com",
                        "server_port": 443,
                    },
                ],
                "route": {"final": "shadowtls-node"},
            },
        ),
    )
    export = NodeClientExport(
        node_id="de-1",
        generation=7,
        users={"user-1": NodeClientExportUser("user-1", (vless, shadowtls))},
    )
    if override:
        user.configuration_name_overrides[node_profile_name_key("de-1", "vless", "")] = "Alice Node VLESS"
    state = AppState(users=[user], nodes=[node])
    return user, state, LocalExports(export)


def test_node_profiles_are_user_scoped_and_apply_user_then_node_names():
    user, state, exports = _fixture()

    profiles = node_profiles_for_user(user, state, node_exports=exports)

    assert exports.reads == ["de-1"]
    assert [(item.protocol, item.name) for item in profiles] == [
        ("vless", "Alice Node VLESS"),
        ("shadowtls", "Node ShadowTLS"),
    ]
    assert profiles[0].links[0].endswith("#Alice%20Node%20VLESS")
    assert profiles[1].links[0].endswith("#Node%20ShadowTLS")


def test_unpublished_node_export_is_not_read_or_served():
    user, state, exports = _fixture()
    state.nodes[0].published_generation = 0
    state.nodes[0].published_digest = ""

    assert node_profiles_for_user(user, state, node_exports=exports) == ()
    assert exports.reads == []


def test_singbox_name_override_updates_endpoint_and_route_reference():
    payload = json.dumps({
        "endpoints": [{"type": "wireguard", "tag": "awg-mobile"}],
        "route": {"final": "awg-mobile"},
    })

    renamed = json.loads(apply_json_configuration_name(
        payload,
        key="node:profile",
        global_names={"node:profile": "DE · amneziawg · mobile"},
        user_names={},
    ))

    assert renamed["endpoints"][0]["tag"] == "DE · amneziawg · mobile"
    assert renamed["route"]["final"] == "DE · amneziawg · mobile"


def test_base64_and_shadowrocket_include_only_confirmed_local_node_links():
    user, state, exports = _fixture()
    plugins = EmptyPlugins()

    base64_text = base64.b64decode(
        generate_base64_sub(user, state, plugins=plugins, node_exports=exports),
    ).decode()
    shadowrocket_text = base64.b64decode(
        generate_shadowrocket_sub(user, state, plugins=plugins, node_exports=exports),
    ).decode()

    assert "vless://user-1@node.example.com:443?encryption=none#Alice%20Node%20VLESS" in base64_text
    assert "trojan://user-1@node.example.com:443?plugin=shadow-tls#Node%20ShadowTLS" in base64_text
    assert "node.example.com" in shadowrocket_text
    assert exports.reads == ["de-1", "de-1"]


def test_singbox_throne_and_nekobox_merge_node_material_without_rewriting_links():
    user, state, exports = _fixture()
    plugins = EmptyPlugins()

    singbox = generate_singbox_config(user, state, plugins=plugins, node_exports=exports)
    throne = base64.b64decode(
        generate_throne_sub(user, state, plugins=plugins, node_exports=exports),
    ).decode()
    nekobox = base64.b64decode(
        generate_nekobox_sub(user, state, plugins=plugins, node_exports=exports),
    ).decode()

    assert any(outbound.get("tag") == "Alice Node VLESS" for outbound in singbox["outbounds"])
    assert singbox["route"]["final"] == "Alice Node VLESS"
    assert "vless://user-1@node.example.com:443" in throne
    assert "json://shadowtls#" in throne
    assert "node.example.com" in nekobox
    assert exports.reads == ["de-1"] * 5


def test_hydrabox_namespaces_node_resources_and_profiles():
    user, state, exports = _fixture()

    document = generate_hydrabox_subscription(
        user,
        state,
        plugins=EmptyPlugins(),
        node_exports=exports,
    )

    assert len(document["resources"]) == 2
    assert len(document["profiles"]) == 2
    assert all(profile["resource"].startswith("resource-node-de-1") for profile in document["profiles"])
    assert {profile["name"] for profile in document["profiles"]} == {
        "Alice Node VLESS",
        "Node ShadowTLS",
    }
    assert document["identity"]["sequence"] > 0
