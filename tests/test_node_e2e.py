"""End-to-end node path: base reconciler -> real mTLS control -> node -> subscription.

Opt-in (``HYDRA_NODE_E2E=1``): the default suite must not open sockets or write outside
tmp_path, so this file does nothing unless the operator asks for it.

What is real here: the mutually authenticated transport and its certificate pinning, the
node's desired-state preparation with the real plugins, the export, the base's generation
reservation and coverage gate, the immutable snapshot store, and the subscription
rendering that reads the published snapshot.

What is not real: the host. Package installation, sing-box configuration and nftables
belong to the Linux integration job, which performs a real install and apply; here the
apply is recorded instead, so a defect in the desired-state chain cannot hide behind host
noise.
"""

from __future__ import annotations

import os
import threading
from copy import deepcopy
from typing import Any, cast

import pytest

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.core import state as state_module
from hydra.core.host import HostBackend
from hydra.core.node_identity import NodeIdentity
from hydra.core.state_models import AppState, PluginState, User
from hydra.core.state_nodes import NodeConfig
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.plugins.base import PluginCategory
from hydra.plugins.vless_xhttp.plugin import VlessXhttpPlugin
from hydra.services.nodes.control_client import NodeControlClient
from hydra.services.nodes.reconcile import NodeReconciler
from hydra.services.nodes.reconciler import NodeSnapshotReconciler
from hydra.services.nodes.snapshot_store import NodeSnapshotStore
from hydra.services.nodes.transport import create_control_server
from hydra.services.subscriptions.links import generate_base64_sub
from tests.node_mtls import certificate_fingerprint, write_certificates

NODE_ID = "uk-1"
HANDSHAKE = "hcp.example.com"

pytestmark = pytest.mark.skipif(
    os.environ.get("HYDRA_NODE_E2E") != "1",
    reason="end-to-end node path is opt-in (HYDRA_NODE_E2E=1)",
)


class _NodeProtocols:
    """The node's protocol port: real preparation and client material, recorded lifecycle.

    Installing a package and applying sing-box configuration are the two steps that touch
    the host, so they are recorded here and exercised by the Linux integration job.
    """

    def __init__(self, plugins: list[Any]):
        self._plugins = {plugin.meta.name: plugin for plugin in plugins}
        self.installed: list[str] = []
        self.enabled: list[str] = []
        self.disabled: list[str] = []
        self.applies: list[AppState] = []

    def list(self, category: PluginCategory | None = None) -> list[Any]:
        del category
        return list(self._plugins.values())

    def enabled_subscription_names(self, state: AppState, category: PluginCategory | None = None) -> set[str]:
        del category
        return {
            name
            for name, plugin in self._plugins.items()
            if state.protocols.get(name)
            and state.protocols[name].enabled
            and (
                plugin.meta.capabilities.subscription_enabled or plugin.meta.capabilities.hydra_v2_subscription_enabled
            )
        }

    def client_profiles(self, state: AppState, name: str) -> list[dict[str, Any]]:
        plugin = self._plugins[name]
        query = plugin.meta.capabilities.subscription_profile_query
        if not query:
            return []
        return list(getattr(plugin, query)(state) or [])

    def client_links(self, state: AppState, name: str, user: User, **parameters: object) -> list[str]:
        return list(self._plugins[name].client_links(user, state, **parameters) or [])

    def client_link(self, state: AppState, name: str, user: User, **parameters: object) -> str:
        return str(self._plugins[name].client_link(user, state, **parameters) or "")

    def client_config(self, state: AppState, name: str, user: User, **parameters: object) -> str:
        return str(self._plugins[name].generate_client_config(user, state, **parameters) or "")

    def install(self, state: AppState, name: str) -> bool:
        del state
        self.installed.append(name)
        return True

    def enable(self, state: AppState, name: str) -> bool:
        # Enabling a protocol opens its firewall port, which is a host effect: the Linux
        # integration job covers that. The state side of enablement — profiles, keys,
        # addresses — happens in prepare_node_config and the user hooks below, so the
        # client material this scenario checks is still produced by the real plugins.
        state.protocols[name].enabled = True
        self.enabled.append(name)
        return True

    def disable(self, state: AppState, name: str) -> bool:
        state.protocols[name].enabled = False
        self.disabled.append(name)
        return True

    def uninstall(self, state: AppState, name: str) -> bool:
        state.protocols[name].installed = False
        return True


class _NodeUsers:
    """User reconciliation as the node performs it: state plus the plugins' user hooks."""

    def __init__(self, protocols: _NodeProtocols):
        self._protocols = protocols

    def reconcile(self, state: AppState, users: list[User]) -> None:
        existing = {user.uuid: user for user in state.users}
        added = [user for user in users if user.uuid not in existing]
        removed = [user for user in state.users if user.uuid not in {item.uuid for item in users}]
        state.users = [existing.get(user.uuid, user) for user in users]
        for user in removed:
            for plugin in self._protocols.list():
                plugin.on_user_remove(user, state)
        for user in added:
            for plugin in self._protocols.list():
                plugin.on_user_add(user, state)


class _NodeAdmin:
    """The node's own state is kept in memory here.

    Both sides of this scenario live in one process, so letting the node write the same
    ``state.json`` would make the base's writer and the node's writer fight over one
    revision — a conflict that says nothing about the chain under test. The node's file
    persistence has its own tests, and the Linux integration job exercises it for real.
    """

    def __init__(self):
        self.saves = 0

    def save_state(self, state: AppState) -> None:
        del state
        self.saves += 1


class _NodeCalls:
    """Calls is not part of this scenario; the reconciler only probes for pool changes."""

    def snapshot_managed_vk_pool(self) -> object:
        return None

    def restore_managed_vk_pool(self, snapshot: object) -> None:
        del snapshot


class _NodeApplication:
    """The node's application surface, with host effects recorded instead of performed."""

    def __init__(self, state: AppState):
        self._state = state
        self.protocols = _NodeProtocols([AmneziaWGPlugin(), VlessXhttpPlugin()])
        self.users = _NodeUsers(self.protocols)
        self.admin = _NodeAdmin()
        self.calls = _NodeCalls()
        self.apply_error_text = ""

    def apply(self, state: AppState) -> bool:
        self.protocols.applies.append(deepcopy(state))
        return True

    def apply_error(self) -> str:
        return self.apply_error_text


class _PublishedExports:
    """Subscription-side reader over the real snapshot store."""

    def __init__(self, store: NodeSnapshotStore):
        self._store = store

    def published_export(self, state: AppState, node_id: str):
        node = next((item for item in state.nodes if item.id == node_id), None)
        if node is None or node.published_generation <= 0 or not node.published_digest:
            return None
        return self._store.load(node_id, node.published_generation, node.published_digest)


class _NoBaseProtocols:
    """The base serves no protocols of its own in this scenario.

    ``get`` answers None because the subscription builder also asks for the base's own
    AmneziaWG, and everything else raises: an unexpected call must be visible, not
    silently satisfied.
    """

    def enabled_transports(self, state: AppState) -> list[Any]:
        del state
        return []

    def get(self, name: str) -> None:
        del name
        return None

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the base should not be asked for {name}")


def _node_state() -> AppState:
    return AppState(
        protocols={
            "amneziawg": PluginState(installed=True, config={}),
            "vless": PluginState(installed=True, config={}),
        },
    )


def _base_state() -> AppState:
    return AppState(
        users=[User(email="alice@example.com", uuid="user-1")],
        nodes=[
            NodeConfig(
                id=NODE_ID,
                name="UK node",
                region="UK",
                address="127.0.0.1",
                protocols={
                    "amneziawg": NodeProtocolSpec(enabled=True, config={"protocol_mode": "3.1"}),
                    "vless": NodeProtocolSpec(
                        enabled=True,
                        config={"security": "reality", "domain": HANDSHAKE, "xhttp_path": "/xhttp"},
                    ),
                },
            ),
        ],
    )


@pytest.fixture
def node_cluster(tmp_path, monkeypatch):
    """A node control server over the real mTLS transport, plus the base's reconciler."""
    files = write_certificates(tmp_path)
    identity = NodeIdentity(
        node_id=NODE_ID,
        base_url="https://base.example.com:8443",
        base_ip="127.0.0.1",
        certificate=str(files["server_cert"]),
        private_key=str(files["server_key"]),
        base_ca=str(files["ca"]),
        base_fingerprint=certificate_fingerprint(files["client_cert"]),
    )
    node_state = _node_state()
    application = _NodeApplication(node_state)
    reconciler = NodeReconciler(NODE_ID, cast(Any, application), state_reader=lambda: node_state)
    server = create_control_server(identity, reconciler, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    state_module.save_state(_base_state())
    store = NodeSnapshotStore(host=HostBackend(), root=tmp_path / "exports")
    host, port = server.server_address[:2]
    host = str(host)

    def client_for(node: NodeConfig) -> NodeControlClient:
        return NodeControlClient(
            host=host,
            port=port,
            node_id=node.id,
            ca_file=files["ca"],
            certificate=files["client_cert"],
            private_key=files["client_key"],
            server_fingerprint=certificate_fingerprint(files["server_cert"]),
        )

    base = NodeSnapshotReconciler(
        state_updater=state_module.update_state,
        client_for=client_for,
        snapshot_store=store,
    )
    monkeypatch.setattr("hydra.core.singbox_keys.generate_reality_keypair", lambda: ("private-key", "public-key"))
    try:
        yield base, store, node_state, application
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_a_node_publishes_profiles_a_subscription_can_read(node_cluster):
    """The whole chain the operator actually cares about, over the real transport."""
    base, store, node_state, application = node_cluster

    result = base.refresh(NODE_ID)

    assert result.status == "published"
    assert result.coverage == {"amneziawg": 1, "vless": 1}
    assert result.warnings == ()

    # The node really prepared the material the desired settings mean.
    amneziawg = node_state.protocols["amneziawg"].config
    paddings = amneziawg["profiles"]["desktop"]["obfuscation"]
    assert amneziawg["protocol_mode"] == "3.1"
    assert all(int(paddings[field]) >= 12 for field in ("S1", "S2", "S3", "S4"))
    generation = amneziawg["profiles"]["desktop"]["generation"]
    assert generation["RandomTrailers"] is True and generation["DisableCookies"] is True
    vless = node_state.protocols["vless"].config
    assert vless["security"] == "reality"
    assert vless["reality_handshake"] == HANDSHAKE
    assert vless["reality_private_key"] == "private-key"
    assert isinstance(vless["_tls_passthrough_route"], dict)

    # And the base publishes that export, so a subscription can read it locally.
    published = state_module.load_state().nodes[0]
    assert published.published_generation == result.generation
    assert published.published_digest == result.sha256

    user = state_module.load_state().users[0]
    subscription = generate_base64_sub(
        user,
        state_module.load_state(),
        plugins=cast(Any, _NoBaseProtocols()),
        node_exports=_PublishedExports(store),
    )
    assert subscription
    import base64

    decoded = base64.b64decode(subscription).decode("utf-8")
    assert HANDSHAKE in decoded
    assert "UK" in decoded  # the region names the node's profiles
    assert decoded.count("://") >= 2  # both transports produced something


def test_the_node_never_commits_a_generation_it_cannot_export(node_cluster):
    """A published generation must carry profiles; the base refuses an empty export."""
    base, store, node_state, application = node_cluster

    # Break the node's own material generation so its export would come back empty.
    application.protocols.client_links = lambda state, name, user, **parameters: []
    application.protocols.client_config = lambda state, name, user, **parameters: ""

    with pytest.raises(RuntimeError, match="no client profiles"):
        base.refresh(NODE_ID)

    assert state_module.load_state().nodes[0].published_generation == 0
    assert list((store.root / NODE_ID).glob("*.json")) == []
