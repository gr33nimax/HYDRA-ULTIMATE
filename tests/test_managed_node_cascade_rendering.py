from __future__ import annotations

import json
from datetime import date, timedelta
import os
import uuid
from pathlib import Path

import pytest

from hydra.contracts import ConfigFragment, RuntimeRenderContributions, RuntimeSubject
from hydra.contracts.managed_node_models import CascadeDefinition, NodeDefinition, ProtocolAssignment
from hydra.core.host import HostBackend
from hydra.core.singbox_config import generate_config
from hydra.core.state_managed_nodes import (
    ManagedNodesState,
    managed_nodes_from_extensions,
    store_managed_nodes,
)
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.base import BasePlugin, PluginCategory, PluginMeta, PluginStatus
from hydra.plugins.container import PluginContainer
from hydra.plugins.vless_xhttp.plugin import VlessXhttpPlugin
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.cascade_rendering import (
    CascadePeerMaterial,
    CascadeRenderPermit,
    ManagedNodeCascadeRenderer,
)
from hydra.services.managed_nodes.probe_clients import ManagedNodeProbeIdentityStore
from hydra.services.managed_nodes.rendering import production_runtime_contributions


_ENGINE_ENTRY = "1" * 64
_ENGINE_EXIT = "2" * 64
_PROOF = "3" * 64
_RECEIPT_ENTRY = "4" * 64
_RECEIPT_EXIT = "5" * 64
_PATH_PROOF = "6" * 64
_OPERATION = "cascade-op-1"


class _Host(HostBackend):
    pass


class _UserEchoTransport(BasePlugin):
    meta = PluginMeta(
        name="awg",
        description="test transport that renders every supplied user",
        category=PluginCategory.TRANSPORT,
    )

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        return True

    def status(self, state=None) -> PluginStatus:
        return PluginStatus(installed=True, enabled=True, running=True)

    def configure(self, state) -> ConfigFragment:
        return ConfigFragment(
            inbounds=[
                {
                    "type": "test",
                    "tag": "awg-test-in",
                    "users": [{"name": user.email, "uuid": user.uuid} for user in state.users],
                },
            ],
        )


def _route(protocol: str = "vless") -> CascadeDefinition:
    return CascadeDefinition("route-1", "Route", "base", "exit", [protocol])


def _state(protocol: str, *users: User, route: CascadeDefinition | None = None) -> AppState:
    if protocol == "vless":
        protocol_state = PluginState(
            enabled=True,
            installed=True,
            config={
                "domain": "entry.example.test",
                "cert_file": "/cert.pem",
                "key_file": "/key.pem",
                "xhttp_mode": "stream-up",
                "xhttp_path": "/xhttp",
                "security": "tls",
            },
        )
    else:
        protocol_state = PluginState(
            enabled=True,
            installed=True,
            config={"domain": "entry.example.test"},
        )
    state = AppState(
        protocols={protocol: protocol_state},
        users=list(users),
    )
    state.network.server_ip = "203.0.113.1"
    if route is not None:
        store_managed_nodes(
            state.feature_extensions,
            ManagedNodesState(
                definitions=[
                    NodeDefinition(
                        "exit",
                        "Exit",
                        "203.0.113.2",
                        "root",
                        "dev",
                        "a" * 40,
                        25555,
                        [ProtocolAssignment(protocol)],
                        "managed-node/exit",
                    ),
                ],
                cascades=[route],
            ),
        )
    return state


def _permit(route: CascadeDefinition, protocol: str = "vless") -> CascadeRenderPermit:
    return CascadeRenderPermit(
        cascade_id=route.id,
        entry_id=route.entry_id,
        exit_id=route.exit_id,
        protocol=protocol,
        operation_id=_OPERATION,
        entry_engine_sha256=_ENGINE_ENTRY,
        exit_engine_sha256=_ENGINE_EXIT,
        entry_auth_user_proof_sha256=_PROOF,
        exit_auth_user_proof_sha256=_PROOF,
        entry_receipt_sha256=_RECEIPT_ENTRY,
        exit_receipt_sha256=_RECEIPT_EXIT,
        path_proof_sha256=_PATH_PROOF,
    )


def _exit_state(protocol: str) -> AppState:
    state = _state(protocol)
    state.network.server_ip = "203.0.113.2"
    state.protocols[protocol].config["domain"] = "exit.example.test"
    return state


def _canonical_peer(
    protocol: str,
    route: CascadeDefinition,
    business_user: User,
    transit_user: User,
) -> CascadePeerMaterial:
    plugin = VlessXhttpPlugin() if protocol == "vless" else AnyTLSPlugin()
    raw = plugin.generate_client_config(transit_user, _exit_state(protocol))
    document = json.loads(raw)
    outbound = next(item for item in document["outbounds"] if item["type"] == protocol)
    return CascadePeerMaterial(
        cascade_id=route.id,
        exit_id=route.exit_id,
        protocol=protocol,
        operation_id=_OPERATION,
        user_uuid=business_user.uuid,
        receipt_sha256=_RECEIPT_EXIT,
        client_outbound=outbound,
    )


def _renderer(
    tmp_path: Path,
    route: CascadeDefinition,
    protocol: str,
    *,
    peer_material=None,
    engine_fingerprints=None,
    permit=None,
) -> ManagedNodeCascadeRenderer:
    store = CascadeCredentialStore(host=_Host(), root=tmp_path / "cascade-credentials")
    store.prepare(route.id)
    return ManagedNodeCascadeRenderer(
        participant_id=route.entry_id,
        credentials=store,
        permit_provider=lambda _state, _route, _protocol: permit or _permit(route, protocol),
        engine_fingerprints_provider=lambda _state, _route: (
            engine_fingerprints
            or {
                route.entry_id: _ENGINE_ENTRY,
                route.exit_id: _ENGINE_EXIT,
            }
        ),
        peer_material_provider=peer_material,
    )


def test_cascade_credentials_are_random_stable_and_domain_separated(tmp_path: Path) -> None:
    store = CascadeCredentialStore(host=_Host(), root=tmp_path / "cascade-credentials")
    with pytest.raises(ValueError, match="unavailable"):
        store.load("route-1")
    assert not (tmp_path / "cascade-credentials").exists()

    first = store.prepare("route-1")
    second = store.prepare("route-1")
    user = User("known@example.test", "known-business-uuid")
    entry_vless = first.subject("base", "vless", "entry", user)
    transit_vless = second.subject("exit", "vless", "transit", user)
    entry_anytls = second.subject("base", "anytls", "entry", user)
    other_route = store.prepare("route-2").subject("base", "vless", "entry", user)

    assert entry_vless.uuid == first.subject("base", "vless", "entry", user).uuid
    assert entry_vless.uuid != transit_vless.uuid
    assert entry_vless.uuid != entry_anytls.uuid
    assert entry_vless.uuid != other_route.uuid
    assert entry_vless.email != transit_vless.email
    assert str(uuid.UUID(entry_vless.uuid)) == entry_vless.uuid
    assert "known-business-uuid" not in entry_vless.uuid
    assert repr(first) == "CascadeCredentialScope(<protected>)"
    path = tmp_path / "cascade-credentials" / "route-1.seed"
    seed = path.read_bytes()
    assert len(seed) >= 32
    assert entry_vless.uuid not in repr(entry_vless)
    assert entry_vless.email not in repr(entry_vless)
    assert seed.hex() not in repr(entry_vless)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


def test_cascade_credentials_fail_closed_on_permissions_symlinks_and_missing_reads(tmp_path: Path) -> None:
    root = tmp_path / "cascade-credentials"
    store = CascadeCredentialStore(host=_Host(), root=root)
    store.prepare("route-1")
    secret = root / "route-1.seed"

    if os.name != "nt":
        secret.chmod(0o644)
        with pytest.raises(ValueError, match="permissions"):
            store.load("route-1")
        secret.chmod(0o600)

    if os.name != "nt":
        replacement = tmp_path / "replacement.seed"
        replacement.write_bytes(secret.read_bytes())
        secret.unlink()
        secret.symlink_to(replacement)
        with pytest.raises(ValueError, match="symbolic link"):
            store.load("route-1")
        with pytest.raises(ValueError, match="symbolic link"):
            store.remove("route-1", cleanup_confirmed=True)
        assert secret.is_symlink()
        assert replacement.is_file()
        secret.unlink()
        secret.write_bytes(replacement.read_bytes())
        secret.chmod(0o600)

    with pytest.raises(ValueError, match="confirmed"):
        store.remove("route-1", cleanup_confirmed=False)
    store.remove("route-1", cleanup_confirmed=True)
    assert not secret.exists()
    with pytest.raises(ValueError, match="unavailable"):
        store.load("route-1")
    store.remove("route-1", cleanup_confirmed=True)


def test_mixed_protocol_render_scopes_vless_subject_to_vless_inbound(tmp_path: Path) -> None:
    route = _route("vless")
    business = User("direct@example.test", "business-uuid")
    state = _state("vless", business, route=route)
    state.protocols["anytls"] = PluginState(
        enabled=True,
        installed=True,
        config={"domain": "entry.example.test"},
    )
    renderer = _renderer(
        tmp_path,
        route,
        "vless",
        peer_material=lambda _state, selected, protocol, user, transit, _permit: _canonical_peer(
            protocol, selected, user, transit
        ),
    )
    vless_plugin = VlessXhttpPlugin()
    anytls_plugin = AnyTLSPlugin()
    direct_profiles = (
        vless_plugin.generate_client_config(business, state),
        anytls_plugin.generate_client_config(business, state),
    )
    runtime = renderer.render(state)
    subject = runtime.users[0]
    container = PluginContainer(
        [vless_plugin, anytls_plugin],
        host=_Host(),
        runtime_contributions=lambda current: renderer.render(current),
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "exists", lambda _path: True)
        config = generate_config(state, container.collect_fragments(state))

    vless_inbound = next(item for item in config["inbounds"] if item["type"] == "vless")
    anytls_inbound = next(item for item in config["inbounds"] if item["type"] == "anytls")
    assert subject.uuid in {item["uuid"] for item in vless_inbound["users"]}
    assert subject.email not in {item["name"] for item in anytls_inbound["users"]}
    assert [item["type"] for item in config["outbounds"] if item["tag"].startswith("cascade-")] == ["vless"]
    assert vless_plugin.generate_client_config(business, state) == direct_profiles[0]
    assert anytls_plugin.generate_client_config(business, state) == direct_profiles[1]
    assert state.users == [business]
    assert state.protocols["vless"].enabled and state.protocols["anytls"].enabled


def test_mixed_protocol_render_scopes_anytls_subject_to_anytls_inbound(tmp_path: Path) -> None:
    route = _route("anytls")
    business = User("direct@example.test", "business-uuid")
    state = _state("anytls", business, route=route)
    state.protocols["vless"] = _state("vless").protocols["vless"]
    renderer = _renderer(
        tmp_path,
        route,
        "anytls",
        peer_material=lambda _state, selected, protocol, user, transit, _permit: _canonical_peer(
            protocol, selected, user, transit
        ),
    )
    vless_plugin = VlessXhttpPlugin()
    anytls_plugin = AnyTLSPlugin()
    direct_profiles = (
        vless_plugin.generate_client_config(business, state),
        anytls_plugin.generate_client_config(business, state),
    )
    subject = renderer.render(state).users[0]
    container = PluginContainer(
        [vless_plugin, anytls_plugin],
        host=_Host(),
        runtime_contributions=renderer.render,
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "exists", lambda _path: True)
        config = generate_config(state, container.collect_fragments(state))

    vless_inbound = next(item for item in config["inbounds"] if item["type"] == "vless")
    anytls_inbound = next(item for item in config["inbounds"] if item["type"] == "anytls")
    assert subject.uuid not in {item["uuid"] for item in vless_inbound["users"]}
    assert subject.email in {item["name"] for item in anytls_inbound["users"]}
    assert [item["type"] for item in config["outbounds"] if item["tag"].startswith("cascade-")] == ["anytls"]
    assert vless_plugin.generate_client_config(business, state) == direct_profiles[0]
    assert anytls_plugin.generate_client_config(business, state) == direct_profiles[1]
    assert state.users == [business]
    assert state.protocols["vless"].enabled and state.protocols["anytls"].enabled


def test_two_selected_protocols_keep_subjects_and_routes_isolated(tmp_path: Path) -> None:
    route = CascadeDefinition("route-1", "Dual", "base", "exit", ["vless", "anytls"])
    business = User("direct@example.test", "business-uuid")
    state = _state("vless", business, route=route)
    state.protocols["anytls"] = PluginState(
        enabled=True,
        installed=True,
        config={"domain": "entry.example.test"},
    )
    namespace = managed_nodes_from_extensions(state.feature_extensions)
    namespace.definitions[0].protocols.append(ProtocolAssignment("anytls"))
    store_managed_nodes(state.feature_extensions, namespace)
    credentials = CascadeCredentialStore(host=_Host(), root=tmp_path / "cascade-credentials")
    credentials.prepare(route.id)
    renderer = ManagedNodeCascadeRenderer(
        participant_id="base",
        credentials=credentials,
        permit_provider=lambda _state, selected, protocol: _permit(selected, protocol),
        engine_fingerprints_provider=lambda _state, selected: {
            selected.entry_id: _ENGINE_ENTRY,
            selected.exit_id: _ENGINE_EXIT,
        },
        peer_material_provider=lambda _state, selected, protocol, user, transit, _permit: _canonical_peer(
            protocol, selected, user, transit
        ),
    )
    vless_plugin = VlessXhttpPlugin()
    anytls_plugin = AnyTLSPlugin()
    direct_profiles = (
        vless_plugin.generate_client_config(business, state),
        anytls_plugin.generate_client_config(business, state),
    )
    subjects = {subject.protocols[0]: subject for subject in renderer.render(state).users}
    container = PluginContainer(
        [vless_plugin, anytls_plugin],
        host=_Host(),
        runtime_contributions=renderer.render,
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "exists", lambda _path: True)
        config = generate_config(state, container.collect_fragments(state))

    inbounds = {item["type"]: item for item in config["inbounds"]}
    vless_users = {item["uuid"] for item in inbounds["vless"]["users"]}
    anytls_users = {item["name"] for item in inbounds["anytls"]["users"]}
    assert subjects["vless"].uuid in vless_users
    assert subjects["vless"].email not in anytls_users
    assert subjects["anytls"].email in anytls_users
    assert subjects["anytls"].uuid not in vless_users
    outbounds = {item["tag"]: item["type"] for item in config["outbounds"]}
    for protocol, subject in subjects.items():
        rules = [
            rule
            for rule in config["route"]["rules"]
            if rule.get("auth_user") == [subject.email] and str(rule.get("outbound", "")).startswith("cascade-")
        ]
        assert len(rules) == 1
        assert outbounds[rules[0]["outbound"]] == protocol
    assert vless_plugin.generate_client_config(business, state) == direct_profiles[0]
    assert anytls_plugin.generate_client_config(business, state) == direct_profiles[1]
    assert state.users == [business]


def test_cascade_renderer_uses_state_eligibility_and_canonical_vless_path(tmp_path: Path) -> None:
    route = _route("vless")
    business = User("direct@example.test", "business-uuid")
    state = _state("vless", business, route=route)
    credentials = CascadeCredentialStore(host=_Host(), root=tmp_path / "cascade-credentials")
    scope = credentials.prepare(route.id)
    transit = scope.subject(route.exit_id, "vless", "transit", business)

    def peer(_state, selected, protocol, user, transit_user, permit):
        assert selected == route and protocol == "vless" and user.uuid == business.uuid
        assert permit.operation_id == _OPERATION
        return _canonical_peer(protocol, selected, user, transit_user)

    renderer = ManagedNodeCascadeRenderer(
        participant_id="base",
        credentials=credentials,
        permit_provider=lambda _state, _route, _protocol: _permit(route),
        engine_fingerprints_provider=lambda _state, _route: {
            "base": _ENGINE_ENTRY,
            "exit": _ENGINE_EXIT,
        },
        peer_material_provider=peer,
    )
    before_profile = VlessXhttpPlugin().generate_client_config(business, state)
    contributions = renderer.render(state)
    assert len(contributions.users) == 1
    entry_subject = contributions.users[0]
    assert entry_subject.email != business.email
    assert entry_subject.uuid != business.uuid
    fragment = contributions.fragments["managed_node_cascades"]
    assert fragment.outbounds[0]["type"] == "vless"
    assert fragment.outbounds[0]["uuid"] == transit.uuid
    assert fragment.route_rules == [
        {"auth_user": [entry_subject.email], "outbound": fragment.outbounds[0]["tag"]},
        {"auth_user": [entry_subject.email], "action": "reject"},
    ]

    seen = []
    container = PluginContainer(
        [VlessXhttpPlugin()],
        host=_Host(),
        runtime_contributions=lambda current: seen.append(current) or renderer.render(current),
    )
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "exists", lambda _path: True)
        fragments = container.collect_fragments(state)
    config = generate_config(state, fragments)
    inbound = next(item for item in config["inbounds"] if item["type"] == "vless")
    assert seen == [state]
    assert {item["uuid"] for item in inbound["users"]} == {business.uuid, entry_subject.uuid}
    assert config["route"]["rules"][:2] == fragment.route_rules
    assert VlessXhttpPlugin().generate_client_config(business, state) == before_profile
    assert state.users == [business]
    assert repr(contributions).find(entry_subject.uuid) == -1


def test_cascade_renderer_uses_canonical_anytls_credentials(tmp_path: Path) -> None:
    route = _route("anytls")
    business = User("direct@example.test", "business-uuid")
    state = _state("anytls", business, route=route)
    credentials = CascadeCredentialStore(host=_Host(), root=tmp_path / "cascade-credentials")
    credentials.prepare(route.id)
    scope = credentials.load(route.id)
    expected_transit = scope.subject("exit", "anytls", "transit", business)
    seed_hex = scope._seed.hex()

    renderer = ManagedNodeCascadeRenderer(
        participant_id="base",
        credentials=credentials,
        permit_provider=lambda _state, _route, _protocol: _permit(route, "anytls"),
        engine_fingerprints_provider=lambda _state, _route: {
            "base": _ENGINE_ENTRY,
            "exit": _ENGINE_EXIT,
        },
        peer_material_provider=lambda _state, selected, protocol, user, transit, permit: _canonical_peer(
            protocol,
            selected,
            user,
            transit,
        ),
    )
    contributions = renderer.render(state)
    subject = contributions.users[0]
    outbound = contributions.fragments["managed_node_cascades"].outbounds[0]
    expected_document = json.loads(AnyTLSPlugin().generate_client_config(expected_transit, _exit_state("anytls")))
    expected_outbound = next(item for item in expected_document["outbounds"] if item["type"] == "anytls")
    assert outbound["password"] == expected_outbound["password"]
    assert outbound["password"] != AnyTLSPlugin._derive_password(business.uuid)
    peer_material = _canonical_peer("anytls", route, business, expected_transit)
    assert expected_transit.uuid not in repr(expected_transit)
    assert subject.uuid not in repr(subject)
    assert seed_hex not in repr(expected_transit)
    assert repr(outbound["password"]) not in repr(peer_material)
    assert seed_hex not in repr(peer_material)
    assert subject.uuid not in repr(contributions)
    assert seed_hex not in repr(contributions)
    assert repr(outbound["password"]) not in repr(contributions)
    assert contributions.fragments["managed_node_cascades"].route_rules[0] == {
        "auth_user": [subject.email],
        "outbound": outbound["tag"],
    }
    assert repr(contributions).find(expected_outbound["password"]) == -1

    container = PluginContainer(
        [AnyTLSPlugin()],
        host=_Host(),
        runtime_contributions=lambda current: renderer.render(current),
    )
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "exists", lambda _path: True)
        fragments = container.collect_fragments(state)
    config = generate_config(state, fragments)
    inbound = next(item for item in config["inbounds"] if item["type"] == "anytls")
    assert {item["name"] for item in inbound["users"]} == {business.email, subject.email}
    assert len(config["route"]["rules"]) == 2


def test_cascade_renderer_is_fail_closed_for_expiry_engine_drift_and_missing_material(tmp_path: Path) -> None:
    route = _route("vless")
    business = User("expired@example.test", "business-uuid", expiry_date=(date.today() - timedelta(days=1)).isoformat())
    expired_state = _state("vless", business, route=route)
    store = CascadeCredentialStore(host=_Host(), root=tmp_path / "cascade-credentials")
    store.prepare(route.id)
    renderer = ManagedNodeCascadeRenderer(
        participant_id="base",
        credentials=store,
        permit_provider=lambda _state, _route, _protocol: _permit(route),
        engine_fingerprints_provider=lambda _state, _route: {
            "base": _ENGINE_ENTRY,
            "exit": "9" * 64,
        },
        peer_material_provider=lambda *_args: None,
    )
    assert not renderer.render(expired_state).users
    assert not renderer.render(_state("vless", User("active@example.test", "active-uuid"), route=route)).users

    current_state = _state("vless", User("active@example.test", "active-uuid"), route=route)
    current = ManagedNodeCascadeRenderer(
        participant_id="base",
        credentials=store,
        permit_provider=lambda _state, _route, _protocol: _permit(route),
        engine_fingerprints_provider=lambda _state, _route: {
            "base": _ENGINE_ENTRY,
            "exit": _ENGINE_EXIT,
        },
        peer_material_provider=lambda *_args: None,
    )
    with pytest.raises(ValueError, match="peer material"):
        current.render(current_state)

    scope = store.load(route.id)
    transit = scope.subject("exit", "vless", "transit", current_state.users[0])
    seed_hex = scope._seed.hex()

    def failing_peer(*_args):
        raise RuntimeError(f"private peer failure: {transit.uuid} {seed_hex}")

    unsafe_provider = ManagedNodeCascadeRenderer(
        participant_id="base",
        credentials=store,
        permit_provider=lambda _state, _route, _protocol: _permit(route),
        engine_fingerprints_provider=lambda _state, _route: {
            "base": _ENGINE_ENTRY,
            "exit": _ENGINE_EXIT,
        },
        peer_material_provider=failing_peer,
    )
    with pytest.raises(ValueError, match="peer material provider failed") as error:
        unsafe_provider.render(current_state)
    assert transit.uuid not in str(error.value)
    assert seed_hex not in str(error.value)


def test_opposite_cascade_routes_keep_transit_direct_and_entry_scoped(tmp_path: Path) -> None:
    business = User("direct@example.test", "business-uuid")
    forward = _route("vless")
    reverse = CascadeDefinition("reverse", "Reverse", "exit", "base", ["vless"])
    state = _state("vless", business, route=forward)
    state.protocols["anytls"] = PluginState(
        enabled=True,
        installed=True,
        config={"domain": "entry.example.test"},
    )
    vless_plugin = VlessXhttpPlugin()
    anytls_plugin = AnyTLSPlugin()
    direct_profiles = (
        vless_plugin.generate_client_config(business, state),
        anytls_plugin.generate_client_config(business, state),
    )
    namespace = managed_nodes_from_extensions(state.feature_extensions)
    namespace.cascades.append(reverse)
    store_managed_nodes(state.feature_extensions, namespace)
    credentials = CascadeCredentialStore(host=_Host(), root=tmp_path / "cascade-credentials")
    credentials.prepare(forward.id)
    credentials.prepare(reverse.id)
    renderer = ManagedNodeCascadeRenderer(
        participant_id="exit",
        credentials=credentials,
        permit_provider=lambda _state, route, protocol: _permit(route, protocol),
        engine_fingerprints_provider=lambda _state, route: {
            route.entry_id: _ENGINE_ENTRY,
            route.exit_id: _ENGINE_EXIT,
        },
        peer_material_provider=lambda _state, route, protocol, user, transit, _permit: _canonical_peer(
            protocol, route, user, transit
        ),
    )

    contributions = renderer.render(state)
    fragment = contributions.fragments["managed_node_cascades"]
    forward_transit = credentials.load(forward.id).subject("exit", "vless", "transit", business)
    reverse_entry = credentials.load(reverse.id).subject("exit", "vless", "entry", business)

    assert {user.uuid for user in contributions.users} == {
        forward_transit.uuid,
        reverse_entry.uuid,
    }
    assert {"auth_user": [forward_transit.email], "outbound": "direct"} in fragment.route_rules
    assert {"auth_user": [reverse_entry.email], "outbound": fragment.outbounds[0]["tag"]} in fragment.route_rules
    assert {"auth_user": [reverse_entry.email], "action": "reject"} in fragment.route_rules
    assert not any(
        rule.get("auth_user") == [forward_transit.email] and rule.get("outbound") != "direct"
        for rule in fragment.route_rules
    )
    container = PluginContainer(
        [vless_plugin, anytls_plugin],
        host=_Host(),
        runtime_contributions=renderer.render,
    )
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "exists", lambda _path: True)
        config = generate_config(state, container.collect_fragments(state))
    inbounds = {item["type"]: item for item in config["inbounds"]}
    assert {item["uuid"] for item in inbounds["vless"]["users"]} == {
        business.uuid,
        forward_transit.uuid,
        reverse_entry.uuid,
    }
    assert {item["name"] for item in inbounds["anytls"]["users"]} == {business.email}
    assert [item["type"] for item in config["outbounds"] if item["tag"].startswith("cascade-")] == ["vless"]
    assert vless_plugin.generate_client_config(business, state) == direct_profiles[0]
    assert anytls_plugin.generate_client_config(business, state) == direct_profiles[1]
    assert state.users == [business]


def test_production_render_contribution_wiring_is_state_aware_and_fail_closed(tmp_path: Path) -> None:
    route = _route("vless")
    first = _state("vless", User("one@example.test", "one"), route=route)
    second = _state("vless", User("two@example.test", "two", blocked=True), route=route)
    callback = production_runtime_contributions(
        host=_Host(),
        root=tmp_path / "managed-nodes",
    )

    assert not callback(first).users
    assert not callback(second).users
    assert not (tmp_path / "managed-nodes" / "cascade-credentials").exists()


def test_runtime_probe_subject_is_not_projected_to_unrelated_transport() -> None:
    business = User("direct@example.test", "business-uuid")
    state = AppState(
        protocols={"awg": PluginState(enabled=True, installed=True)},
        users=[business],
    )
    probe = RuntimeSubject("probe@invalid.hydra", "probe-uuid", ("vless", "anytls"))
    container = PluginContainer(
        [_UserEchoTransport()],
        host=_Host(),
        runtime_contributions=lambda _state: RuntimeRenderContributions((probe,)),
    )

    fragment = container.collect_fragments(state)["awg"]

    assert fragment.inbounds[0]["users"] == [
        {"name": business.email, "uuid": business.uuid},
    ]
    assert state.users == [business]


def test_production_render_contributions_reuse_probe_identity(tmp_path: Path) -> None:
    probe_identity = ManagedNodeProbeIdentityStore(
        host=_Host(),
        root=tmp_path / "managed-node",
        node_id="node-a",
    )
    expected_probe = probe_identity.ensure()
    callback = production_runtime_contributions(
        host=_Host(),
        root=tmp_path / "managed-nodes",
        probe_identity=probe_identity,
    )

    contributions = callback(_state("vless", User("business@example.test", "business")))

    assert [(user.email, user.uuid) for user in contributions.users] == [
        (expected_probe.email, expected_probe.uuid),
    ]
    assert contributions.users[0].protocols == ("vless", "anytls")
    assert probe_identity.user().uuid == expected_probe.uuid
