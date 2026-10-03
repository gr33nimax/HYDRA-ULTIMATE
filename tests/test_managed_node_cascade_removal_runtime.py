from __future__ import annotations

import copy
import json
from types import SimpleNamespace
from typing import cast

import pytest

from hydra.contracts.managed_node_cascade import CascadeParticipantRequest
from hydra.contracts.managed_node_models import CascadeDefinition, NodeDefinition, ProtocolAssignment, canonical_digest
from hydra.core.host import HostBackend
from hydra.core.singbox_config import generate_config
from hydra.core.state_managed_nodes import ManagedNodesState, store_managed_nodes
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.container import PluginContainer
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.vless_xhttp.plugin import VlessXhttpPlugin
from hydra.services.configuration import ConfigurationApplier
from hydra.services.managed_nodes.cascade_participant import installed_context_reader
from hydra.services.managed_nodes.cascade_rendering import CascadePeerMaterial, ManagedNodeCascadeRenderer
from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext
from hydra.services.managed_nodes.rendering import ProductionRuntimeContributions
from hydra.services.orchestration_service import OrchestrationService
from hydra.utils.crypto import derive_hex_key
from tests.test_managed_node_cascade_participant import _owner
from tests.test_managed_node_cascade_restoration import _Certificates, _outbound, _permit


def _remove_request(route, participant="base", protocol="vless"):
    plan = {"cascade_id": route.id, "previous": route.to_document(), "cascade": None}
    return CascadeParticipantRequest(
        "remove-operation",
        "cascade_remove",
        route.id,
        canonical_digest(plan),
        plan,
        participant,
        "entry" if participant == route.entry_id else "transit",
        route,
        protocol,
    )


def test_remove_without_target_render_evidence_rejects_before_effect(tmp_path):
    route = CascadeDefinition("remove-route", "Route", "base", "exit", ["vless"])
    request = _remove_request(route, "exit")
    calls = []
    owner, _records, _gate, _current, store, _credentials, _context = _owner(
        tmp_path,
        apply=lambda *_args: calls.append(True) or True,
        capture_restore_context=lambda _state, _operation, req: CascadeRestoreContext.empty(req),
    )
    owner.ensure_snapshot(request)
    with pytest.raises(ValueError, match="removal target.*unavailable"):
        owner.apply(request)
    assert calls == []
    record = store.record(request)
    assert record is not None and record["phase"] == "snapshotted"
    assert store._path(request, ".snapshot").exists()


def _canonical_scene(tmp_path, protocols=("vless",)):
    host = HostBackend()
    owner, records, gate, current, store, credentials, _context = _owner(tmp_path, participant="base")
    route = CascadeDefinition("remove-route", "Route", "base", "exit", list(protocols))
    unrelated = CascadeDefinition("keep-route", "Keep", "base", "exit", ["vless"])
    config_path, engine_path = tmp_path / "sing-box.json", tmp_path / "engine"
    engine_path.write_bytes(b"sandbox identity only, not engine capability evidence")
    state = AppState(
        users=[User("old@example.test", "business-old")],
        protocols={
            "vless": PluginState(
                enabled=True,
                installed=True,
                port=443,
                config={
                    "domain": "entry.example.test",
                    "cert_file": str(tmp_path / "entry.crt"),
                    "key_file": str(tmp_path / "entry.key"),
                    "xhttp_mode": "stream-up",
                    "xhttp_path": "/xhttp",
                    "security": "tls",
                },
            )
        },
    )
    if "anytls" in protocols:
        state.protocols["anytls"] = PluginState(
            enabled=True,
            installed=True,
            port=8443,
            config={
                "domain": "any.example.test",
                "cert_file": str(tmp_path / "any.crt"),
                "key_file": str(tmp_path / "any.key"),
            },
        )
    definition = NodeDefinition(
        "exit",
        "Exit",
        "203.0.113.9",
        "root",
        "dev",
        "a" * 40,
        25555,
        [ProtocolAssignment(protocol) for protocol in protocols],
        "managed-node/exit",
    )
    store_managed_nodes(
        state.feature_extensions, ManagedNodesState(definitions=[definition], cascades=[route, unrelated])
    )
    current[0] = state
    for item in (route, unrelated):
        credentials.prepare(item.id)
    renderer = ManagedNodeCascadeRenderer(
        participant_id="base",
        credentials=credentials,
        permit_provider=lambda _state, item, protocol: _permit(item, protocol),
        engine_fingerprints_provider=lambda _state, item: {item.entry_id: "4" * 64, item.exit_id: "5" * 64},
        peer_material_provider=lambda _state, item, protocol, user, transit, permit: CascadePeerMaterial(
            item.id,
            item.exit_id,
            protocol,
            permit.operation_id,
            user.uuid,
            permit.exit_receipt_sha256,
            _outbound(
                protocol,
                tag="peer",
                server="203.0.113.9",
                credential=(transit.uuid if protocol == "vless" else derive_hex_key("anytls-pass", transit.uuid)),
            ),
        ),
        restore_context_provider=store.restoration_contexts,
    )
    plugins = PluginContainer(
        [VlessXhttpPlugin(), AnyTLSPlugin()], host=host, runtime_contributions=ProductionRuntimeContributions(renderer)
    )
    singbox = SimpleNamespace(SINGBOX_CONFIG=config_path, generate_config=generate_config)
    service = OrchestrationService(
        plugins=plugins,
        singbox=singbox,
        nft=object(),
        host=host,
        save_state=lambda _state: None,
        get_protocol=lambda active, name: active.protocols[name],
        certificates=_Certificates(),
        traffic_daemon_service=tmp_path / "traffic.service",
        apply_journal=tmp_path / "apply.jsonl",
        apply_lock_file=tmp_path / "apply.lock",
        managed_node_apply_gate=gate,
    )
    calls = []

    def write(active):
        document = generate_config(active, plugins.collect_fragments(active))
        host.atomic_write(config_path, json.dumps(document, indent=2, ensure_ascii=False), mode=0o600, durable=True)
        calls.append(copy.deepcopy(document))
        return True

    service._configuration_applier = lambda: cast(ConfigurationApplier, SimpleNamespace(apply=write))
    write(current[0])
    owner._context = installed_context_reader(host, engine_path, config_path)
    owner._apply_config = service.apply_cascade_participant_config
    owner._capture_restore_context = service.capture_cascade_restore_context
    request = _remove_request(route)
    return owner, records, current, store, credentials, service, config_path, calls, request


@pytest.mark.parametrize("lose_response", [False, True])
def test_canonical_remove_changes_owned_config_and_recovers_without_stale_users(tmp_path, lose_response):
    owner, records, current, store, credentials, service, path, calls, request = _canonical_scene(tmp_path)
    # Production's internal preview port, not a caller-supplied digest or a fake apply receipt.
    preview = getattr(service, "capture_cascade_remove_config_identity", None)
    assert callable(preview), "the canonical removal target capture port is missing"
    setattr(owner, "_capture_remove_config_identity", preview)
    owner.ensure_snapshot(request)
    records.begin_step(request.operation_id, "snapshot")
    records.complete_step(request.operation_id, "snapshot")
    saved = store.restore_context(request)
    assert saved.users and saved.fragment.outbounds
    original_apply = owner._apply_config

    def apply_after_effect(state, authorization):
        result = original_apply(state, authorization)
        if lose_response:
            raise OSError("response lost after real canonical config write")
        return result

    owner._apply_config = apply_after_effect
    if lose_response:
        with pytest.raises(RuntimeError, match="response lost"):
            owner.apply(request)
    else:
        assert owner.apply(request).state == "applied"
    removed = json.loads(path.read_text(encoding="utf-8"))
    subjects = {user["name"] for inbound in removed["inbounds"] for user in inbound.get("users", [])}
    assert saved.users[0].email not in subjects
    assert not any(item.get("tag", "").startswith("cascade-remove-route-") for item in removed["outbounds"])
    assert any(item.get("tag", "").startswith("cascade-keep-route-") for item in removed["outbounds"])
    assert any(item.get("tag") == "direct" for item in removed["outbounds"])
    assert removed["route"]["final"] == "direct"
    assert store._path(request, ".snapshot").exists()
    if not lose_response:
        before_calls = len(calls)
        assert owner.apply(request).state == "applied"
        assert len(calls) == before_calls
        return
    current[0].users = [User("new@example.test", "business-new")]
    current[0].revision += 1  # a separate desired-user change, not rollback state restoration
    owner._apply_config = original_apply
    assert owner.rollback(request).state == "rolled_back"
    restored = json.loads(path.read_text(encoding="utf-8"))
    users = {user["uuid"] for inbound in restored["inbounds"] for user in inbound.get("users", [])}
    assert "business-new" in users and "business-old" not in users
    latest = credentials.load(request.target_id).subject("base", "vless", "entry", current[0].users[0])
    assert latest.uuid in users
    assert any(item.get("tag", "").startswith("cascade-remove-route-") for item in restored["outbounds"])
    assert any(item.get("tag", "").startswith("cascade-keep-route-") for item in restored["outbounds"])
    assert len(calls) == 3


@pytest.mark.parametrize("failure", ["invalid_target", "configuration_drift"])
def test_remove_rejects_invalid_or_stale_evidence_before_runtime_effect(tmp_path, failure):
    owner, records, current, store, _credentials, service, path, calls, request = _canonical_scene(tmp_path)
    owner._capture_remove_config_identity = service.capture_cascade_remove_config_identity
    owner.ensure_snapshot(request)
    records.begin_step(request.operation_id, "snapshot")
    records.complete_step(request.operation_id, "snapshot")
    snapshot = store._path(request, ".snapshot").read_bytes()
    if failure == "invalid_target":
        owner._capture_remove_config_identity = lambda *_args: "not-a-config-identity"
    else:
        path.write_bytes(b"{}")
    before = copy.deepcopy(current[0])
    runtime_before = path.read_bytes()
    with pytest.raises(ValueError, match="target identity|configuration changed before removal"):
        owner.apply(request)
    assert current[0] == before
    assert path.read_bytes() == runtime_before
    assert len(calls) == 1
    assert store._path(request, ".snapshot").read_bytes() == snapshot
    record = store.record(request)
    assert record is not None and record["phase"] == "snapshotted"


def test_remove_multiple_protocols_uses_confirmed_sibling_context_without_global_reroute(tmp_path):
    owner, records, _current, store, _credentials, service, path, calls, request = _canonical_scene(
        tmp_path, protocols=("vless", "anytls")
    )
    other = _remove_request(request.route, protocol="anytls")
    owner._capture_remove_config_identity = service.capture_cascade_remove_config_identity
    for scope in (request, other):
        owner.ensure_snapshot(scope)
    records.begin_step(request.operation_id, "snapshot")
    records.complete_step(request.operation_id, "snapshot")
    owner.apply(request)
    partial = json.loads(path.read_text(encoding="utf-8"))
    assert not any(item.get("tag", "").startswith("cascade-remove-route-vless-") for item in partial["outbounds"])
    # Local apply removes the frozen participant contribution atomically across its protocols.
    assert not any(item.get("tag", "").startswith("cascade-remove-route-anytls-") for item in partial["outbounds"])
    assert owner.apply(other).state == "applied"
    assert owner.status(request) == owner.status(other) == "applied"
    removed = json.loads(path.read_text(encoding="utf-8"))
    assert not any(item.get("tag", "").startswith("cascade-remove-route-") for item in removed["outbounds"])
    assert any(item.get("tag", "").startswith("cascade-keep-route-") for item in removed["outbounds"])
    assert removed["route"]["final"] == "direct"
    assert all(store._path(scope, ".snapshot").exists() for scope in (request, other))
    before_calls = len(calls)
    # A shaped caller digest is not the base coordinator's durable distributed commit.
    for scope in (request, other):
        with pytest.raises(ValueError, match="not durably committed"):
            owner.finalize(scope, "e" * 64)
        assert store._path(scope, ".snapshot").exists()
    assert len(calls) == before_calls


def test_remove_requires_all_local_protocol_snapshots_before_any_effect(tmp_path):
    owner, records, _current, store, _credentials, service, path, calls, request = _canonical_scene(
        tmp_path, protocols=("vless", "anytls")
    )
    owner._capture_remove_config_identity = service.capture_cascade_remove_config_identity
    owner.ensure_snapshot(request)  # AnyTLS's required pre-effect artifact is intentionally absent.
    records.begin_step(request.operation_id, "snapshot")
    records.complete_step(request.operation_id, "snapshot")
    baseline = path.read_bytes()
    with pytest.raises(ValueError, match="all local.*snapshots"):
        owner.apply(request)
    assert path.read_bytes() == baseline
    assert len(calls) == 1
    record = store.record(request)
    assert record is not None and record["phase"] == "snapshotted"
