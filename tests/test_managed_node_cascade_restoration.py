from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from hydra.contracts import ConfigFragment, RuntimeSubject
from hydra.contracts.managed_node_cascade import (
    CascadeParticipantReceipt,
    CascadeParticipantRequest,
    CascadeTechnicalMaterial,
)
from hydra.contracts.managed_node_models import (
    CascadeDefinition,
    NodeDefinition,
    Operation,
    ProtocolAssignment,
    canonical_digest,
)
from hydra.core.host import HostBackend
from hydra.core.singbox_config import generate_config
from hydra.core.state_managed_nodes import ManagedNodesState, store_managed_nodes
from hydra.core.state_models import AppState, PluginState, User
from hydra.plugins.container import PluginContainer
from hydra.plugins.vless_xhttp.plugin import VlessXhttpPlugin
from hydra.services.configuration import ConfigurationApplier
from hydra.services.managed_nodes.apply_gate import ManagedNodeApplyGate
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.cascade_participant import ManagedNodeCascadeParticipant, technical_peer_provider
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_preparation import (
    CascadePreparationEvidence,
    CascadePreparationStore,
    ManagedNodeCascadePreparationOwner,
)
from hydra.services.managed_nodes.cascade_rendering import (
    CascadePeerMaterial,
    CascadeRenderPermit,
    ManagedNodeCascadeRenderer,
)
from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext
from hydra.services.managed_nodes.rendering import ProductionRuntimeContributions
from hydra.services.orchestration_service import OrchestrationService
from hydra.utils.crypto import derive_hex_key

_ENGINE, _BASELINE, _PREPARED = (value * 64 for value in "123")
_ENTRY_ENGINE, _EXIT_ENGINE = (value * 64 for value in "45")
_PROOF, _RECEIPT, _PATH_PROOF = (value * 64 for value in "678")


class _Certificates:
    def ensure(self, domain: str, config: dict) -> tuple[str, str]:
        raise AssertionError("the canonical config test must not request certificates")


class _CanonicalConfigWriter:
    def __init__(self, *, plugins, singbox, host, config_path, participant_store, operation_id, context):
        self._plugins = plugins
        self._singbox = singbox
        self._host = host
        self._path = config_path
        self._store = participant_store
        self._operation_id = operation_id
        self._context = context
        self.configs = []

    def apply(self, state):
        fragments = self._plugins.collect_fragments(state)
        config = self._singbox.generate_config(state, fragments)
        self._host.atomic_write(self._path, json.dumps(config, indent=2), mode=0o600, durable=True)
        self.configs.append(copy.deepcopy(config))
        request = self._store.request_for(self._operation_id, "base", "vless")
        phase = self._store.record(request)["phase"] if request is not None else "snapshot"
        self._context[1] = _PREPARED if phase in {"applying", "applied"} else _BASELINE
        return True


def _permit(route: CascadeDefinition, protocol: str) -> CascadeRenderPermit:
    return CascadeRenderPermit(
        route.id,
        route.entry_id,
        route.exit_id,
        protocol,
        "old-cascade-publication",
        _ENTRY_ENGINE,
        _EXIT_ENGINE,
        _PROOF,
        _PROOF,
        _RECEIPT,
        _RECEIPT,
        _PATH_PROOF,
    )


def _outbound(protocol: str, *, tag: str, server: str, credential: str) -> dict:
    secret = "uuid" if protocol == "vless" else "password"
    return {
        "type": protocol,
        "tag": tag,
        "server": server,
        "server_port": 443,
        secret: credential,
        "tls": {"enabled": True, "server_name": "exit.example.test"},
    }


@pytest.mark.parametrize(
    ("participant", "protocol"), (("base", "vless"), ("base", "anytls"), ("exit", "vless"), ("exit", "anytls"))
)
def test_restore_rebuilds_only_current_business_users(tmp_path, participant, protocol):
    host = HostBackend()
    route = CascadeDefinition("route-transit-restore", "Route", "base", "exit", ["vless", "anytls"])
    plan = {"cascade_id": route.id, "previous": route.to_document(), "cascade": route.to_document()}
    digest = canonical_digest(plan)
    request = CascadeParticipantRequest(
        "transit-restore",
        "cascade_save",
        route.id,
        digest,
        plan,
        participant,
        "entry" if participant == "base" else "transit",
        route,
        protocol,
    )
    credentials = CascadeCredentialStore(host=host, root=tmp_path / "credentials")
    credentials.prepare(route.id)
    old = User("old@example.test", "business-old")
    scope = credentials.load(route.id)
    role = "entry" if participant == "base" else "transit"
    old_subject = scope.subject(participant, protocol, role, old)
    old_transit = scope.subject("exit", protocol, "transit", old)
    old_tag = f"cascade-{route.id}-{protocol}-old"
    rules = [{"auth_user": [old_subject.email], "outbound": "direct"}]
    outbounds = []
    if participant == "base":
        credential = old_transit.uuid if protocol == "vless" else derive_hex_key("anytls-pass", old_transit.uuid)
        outbounds = [_outbound(protocol, tag=old_tag, server="203.0.113.10", credential=credential)]
        rules = [
            {"auth_user": [old_subject.email], "outbound": old_tag},
            {"auth_user": [old_subject.email], "action": "reject"},
        ]
    context = CascadeRestoreContext(
        route.id,
        route.entry_id,
        route.exit_id,
        request.operation_id,
        digest,
        participant,
        protocol,
        (old.uuid,),
        (RuntimeSubject(old_subject.email, old_subject.uuid, (protocol,)),),
        ConfigFragment(outbounds=outbounds, route_rules=rules),
    )
    context.validate_for(request)

    latest = User("new@example.test", "business-new")
    state = AppState(protocols={protocol: PluginState(enabled=True)}, users=[latest])
    users, fragment = context.render_current_users(state, credentials, participant)
    expected_subject = scope.subject(participant, protocol, role, latest)
    assert users == (RuntimeSubject(expected_subject.email, expected_subject.uuid, (protocol,)),)
    assert old_subject.email not in {item.email for item in users}
    if participant == "exit":
        assert fragment.outbounds == []
        assert fragment.route_rules == [{"auth_user": [expected_subject.email], "outbound": "direct"}]
    else:
        expected_transit = scope.subject("exit", protocol, "transit", latest)
        key = "uuid" if protocol == "vless" else "password"
        value = expected_transit.uuid if protocol == "vless" else derive_hex_key("anytls-pass", expected_transit.uuid)
        tag = f"cascade-{route.id}-{protocol}-{hashlib.sha256(expected_subject.uuid.encode()).hexdigest()[:12]}"
        assert fragment.outbounds[0][key] == value
        assert fragment.outbounds[0]["tag"] == tag
        assert fragment.route_rules == [
            {"auth_user": [expected_subject.email], "outbound": tag},
            {"auth_user": [expected_subject.email], "action": "reject"},
        ]


def test_canonical_rollback_restores_prior_owned_context_and_latest_main_state(tmp_path):
    host = HostBackend()
    config_path = tmp_path / "sing-box.json"
    engine_path = tmp_path / "sing-box"
    engine_path.write_bytes(b"temporary test engine identity")
    old_route = CascadeDefinition("route-restore", "Old route", "base", "exit", ["vless"])
    candidate = CascadeDefinition("route-restore", "Edited route", "base", "exit", ["vless"])
    operation_id = "cascade-restore"
    plan = {"cascade_id": old_route.id, "previous": old_route.to_document(), "cascade": candidate.to_document()}
    operation = Operation(operation_id, "cascade_save", old_route.id, canonical_digest(plan), "pending", plan=plan)
    old_user = User("old@example.test", "business-old")
    state = AppState(
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
            ),
        },
        users=[old_user],
    )
    store_managed_nodes(
        state.feature_extensions,
        ManagedNodesState(
            definitions=[
                NodeDefinition(
                    "exit",
                    "Exit",
                    "203.0.113.9",
                    "root",
                    "dev",
                    "a" * 40,
                    25555,
                    [ProtocolAssignment("vless")],
                    "managed-node/exit",
                ),
            ],
            cascades=[old_route],
        ),
    )
    current = [copy.deepcopy(state)]
    gate = ManagedNodeApplyGate(
        state_reader=lambda: copy.deepcopy(current[0]),
        participant_id="base",
        lock_path=tmp_path / "apply-gate.lock",
        authenticated_participant=lambda _operation: "base",
    )

    def update(mutator):
        fresh = copy.deepcopy(current[0])
        result = mutator(fresh)
        fresh.revision += 1
        current[0] = fresh
        return copy.deepcopy(fresh), copy.deepcopy(result)

    state_updater = gate.wrap_state_updater(update)
    from hydra.services.managed_nodes.records import ManagedNodeRecords

    records = ManagedNodeRecords(state_reader=lambda: copy.deepcopy(current[0]), state_updater=state_updater)
    store = CascadeParticipantStore(host=host, root=tmp_path / "transactions")
    credentials = CascadeCredentialStore(host=host, root=tmp_path / "credentials")
    credentials.prepare(old_route.id)
    preparations = ManagedNodeCascadePreparationOwner(
        records=records,
        state_reader=lambda: copy.deepcopy(current[0]),
        credentials=credentials,
        store=CascadePreparationStore(host=host, root=tmp_path / "preparations"),
        participant_id="base",
        authenticated_participant=lambda _operation, _route: "base",
        evidence_provider=lambda *_args: CascadePreparationEvidence(_ENGINE, _BASELINE, _PREPARED, _BASELINE),
        renderable_operation=store.can_render,
    )
    cascade_renderer = ManagedNodeCascadeRenderer(
        participant_id="base",
        credentials=credentials,
        permit_provider=lambda _state, route, protocol: _permit(route, protocol),
        engine_fingerprints_provider=lambda _state, route: {
            route.entry_id: _ENTRY_ENGINE,
            route.exit_id: _EXIT_ENGINE,
        },
        peer_material_provider=lambda _state, route, protocol, user, transit, permit: CascadePeerMaterial(
            route.id,
            route.exit_id,
            protocol,
            permit.operation_id,
            user.uuid,
            permit.exit_receipt_sha256,
            _outbound(protocol, tag="old-peer", server="203.0.113.9", credential=transit.uuid),
        ),
        technical_preparation_provider=preparations.preparations_for_render,
        technical_peer_material_provider=technical_peer_provider(store, "base"),
        restore_context_provider=store.restoration_contexts,
    )
    runtime_contributions = ProductionRuntimeContributions(cascade_renderer)
    plugins = PluginContainer([VlessXhttpPlugin()], host=host, runtime_contributions=runtime_contributions)
    singbox = SimpleNamespace(SINGBOX_CONFIG=config_path, generate_config=generate_config)
    orchestration = OrchestrationService(
        plugins=plugins,
        singbox=singbox,
        nft=object(),
        host=host,
        save_state=lambda _state: None,
        get_protocol=lambda current_state, name: current_state.protocols[name],
        certificates=_Certificates(),
        traffic_daemon_service=tmp_path / "traffic.service",
        apply_journal=tmp_path / "apply.jsonl",
        apply_lock_file=tmp_path / "apply.lock",
        managed_node_apply_gate=gate,
    )
    writer_context = [_ENGINE, _BASELINE]
    writer = _CanonicalConfigWriter(
        plugins=plugins,
        singbox=singbox,
        host=host,
        config_path=config_path,
        participant_store=store,
        operation_id=operation_id,
        context=writer_context,
    )
    orchestration._configuration_applier = lambda: cast(ConfigurationApplier, writer)
    initial = generate_config(current[0], plugins.collect_fragments(current[0]))
    host.atomic_write(config_path, json.dumps(initial, indent=2), mode=0o600, durable=True)

    records.begin_operation(operation)
    request = CascadeParticipantRequest(
        operation_id,
        "cascade_save",
        candidate.id,
        operation.desired_digest,
        plan,
        "base",
        "entry",
        candidate,
        "vless",
    )
    transfer = credentials.export_transfer(candidate.id)
    transit = credentials.load(candidate.id).technical_subject("exit", "vless", "transit", operation_id)
    peer_outbound = _outbound("vless", tag="technical-peer", server="203.0.113.10", credential=transit.uuid)
    exit_request = CascadeParticipantRequest(
        operation_id,
        "cascade_save",
        candidate.id,
        operation.desired_digest,
        plan,
        "exit",
        "transit",
        candidate,
        "vless",
    )
    exit_receipt = CascadeParticipantReceipt(
        operation_id,
        operation.desired_digest,
        candidate.id,
        "exit",
        "transit",
        "vless",
        "prepared",
        _ENGINE,
        _PREPARED,
        canonical_digest(peer_outbound),
    )
    material = CascadeTechnicalMaterial(exit_receipt, peer_outbound)
    material.validate_for(exit_request)
    participant = ManagedNodeCascadeParticipant(
        participant_id="base",
        records=records,
        state_reader=lambda: copy.deepcopy(current[0]),
        gate=gate,
        store=store,
        preparation=preparations,
        credentials=credentials,
        context_reader=lambda: (writer_context[0], writer_context[1]),
        apply_config=orchestration.apply_cascade_participant_config,
        capture_restore_context=orchestration.capture_cascade_restore_context,
    )
    incorrect = copy.deepcopy(initial)
    incorrect["route"]["final"] = "reject"
    host.atomic_write(config_path, json.dumps(incorrect, indent=2), mode=0o600, durable=True)
    revision_before_capture = current[0].revision
    with pytest.raises(RuntimeError, match="differs from canonical owned rendering"):
        participant.ensure_snapshot(request)
    assert store.record(request) is None
    assert not store._path(request, ".snapshot").exists()
    assert current[0].revision == revision_before_capture + 1  # only the frozen operation ledger was persisted
    host.atomic_write(config_path, json.dumps(initial, indent=2), mode=0o600, durable=True)

    participant.ensure_snapshot(request)
    records.begin_step(operation_id, "snapshot")
    records.complete_step(operation_id, "snapshot")
    snapshot_path = store._path(request, ".snapshot")
    saved_context = store.restore_context(request)
    old_cascade_subject = saved_context.users[0]
    old_overlay_outbound = copy.deepcopy(saved_context.fragment.outbounds[0])
    participant.prepare(request, transfer, material)

    def lose_response_after_apply(state, authorization):
        applied = orchestration.apply_cascade_participant_config(state, authorization)
        assert applied is True
        raise OSError("simulated response loss after canonical runtime mutation")

    participant._apply_config = lose_response_after_apply
    with pytest.raises(RuntimeError, match="simulated response loss"):
        participant.apply(request)
    staged = json.loads(host.read_bytes(config_path, max_bytes=8 * 1024 * 1024))
    assert any(item.get("tag", "").startswith("cascade-stage-route-restore-vless-") for item in staged["outbounds"])
    assert snapshot_path.is_file()

    def add_latest_user(latest):
        latest.users = [User("new@example.test", "business-new")]

    state_updater(add_latest_user)

    rollback_results = iter(("lost", "confirmed"))

    def rollback_apply(state, authorization):
        applied = orchestration.apply_cascade_participant_config(state, authorization)
        assert applied is True
        if next(rollback_results) == "lost":
            raise OSError("simulated rollback response loss after restoration")
        return True

    restarted = ManagedNodeCascadeParticipant(
        participant_id="base",
        records=records,
        state_reader=lambda: copy.deepcopy(current[0]),
        gate=gate,
        store=CascadeParticipantStore(host=host, root=tmp_path / "transactions"),
        preparation=preparations,
        credentials=CascadeCredentialStore(host=host, root=tmp_path / "credentials"),
        context_reader=lambda: (writer_context[0], writer_context[1]),
        apply_config=rollback_apply,
        capture_restore_context=orchestration.capture_cascade_restore_context,
    )
    with pytest.raises(RuntimeError, match="rollback response loss"):
        restarted.rollback(request)
    assert snapshot_path.is_file()
    retained = store.restore_context(request)
    assert retained == saved_context

    assert restarted.rollback(request).state == "rolled_back"
    assert not snapshot_path.exists()
    restored = json.loads(host.read_bytes(config_path, max_bytes=8 * 1024 * 1024))
    vless_inbound = next(item for item in restored["inbounds"] if item["type"] == "vless")
    inbound_users = {item["uuid"] for item in vless_inbound["users"]}
    inbound_names = {item["name"] for item in vless_inbound["users"]}
    assert "business-old" not in inbound_users
    assert "business-new" in inbound_users
    assert old_cascade_subject.uuid not in inbound_users
    assert old_cascade_subject.email not in inbound_names
    latest_subject = credentials.load(candidate.id).subject(
        "base", "vless", "entry", User("new@example.test", "business-new")
    )
    latest_transit = credentials.load(candidate.id).subject(
        "exit", "vless", "transit", User("new@example.test", "business-new")
    )
    latest_tag = f"cascade-{candidate.id}-vless-{hashlib.sha256(latest_subject.uuid.encode()).hexdigest()[:12]}"
    assert latest_subject.uuid in inbound_users
    assert latest_subject.email in inbound_names
    assert any(
        item.get("tag") == latest_tag and item.get("uuid") == latest_transit.uuid for item in restored["outbounds"]
    )
    assert restored["route"]["final"] == "direct"
    assert not any(item == old_overlay_outbound for item in restored["outbounds"])
    assert any(item.get("tag") == "direct" for item in restored["outbounds"])
    assert not any(item.get("tag", "").startswith("cascade-stage-") for item in restored["outbounds"])
    assert any(
        rule.get("auth_user") == [latest_subject.email] and rule.get("outbound") == latest_tag
        for rule in restored["route"]["rules"]
    )
    assert current[0].users[-1].uuid == "business-new"
