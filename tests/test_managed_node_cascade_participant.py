from __future__ import annotations

import copy
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from hydra.contracts.managed_node_cascade import (
    CascadeParticipantReceipt,
    CascadeParticipantRequest,
    CascadeTechnicalMaterial,
)
from hydra.contracts.managed_node_models import CascadeDefinition, Operation, canonical_digest
from hydra.core.host import HostBackend
from hydra.core.state_managed_nodes import ManagedNodesState, store_managed_nodes
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.agent import ManagedNodeAgent
from hydra.services.managed_nodes.apply_gate import ManagedNodeApplyGate
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore, CascadeCredentialTransfer
from hydra.services.managed_nodes.cascade_participant import ManagedNodeCascadeParticipant
from hydra.services.managed_nodes.cascade_runtime_service import ManagedNodeCascadeRuntime
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_preparation import (
    CascadePreparationEvidence,
    CascadePreparationStore,
    ManagedNodeCascadePreparationOwner,
)
from hydra.services.managed_nodes.client import ManagedNodeClient, ManagedNodeError
from hydra.services.managed_nodes.identity import ManagementIdentity, certificate_fingerprint, create_certificate_pair
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.transport import ManagedNodeServer
from hydra.utils.crypto import derive_hex_key

_ENGINE, _BASELINE, _PREPARED = (value * 64 for value in "123")


def _request(operation_id: str = "cascade-tx", *, participant: str = "exit") -> CascadeParticipantRequest:
    route = (
        CascadeDefinition("route-tx", "Route", "exit", "base", ["vless"])
        if participant == "base"
        else CascadeDefinition("route-tx", "Route", "base", "exit", ["vless"])
    )
    plan = {"cascade_id": route.id, "previous": None, "cascade": route.to_document()}
    return CascadeParticipantRequest(
        operation_id,
        "cascade_save",
        route.id,
        canonical_digest(plan),
        plan,
        participant,
        "transit",
        route,
        "vless",
    )


def _owner(tmp_path: Path, *, participant: str = "exit", apply=None, context=None, capture_restore_context=None):
    state = AppState()
    current = [copy.deepcopy(state)]
    gate = ManagedNodeApplyGate(
        state_reader=lambda: copy.deepcopy(current[0]),
        participant_id=participant,
        lock_path=tmp_path / "apply-gate.lock",
        authenticated_participant=lambda _operation: participant,
    )

    def update(mutator):
        candidate = copy.deepcopy(current[0])
        result = mutator(candidate)
        candidate.revision += 1
        current[0] = candidate
        return copy.deepcopy(candidate), copy.deepcopy(result)

    records = ManagedNodeRecords(
        state_reader=lambda: copy.deepcopy(current[0]),
        state_updater=gate.wrap_state_updater(update),
    )
    host = HostBackend()
    store = CascadeParticipantStore(host=host, root=tmp_path / "transactions")
    credentials = CascadeCredentialStore(host=host, root=tmp_path / "credentials")
    preparations = ManagedNodeCascadePreparationOwner(
        records=records,
        state_reader=lambda: copy.deepcopy(current[0]),
        credentials=credentials,
        store=CascadePreparationStore(host=host, root=tmp_path / "preparations"),
        participant_id=participant,
        authenticated_participant=lambda _operation, _route: participant,
        evidence_provider=lambda *_args: CascadePreparationEvidence(_ENGINE, _BASELINE, _PREPARED, _BASELINE),
        renderable_operation=store.can_render,
    )
    active_context = context if context is not None else [_ENGINE, _BASELINE]

    def read_context() -> tuple[str, str]:
        return str(active_context[0]), str(active_context[1])

    def client_material(_state, protocol, transit):
        key = "uuid" if protocol == "vless" else "password"
        value = transit.uuid if protocol == "vless" else derive_hex_key("anytls-pass", transit.uuid)
        return {
            "type": protocol,
            "tag": "technical-client",
            "server": "203.0.113.10",
            "server_port": 443,
            key: value,
            "tls": {"enabled": True, "server_name": "exit.example.test"},
        }

    owner = ManagedNodeCascadeParticipant(
        participant_id=participant,
        records=records,
        state_reader=lambda: copy.deepcopy(current[0]),
        gate=gate,
        store=store,
        preparation=preparations,
        credentials=credentials,
        context_reader=read_context,
        apply_config=apply or (lambda _state, _authorization: True),
        client_material=client_material,
        capture_restore_context=capture_restore_context,
    )
    return owner, records, gate, current, store, credentials, active_context


def _coordinator_transfer(tmp_path: Path, route_id: str = "route-tx"):
    store = CascadeCredentialStore(host=HostBackend(), root=tmp_path / "coordinator-credentials")
    store.prepare(route_id)
    return store.export_transfer(route_id)


def test_typed_request_binds_full_plan_receiver_role_and_protocol():
    request = _request()
    request.validate()
    with pytest.raises(ValueError, match="outside the frozen topology"):
        replace(request, participant_id="other").validate()
    with pytest.raises(ValueError, match="role"):
        replace(request, role="entry").validate()
    with pytest.raises(ValueError, match="protocol"):
        replace(request, protocol="anytls").validate()
    altered = dict(request.plan, extra=True)
    with pytest.raises(ValueError, match="plan"):
        replace(request, plan=altered).validate()
    with pytest.raises(ValueError, match="role"):
        replace(request, participant_id="base").validate()


def test_participant_prepare_apply_query_restart_rollback_and_lease_release(tmp_path: Path):
    owner, records, gate, current, store, credentials, context = _owner(tmp_path)
    request = _request()
    transfer = _coordinator_transfer(tmp_path)

    snapshot = owner.ensure_snapshot(request)
    assert snapshot.state == "snapshotted"
    prepared = owner.prepare(request, transfer)
    assert prepared.state == "prepared" and prepared.material_digest
    assert repr(transfer) == "CascadeCredentialTransfer(<protected>)"
    assert repr(prepared) == "CascadeParticipantReceipt(<protected>)"
    assert owner.status(request) == "not_applied"

    context[1] = _PREPARED
    applied = owner.apply(request)
    assert applied.state == "applied"
    assert owner.status(request) == "applied"
    repeated_snapshot = owner.ensure_snapshot(request)
    assert repeated_snapshot.engine_identity == _ENGINE and repeated_snapshot.config_identity == _BASELINE
    applied_record = store.record(request)
    assert applied_record is not None and applied_record["phase"] == "applied"
    assert store._path(request, ".snapshot").is_file()

    restarted = ManagedNodeCascadeParticipant(
        participant_id="exit",
        records=records,
        state_reader=lambda: copy.deepcopy(current[0]),
        gate=gate,
        store=CascadeParticipantStore(host=HostBackend(), root=tmp_path / "transactions"),
        preparation=ManagedNodeCascadePreparationOwner(
            records=records,
            state_reader=lambda: copy.deepcopy(current[0]),
            credentials=credentials,
            store=CascadePreparationStore(host=HostBackend(), root=tmp_path / "preparations"),
            participant_id="exit",
            authenticated_participant=lambda _operation, _route: "exit",
            evidence_provider=lambda *_args: CascadePreparationEvidence(_ENGINE, _BASELINE, _PREPARED, _BASELINE),
        ),
        credentials=CascadeCredentialStore(host=HostBackend(), root=tmp_path / "credentials"),
        context_reader=lambda: (context[0], context[1]),
        apply_config=lambda _state, _authorization: True,
    )
    assert restarted.status(request) == "applied"
    rolled_back = restarted.rollback(request)
    assert rolled_back.state == "rolled_back"
    assert not store._path(request, ".snapshot").exists()
    assert records.find_operation(request.operation_id) is None
    assert not credentials.exists("route-tx")
    with pytest.raises(ValueError, match="already terminal"):
        restarted.ensure_snapshot(request)
    with pytest.raises(ValueError, match="immutable"):
        store.update(request, phase="rolled_back", before_config_identity="f" * 64)
    with gate.application():
        pass


def test_apply_failure_is_unknown_until_idempotent_rollback_confirms_cleanup(tmp_path: Path):
    context = [_ENGINE, _BASELINE]
    apply_results = iter((False, True))
    owner, records, _gate, _current, store, _credentials, _context = _owner(
        tmp_path,
        apply=lambda _state, _authorization: next(apply_results),
        context=context,
    )
    request = _request()
    transfer = _coordinator_transfer(tmp_path)
    owner.ensure_snapshot(request)
    owner.prepare(request, transfer)

    with pytest.raises(RuntimeError, match="did not confirm"):
        owner.apply(request)
    assert owner.status(request) == "unknown"
    failed_record = store.record(request)
    assert failed_record is not None and failed_record["phase"] == "recovery_required"
    assert records.find_operation(request.operation_id) is not None
    assert owner.rollback(request).state == "rolled_back"
    assert records.find_operation(request.operation_id) is None


def test_response_loss_after_effect_is_unknown_and_replay_is_forbidden_until_rollback(tmp_path: Path):
    context = [_ENGINE, _BASELINE]
    attempts = []

    def apply_after_effect(_state, _authorization):
        attempts.append(True)
        context[1] = _PREPARED if len(attempts) == 1 else _BASELINE
        if len(attempts) == 1:
            raise OSError("response lost after runtime mutation")
        return True

    owner, _records, _gate, _current, _store, _credentials, _context = _owner(
        tmp_path, apply=apply_after_effect, context=context
    )
    request = _request()
    owner.ensure_snapshot(request)
    owner.prepare(request, _coordinator_transfer(tmp_path))

    with pytest.raises(RuntimeError, match="response lost"):
        owner.apply(request)
    assert owner.status(request) == "unknown"
    with pytest.raises(ValueError, match="not safely replayable"):
        owner.apply(request)
    assert len(attempts) == 1
    assert owner.rollback(request).state == "rolled_back"
    assert len(attempts) == 2


def test_real_pinned_mtls_client_agent_participant_roundtrip(tmp_path: Path):
    request = _request()
    owner, records, _gate, _current, _store, _credentials, _context = _owner(tmp_path)
    client_cert, client_key = create_certificate_pair("base", role="client")
    server_cert, server_key = create_certificate_pair("exit", role="server", address="127.0.0.1")
    client_certificate = tmp_path / "base.crt"
    client_private_key = tmp_path / "base.key"
    server_certificate = tmp_path / "exit.crt"
    server_private_key = tmp_path / "exit.key"
    trusted_client = tmp_path / "trusted-base.crt"
    client_certificate.write_bytes(client_cert)
    client_private_key.write_bytes(client_key)
    server_certificate.write_bytes(server_cert)
    server_private_key.write_bytes(server_key)
    trusted_client.write_bytes(client_cert)
    identity = ManagementIdentity(
        "exit",
        "127.0.0.1",
        0,
        server_certificate,
        server_private_key,
        trusted_client,
        certificate_fingerprint(client_cert),
        ("127.0.0.1",),
    )
    agent = ManagedNodeAgent(
        node_id="exit",
        state_provider=lambda: pytest.fail("state endpoint not expected"),
        submit_provider=None,
        operation_provider=records.find_operation,
        profiles_provider=None,
        cascade_participant=owner,
    )
    with ManagedNodeServer(identity, agent, bind_host="127.0.0.1", request_timeout=2) as server:
        client = ManagedNodeClient(
            host="127.0.0.1",
            port=server.port,
            node_id="exit",
            certificate=client_certificate,
            private_key=client_private_key,
            pinned_server_certificate=server_cert,
        )
        receipt = client.cascade_snapshot(request, time.monotonic() + 3)
        assert receipt.state == "snapshotted"
        assert client.cascade_status(request, time.monotonic() + 3).state == "not_applied"
        wrong = replace(request, participant_id="base", role="entry")
        with pytest.raises(ManagedNodeError):
            client.cascade_snapshot(wrong, time.monotonic() + 3)


def test_prepared_transit_material_is_protected_and_bound_to_its_receipt(tmp_path: Path):
    owner, _records, _gate, _current, store, _credentials, context = _owner(tmp_path)
    request = _request()
    transfer = _coordinator_transfer(tmp_path)
    owner.ensure_snapshot(request)
    receipt = owner.prepare(request, transfer)
    material = owner.technical_material(request)

    assert material.receipt == receipt
    assert material.outbound["uuid"]
    assert "uuid" not in repr(material)
    assert owner.prepare(request, transfer).state == "prepared"
    with pytest.raises(ValueError, match="immutable for this route"):
        owner.prepare(request, _coordinator_transfer(tmp_path / "other-coordinator"))
    context[1] = _PREPARED
    assert owner.apply(request).state == "applied"
    assert owner.technical_material(request).receipt == receipt
    stored = store.record(request)
    assert stored is not None and stored["material"]["outbound"]["uuid"] == material.outbound["uuid"]
    forged = replace(material, receipt=replace(receipt, plan_digest="f" * 64))
    with pytest.raises(ValueError, match="another request"):
        forged.validate_for(request)


@pytest.mark.parametrize(
    ("entry_id", "exit_id"),
    [("base", "exit"), ("entry", "base"), ("entry", "exit")],
)
def test_production_runtime_roundtrips_local_and_remote_roles_over_pinned_mtls(
    tmp_path: Path, entry_id: str, exit_id: str
):
    route = CascadeDefinition("route-tx", "Route", entry_id, exit_id, ["vless", "anytls"])
    plan = {"cascade_id": route.id, "previous": None, "cascade": route.to_document()}
    operation = Operation("cascade-full", "cascade_save", route.id, canonical_digest(plan), "pending", plan=plan)
    base = _owner(tmp_path / "base", participant="base")
    base_owner, base_records, _gate, _current, base_store, base_credentials, base_context = base
    base_records.begin_operation(operation)
    base_records.begin_step(operation.id, "snapshot")
    base_records.complete_step(operation.id, "snapshot")
    base_credentials.prepare(route.id)

    client_cert, client_key = create_certificate_pair("base", role="client")
    client_certificate = tmp_path / "base-client.crt"
    client_private_key = tmp_path / "base-client.key"
    client_certificate.write_bytes(client_cert)
    client_private_key.write_bytes(client_key)
    remote_ids = sorted({entry_id, exit_id} - {"base"})
    owners = {"base": base_owner}
    owner_data_by_id = {"base": base}
    clients = {}

    with ExitStack() as stack:
        for node_id in remote_ids:
            node_root = tmp_path / node_id
            node_root.mkdir(parents=True)
            owner_data = _owner(node_root, participant=node_id)
            owner = owner_data[0]
            owners[node_id] = owner
            owner_data_by_id[node_id] = owner_data
            server_cert, server_key = create_certificate_pair(node_id, role="server", address="127.0.0.1")
            cert_path, key_path, trusted_path = (
                node_root / f"{node_id}.crt",
                node_root / f"{node_id}.key",
                node_root / "base.crt",
            )
            cert_path.write_bytes(server_cert)
            key_path.write_bytes(server_key)
            trusted_path.write_bytes(client_cert)
            identity = ManagementIdentity(
                node_id,
                "127.0.0.1",
                0,
                cert_path,
                key_path,
                trusted_path,
                certificate_fingerprint(client_cert),
                ("127.0.0.1",),
            )
            agent = ManagedNodeAgent(
                node_id=node_id,
                state_provider=lambda: pytest.fail("unexpected state query"),
                submit_provider=None,
                operation_provider=owner_data[1].find_operation,
                profiles_provider=None,
                cascade_participant=owner,
            )
            server = stack.enter_context(ManagedNodeServer(identity, agent, bind_host="127.0.0.1", request_timeout=2))
            clients[node_id] = ManagedNodeClient(
                host="127.0.0.1",
                port=server.port,
                node_id=node_id,
                certificate=client_certificate,
                private_key=client_private_key,
                pinned_server_certificate=server_cert,
            )

        runtime = ManagedNodeCascadeRuntime(
            records=base_records,
            local=base_owner,
            credentials=base_credentials,
            client_factory=lambda node_id: clients[node_id],
        )
        participants = sorted({entry_id, exit_id})
        for participant_id in participants:
            runtime.ensure_snapshot(operation.id, participant_id, None)
        runtime.prepare_participants(operation.id, route)
        for participant_id in participants:
            request = runtime._request(operation, participant_id, route, "vless")
            owner_data = owner_data_by_id.get(participant_id)
            if owner_data is not None:
                owner_data[6][1] = _PREPARED
            assert runtime.participant_status(operation.id, participant_id) == "not_applied"

        base_context[1] = _PREPARED
        base_records.begin_step(operation.id, "apply")
        for participant_id in participants:
            runtime.apply_participant(operation.id, participant_id, route)
        assert all(runtime.participant_status(operation.id, item) == "applied" for item in participants)
        base_records.complete_step(operation.id, "apply")
        assert runtime.verify_path(operation.id, route) is False
        with pytest.raises(RuntimeError, match="publication and billing are not wired"):
            runtime.commit_profiles(operation.id, route)

        base_records.begin_step(operation.id, "profiles")
        base_records.complete_step(operation.id, "profiles")
        base_records.commit_cascade_operation(operation.id, route)
        for participant_id in participants:
            assert runtime.finalize_participant(operation.id, participant_id, route) is True
        for participant_id in participants:
            owner_data = owner_data_by_id.get(participant_id)
            if owner_data is not None:
                owner = owners[participant_id]
                request = runtime._request(operation, participant_id, route, "vless")
                final_record = owner._store.record(request)
                assert final_record is not None and final_record["phase"] == "finalized"
                assert not owner._store._path(request, ".snapshot").exists()


def _entry_material(request, transfer: CascadeCredentialTransfer, seed_store: CascadeCredentialStore):
    seed_store.import_transfer(transfer)
    transit = seed_store.load(request.target_id).technical_subject(
        request.route.exit_id, request.protocol, "transit", request.operation_id
    )
    key = "uuid" if request.protocol == "vless" else "password"
    value = transit.uuid if request.protocol == "vless" else derive_hex_key("anytls-pass", transit.uuid)
    outbound = {
        "type": request.protocol,
        "tag": "test-peer",
        "server": "203.0.113.10",
        "server_port": 443,
        key: value,
        "tls": {"enabled": True, "server_name": "exit.example.test"},
    }
    receipt = CascadeParticipantReceipt(
        request.operation_id,
        request.plan_digest,
        request.target_id,
        request.route.exit_id,
        "transit",
        request.protocol,
        "prepared",
        _ENGINE,
        _PREPARED,
        canonical_digest(outbound),
    )
    material = CascadeTechnicalMaterial(receipt, outbound)
    material.validate_for(
        CascadeParticipantRequest(
            request.operation_id,
            request.kind,
            request.target_id,
            request.plan_digest,
            request.plan,
            request.route.exit_id,
            "transit",
            request.route,
            request.protocol,
        )
    )
    return material


def _private_files(tmp_path: Path) -> dict[str, bytes]:
    roots = (tmp_path / "credentials", tmp_path / "transactions", tmp_path / "preparations")
    return {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for root in roots
        if root.exists()
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("participant", ("base", "exit"))
def test_terminal_replay_and_wrong_scope_do_not_restore_credentials(tmp_path: Path, participant: str):
    owner, records, _gate, current, _store, credentials, _context = _owner(tmp_path, participant=participant)
    request = _request("cascade-terminal", participant=participant)
    wrong_store = CascadeCredentialStore(host=HostBackend(), root=tmp_path / "wrong-transfer")
    wrong_store.prepare("wrong-route")
    wrong_transfer = wrong_store.export_transfer("wrong-route")

    owner.ensure_snapshot(request)
    if participant == "base":
        records.begin_step(request.operation_id, "snapshot")
        records.complete_step(request.operation_id, "snapshot")
    transfer = _coordinator_transfer(tmp_path)
    seed_store = CascadeCredentialStore(host=HostBackend(), root=tmp_path / "coordinator-credentials")
    material = _entry_material(request, transfer, seed_store) if request.role == "entry" else None
    before_wrong_scope = _private_files(tmp_path)
    revision_before_wrong_scope = current[0].revision
    with pytest.raises(ValueError, match="does not match its frozen save route"):
        owner.prepare(request, wrong_transfer)
    assert _private_files(tmp_path) == before_wrong_scope
    assert current[0].revision == revision_before_wrong_scope

    owner.prepare(request, transfer, material)
    old_seed = credentials.load(request.target_id)._seed
    assert credentials.exists(request.target_id)
    owner.rollback(request)
    assert not credentials.exists(request.target_id)
    if participant == "base":
        records.fail_operation(
            request.operation_id, stage="test", reason="coordinator terminal failure", recovery_required=False
        )
    terminal_operation = records.find_operation(request.operation_id)
    assert terminal_operation is None or terminal_operation.state == "failed"

    before_terminal_retry = _private_files(tmp_path)
    revision_before_terminal_retry = current[0].revision
    with pytest.raises(ValueError, match="active frozen cascade participant lease"):
        owner.prepare(request, transfer, material)
    assert not credentials.exists(request.target_id)
    assert _private_files(tmp_path) == before_terminal_retry
    assert current[0].revision == revision_before_terminal_retry

    replacement = _request("cascade-recreated", participant=participant)
    owner.ensure_snapshot(replacement)
    if participant == "base":
        records.begin_step(replacement.operation_id, "snapshot")
        records.complete_step(replacement.operation_id, "snapshot")
    replacement_store = CascadeCredentialStore(host=HostBackend(), root=tmp_path / "new-coordinator")
    replacement_store.prepare(replacement.target_id)
    replacement_transfer = replacement_store.export_transfer(replacement.target_id)
    replacement_material = (
        _entry_material(replacement, replacement_transfer, replacement_store) if replacement.role == "entry" else None
    )
    owner.prepare(replacement, replacement_transfer, replacement_material)
    assert credentials.exists(replacement.target_id)
    assert credentials.load(replacement.target_id)._seed != old_seed


def test_prepare_is_linearized_with_concurrent_rollback(tmp_path: Path):
    owner, _records, _gate, _current, store, credentials, _context = _owner(tmp_path)
    request = _request()
    transfer = _coordinator_transfer(tmp_path)
    owner.ensure_snapshot(request)
    entered = Event()
    release = Event()
    rollback_started = Event()
    original = owner._client_material
    assert original is not None

    def blocked_client_material(state, protocol, transit):
        entered.set()
        assert release.wait(timeout=5)
        return original(state, protocol, transit)

    owner._client_material = blocked_client_material

    def prepare():
        return owner.prepare(request, transfer)

    def rollback():
        rollback_started.set()
        return owner.rollback(request)

    with ThreadPoolExecutor(max_workers=2) as pool:
        preparing = pool.submit(prepare)
        assert entered.wait(timeout=5)
        rolling_back = pool.submit(rollback)
        assert rollback_started.wait(timeout=5)
        time.sleep(0.05)
        assert not rolling_back.done()
        release.set()
        assert preparing.result(timeout=5).state == "prepared"
        assert rolling_back.result(timeout=5).state == "rolled_back"

    record = store.record(request)
    assert record is not None and record["phase"] == "rolled_back"
    assert not credentials.exists(request.target_id)
