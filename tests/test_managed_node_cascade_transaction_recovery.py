from __future__ import annotations

import copy
import hashlib
import json

import pytest

from hydra.contracts import ConfigFragment, RuntimeSubject
from hydra.contracts.managed_node_cascade import CascadeParticipantRequest
from hydra.contracts.managed_node_models import CascadeDefinition, canonical_digest
from hydra.core.host import HostBackend
from hydra.services.managed_nodes import cascade_participant_store as store_module
from hydra.services.managed_nodes.cascade_participant_store import CascadeParticipantStore
from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext
from tests.test_managed_node_cascade_participant import _PREPARED, _coordinator_transfer, _owner, _request


@pytest.mark.parametrize(
    ("participant", "terminal"), [("base", "rollback"), ("exit", "rollback"), ("exit", "finalize")]
)
def test_terminal_response_loss_retries_without_snapshot_or_runtime_reapply(tmp_path, participant, terminal):
    calls = []
    owner, records, _gate, current, store, credentials, context = _owner(
        tmp_path, participant=participant, apply=lambda *_args: calls.append(True) or True
    )
    request = _request(participant=participant)
    owner.ensure_snapshot(request)
    if participant == "base":
        records.begin_step(request.operation_id, "snapshot")
        records.complete_step(request.operation_id, "snapshot")
    owner.prepare(request, _coordinator_transfer(tmp_path))
    if terminal == "finalize":
        context[1] = _PREPARED
        owner.apply(request)
    finish = owner.rollback if terminal == "rollback" else lambda req: owner.finalize(req, "e" * 64)
    receipt = finish(request)
    assert not store._path(request, ".snapshot").exists()
    before_record = copy.deepcopy(store.record(request))
    before_revision = current[0].revision
    before_calls = len(calls)
    before_seed = credentials.exists(request.target_id)
    owner._store = CascadeParticipantStore(host=HostBackend(), root=tmp_path / "transactions")
    assert finish(request) == receipt
    assert store.record(request) == before_record
    assert current[0].revision == before_revision
    assert len(calls) == before_calls
    assert credentials.exists(request.target_id) == before_seed


def _large_restore_request(count):
    route = CascadeDefinition("route-size", "Size", "base", "exit", ["vless"])
    plan = {"cascade_id": route.id, "previous": route.to_document(), "cascade": route.to_document()}
    request = CascadeParticipantRequest(
        "large-context", "cascade_save", route.id, canonical_digest(plan), plan, "base", "entry", route, "vless"
    )
    users, outbounds, rules, ids = [], [], [], []
    for index in range(count):
        name, uuid, tag = f"cascade-size-{index}", f"{index:032x}", f"cascade-route-size-vless-{index}"
        users.append(RuntimeSubject(name, uuid, ("vless",)))
        ids.append(f"business-{index}")
        outbounds.append(
            {
                "type": "vless",
                "tag": tag,
                "server": "203.0.113.10",
                "server_port": 443,
                "uuid": uuid,
                "tls": {"enabled": True, "server_name": "exit.example.test"},
            }
        )
        rules.extend(({"auth_user": [name], "outbound": tag}, {"auth_user": [name], "action": "reject"}))
    context = CascadeRestoreContext(
        route.id,
        route.entry_id,
        route.exit_id,
        request.operation_id,
        request.plan_digest,
        "base",
        "vless",
        tuple(ids),
        tuple(users),
        ConfigFragment(outbounds=outbounds, route_rules=rules),
    )
    return request, context


def test_oversized_scoped_snapshot_rejects_before_creating_private_artifacts(tmp_path):
    request, context = _large_restore_request(4000)
    context.validate_for(request)
    # A legitimate config can fit its 8MiB read budget while its restore artifact exceeds 1MiB.
    assert len(json.dumps(context.fragment.as_dict()).encode()) < 8 * 1024 * 1024
    store = CascadeParticipantStore(host=HostBackend(), root=tmp_path / "transactions")
    with pytest.raises(ValueError, match="size limit"):
        store.snapshot(request, "a" * 64, "b" * 64, context)
    assert not store._path(request, ".snapshot").exists()
    assert store.record(request) is None


@pytest.mark.parametrize("extra_byte", [False, True])
def test_snapshot_envelope_boundary_is_checked_before_write(tmp_path, monkeypatch, extra_byte):
    request, context = _large_restore_request(1)
    payload = {
        "request_digest": hashlib.sha256(store_module._encode(request.to_document())).hexdigest(),
        "engine_identity": "a" * 64,
        "config_identity": "b" * 64,
        "restore_context": context.to_document(),
    }
    envelope = {"payload": payload, "sha256": hashlib.sha256(store_module._encode(payload)).hexdigest()}
    encoded_size = len(store_module._encode(envelope))
    monkeypatch.setattr(store_module, "_MAX_RECORD", encoded_size - int(extra_byte))
    store = CascadeParticipantStore(host=HostBackend(), root=tmp_path / "transactions")
    if extra_byte:
        with pytest.raises(ValueError, match="size limit"):
            store.snapshot(request, "a" * 64, "b" * 64, context)
        assert not store._path(request, ".snapshot").exists()
        assert store.record(request) is None
    else:
        saved = store.snapshot(request, "a" * 64, "b" * 64, context)
        assert store.snapshot_data(request) == saved
        assert store.restore_context(request) == context
