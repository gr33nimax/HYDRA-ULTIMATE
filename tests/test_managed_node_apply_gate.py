from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from hydra.contracts.managed_node_models import CascadeDefinition, Operation, canonical_digest
from hydra.core.state_models import AppState
from hydra.core.state_managed_nodes import ManagedNodesState, store_managed_nodes
from hydra.services.managed_nodes.apply_gate import ManagedNodeApplyGate
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.orchestration_service import OrchestrationService


def _route(entry: str = "base", exit: str = "exit-node") -> CascadeDefinition:
    return CascadeDefinition("lease-route", "Leased", entry, exit, ["vless"])


def _state(route: CascadeDefinition, *, kind: str = "cascade_save") -> AppState:
    plan = {
        "cascade_id": route.id,
        "previous": route.to_document() if kind == "cascade_remove" else None,
        "cascade": route.to_document() if kind == "cascade_save" else None,
    }
    operation = Operation("stage-1", kind, route.id, canonical_digest(plan), "pending", plan=plan)
    state = AppState()
    store_managed_nodes(state.feature_extensions, ManagedNodesState(operations=[operation]))
    return state


def _service(tmp_path: Path, persisted: AppState, *, participant_id: str = "base", owner=None):
    current = [copy.deepcopy(persisted)]
    gate = ManagedNodeApplyGate(
        state_reader=lambda: copy.deepcopy(current[0]),
        participant_id=participant_id,
        lock_path=tmp_path / "apply-gate.lock",
        authenticated_participant=owner,
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
    saved = []
    applied = []
    service = OrchestrationService(
        plugins=SimpleNamespace(),
        singbox=SimpleNamespace(log=lambda *_args: None),
        nft=SimpleNamespace(),
        host=SimpleNamespace(),
        save_state=lambda state: saved.append(copy.deepcopy(state)),
        get_protocol=lambda *_args: None,
        certificates=cast(Any, SimpleNamespace()),
        traffic_daemon_service=tmp_path / "traffic.service",
        apply_journal=tmp_path / "apply.jsonl",
        apply_lock_file=tmp_path / "apply.lock",
        managed_node_apply_gate=gate,
    )
    cast(Any, service)._configuration_applier = lambda: SimpleNamespace(
        apply=lambda state: applied.append(state) or True
    )
    return service, gate, records, current, saved, applied


@pytest.mark.parametrize(
    ("route", "participant_id"),
    [(_route(), "base"), (_route("entry-node"), "entry-node")],
)
def test_ordinary_apply_rejects_current_persisted_participant_lease_before_any_restore_or_apply(
    tmp_path: Path,
    route: CascadeDefinition,
    participant_id: str,
):
    service, _gate, _records, current, saved, applied = _service(tmp_path, _state(route), participant_id=participant_id)
    stale_caller_state = AppState()
    stale_caller_state.install["keep"] = "caller desired value"
    before = copy.deepcopy(stale_caller_state)

    assert service.apply_config(stale_caller_state) is False

    assert current[0].feature_extensions["managed_nodes"]
    assert stale_caller_state == before
    assert saved == []
    assert applied == []
    assert "cascade participant" in service.last_apply_error()


def test_ordinary_apply_is_allowed_after_atomic_cascade_commit_releases_both_participants(tmp_path: Path):
    route = _route("entry-node")
    service, _gate, records, _current, _saved, applied = _service(tmp_path, _state(route), participant_id="entry-node")
    operation_id = "stage-1"
    records.begin_step(operation_id, "snapshot")
    records.complete_step(operation_id, "snapshot")
    records.begin_step(operation_id, "profiles")
    records.complete_step(operation_id, "profiles")
    records.commit_cascade_operation(operation_id, route)

    assert service.apply_config(records._state_reader()) is True
    assert len(applied) == 1


def test_only_an_authenticated_operation_bound_owner_can_apply_under_its_matching_lease(tmp_path: Path):
    route = _route()
    service, gate, records, _current, _saved, applied = _service(
        tmp_path,
        _state(route),
        owner=lambda operation: "base" if operation.id == "stage-1" else None,
    )
    records.begin_step("stage-1", "snapshot")
    records.complete_step("stage-1", "snapshot")
    authorization = gate.authorize_participant("stage-1")

    assert service.apply_config(AppState()) is False
    assert service.apply_cascade_participant_config(AppState(), authorization) is True
    assert len(applied) == 1
    assert repr(authorization) == "ManagedNodeApplyAuthorization(<protected>)"

    assert service.apply_cascade_participant_config(AppState(), object()) is False
    assert len(applied) == 1


def test_operation_bound_owner_path_also_allows_scoped_cascade_removal(tmp_path: Path):
    route = _route()
    service, gate, records, _current, _saved, applied = _service(
        tmp_path,
        _state(route, kind="cascade_remove"),
        owner=lambda operation: "base" if operation.id == "stage-1" else None,
    )
    records.begin_step("stage-1", "snapshot")
    records.complete_step("stage-1", "snapshot")
    authorization = gate.authorize_participant("stage-1")

    assert service.apply_cascade_participant_config(AppState(), authorization) is True
    assert len(applied) == 1


def test_unauthenticated_or_conflicting_operation_cannot_claim_a_participant_lease(tmp_path: Path):
    route = _route()
    service, gate, records, _current, _saved, applied = _service(
        tmp_path, _state(route), owner=lambda _operation: "another-participant"
    )
    records.begin_step("stage-1", "snapshot")
    records.complete_step("stage-1", "snapshot")
    with pytest.raises(ValueError, match="authenticated participant"):
        gate.authorize_participant("stage-1")
    with pytest.raises(ValueError, match="unknown"):
        gate.authorize_participant("guessed-operation")
    with pytest.raises(ValueError, match="already leased"):
        records.begin_operation(
            Operation(
                "stage-2",
                "cascade_save",
                "lease-route",
                canonical_digest(
                    {
                        "cascade_id": "lease-route",
                        "previous": None,
                        "cascade": _route(exit="different-exit").to_document(),
                    }
                ),
                "pending",
                plan={
                    "cascade_id": "lease-route",
                    "previous": None,
                    "cascade": _route(exit="different-exit").to_document(),
                },
            )
        )
    assert service.apply_cascade_participant_config(AppState(), object()) is False
    assert applied == []
