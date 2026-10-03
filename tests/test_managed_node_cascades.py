from __future__ import annotations

import copy

import pytest

from hydra.contracts.managed_node_models import CascadeDefinition, NodeDefinition, ProtocolAssignment
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.cascades import ManagedNodeCascadeService
from hydra.services.managed_nodes.records import ManagedNodeRecords

_SHA = "a" * 40
_CAPS = {name: {"client": True, "server": True, "probe": True} for name in ("vless", "anytls")}


def _records():
    state = AppState()

    def update(mutator):
        result = mutator(state)
        state.revision += 1
        return copy.deepcopy(state), result

    records = ManagedNodeRecords(state_reader=lambda: copy.deepcopy(state), state_updater=update)
    for node_id in ("entry", "exit"):
        records.put_definition(NodeDefinition(
            node_id, node_id.upper(), "203.0.113.4", "root", "dev", _SHA,
            25555, [ProtocolAssignment("vless", {"port": 443})], f"managed-node/{node_id}",
        ))
    return records


class _Runtime:
    def __init__(self, *, path_ok=True, initial="not_applied", rollback_ok=True):
        self.path_ok = path_ok
        self.initial = initial
        self.rollback_ok = rollback_ok
        self.applied = set()
        self.snapshots = []
        self.calls = []
        self.path_verified = False
        self.committed = False
        self.restored = []

    def capabilities(self, participant_id: str) -> dict[str, dict[str, bool]]:
        del participant_id
        return _CAPS

    def ensure_snapshot(self, operation_id: str, participant_id: str, previous: CascadeDefinition | None) -> None:
        self.snapshots.append((operation_id, participant_id, previous))

    def participant_status(self, operation_id: str, participant_id: str) -> str:
        del operation_id
        self.calls.append(("status", participant_id))
        if self.initial == "unknown":
            return "unknown"
        return "applied" if participant_id in self.applied else "not_applied"

    def apply_participant(self, operation_id: str, participant_id: str, definition: CascadeDefinition | None) -> None:
        self.calls.append(("apply", participant_id, definition))
        self.applied.add(participant_id)

    def verify_path(self, operation_id: str, definition: CascadeDefinition) -> bool:
        del operation_id, definition
        self.calls.append(("verify",))
        self.path_verified = self.path_ok
        return self.path_ok

    def commit_profiles(self, operation_id: str, definition: CascadeDefinition | None) -> None:
        del operation_id, definition
        assert self.path_verified
        self.calls.append(("profiles",))
        self.committed = True

    def rollback_participant(self, operation_id: str, participant_id: str) -> bool:
        del operation_id
        self.restored.append(participant_id)
        self.applied.discard(participant_id)
        return self.rollback_ok


def test_cascade_rejects_same_participant_and_reserved_node_id():
    with pytest.raises(ValueError, match="different"):
        CascadeDefinition("route", "route", "edge", "edge", ["vless"]).validate()

    with pytest.raises(ValueError, match="reserved|base"):
        ManagedNodeCascadeService.validate_node_id("base")

    with pytest.raises(ValueError, match="reserved"):
        NodeDefinition("base", "friendly base", "203.0.113.4", "root", "dev", _SHA, 25555, [], "ref").validate()


def test_options_require_real_client_server_and_probe_evidence_on_both_hops():
    options = ManagedNodeCascadeService.options_for_capabilities(
        {"vless": {"client": True, "server": True, "probe": True}},
        {"vless": {"client": True, "server": True, "probe": True}},
    )
    assert [item.name for item in options if item.supported] == ["vless"]
    assert not any(item.name == "anytls" and item.supported for item in options)
    assert "not proven" in next(item.reason for item in options if item.name == "anytls")


def test_cascade_protocol_selection_requires_same_protocol():
    with pytest.raises(ValueError, match="same protocol|same-protocol"):
        ManagedNodeCascadeService.validate_protocol_pair("vless", "anytls")


def test_three_supported_topologies_accept_only_two_distinct_participants():
    for route in (
        CascadeDefinition("one", "One", "base", "entry", ["vless"]),
        CascadeDefinition("two", "Two", "entry", "exit", ["vless"]),
        CascadeDefinition("three", "Three", "entry", "base", ["vless"]),
    ):
        ManagedNodeCascadeService.validate_definition(route)
    with pytest.raises(ValueError, match="different"):
        ManagedNodeCascadeService.validate_definition(CascadeDefinition("loop", "Loop", "entry", "entry", ["vless"]))


def test_save_cascade_persists_intent_then_apply_probe_and_profile_commit():
    records = _records()
    runtime = _Runtime()
    service = ManagedNodeCascadeService(records=records, runtime=runtime, operation_id_factory=lambda: "cascade-1")
    route = CascadeDefinition("route-1", "Germany via UK", "entry", "exit", ["vless"])

    result = service.save_cascade(route, confirmed=True)

    assert result.state == "succeeded"
    assert records.find_cascade(route.id) == route
    assert {participant for _, participant, _ in runtime.snapshots} == {"entry", "exit"}
    assert [call[0] for call in runtime.calls if call[0] in {"apply", "verify", "profiles"}] == [
        "apply", "apply", "verify", "profiles",
    ]
    assert runtime.committed and runtime.path_verified


def test_failed_whole_path_verification_rolls_back_both_contexts_and_keeps_desired_old():
    records = _records()
    runtime = _Runtime(path_ok=False)
    service = ManagedNodeCascadeService(records=records, runtime=runtime, operation_id_factory=lambda: "cascade-fail")

    result = service.save_cascade(CascadeDefinition("route-1", "Route", "entry", "exit", ["vless"]), confirmed=True)

    assert result.state == "failed"
    assert records.find_cascade("route-1") is None
    assert runtime.restored == ["exit", "entry"]
    assert not runtime.committed


def test_unknown_remote_apply_is_not_replayed_and_remains_recovery_required():
    records = _records()
    runtime = _Runtime(initial="unknown")
    service = ManagedNodeCascadeService(records=records, runtime=runtime, operation_id_factory=lambda: "cascade-unknown")

    result = service.save_cascade(CascadeDefinition("route-1", "Route", "entry", "exit", ["vless"]), confirmed=True)

    assert result.state == "recovery_required"
    assert not any(call[0] == "apply" for call in runtime.calls)
    assert records.find_cascade("route-1") is None
