from __future__ import annotations

import copy
import time
from pathlib import Path
from dataclasses import replace
from typing import Any, cast

import pytest

from hydra.contracts.managed_node_models import (
    ApplyReceipt,
    NodeDefinition,
    NodeDesired,
    Operation,
    ProtocolAssignment,
    UserAssignment,
    canonical_digest,
)
from hydra.contracts.managed_node_observations import ConfirmedProfiles, NodeSample
from hydra.core.host import HOST
from hydra.core.state_models import AppState
from hydra.core.state_runtime import desired_payload, merge_runtime_state
from hydra.services.managed_nodes.agent import ManagedNodeAgent
from hydra.services.managed_nodes.checks import ManagedNodeCheckService
from hydra.services.managed_nodes.client import ManagedNodeError
from hydra.services.managed_nodes.observations import ManagedNodeObservationStore
from hydra.services.managed_nodes.probe_clients import ManagedNodeProbeClient
from hydra.services.managed_nodes.profile_store import ManagedNodeProfileStore
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.sync import ManagedNodeSyncService
from hydra.services.managed_nodes.sync_operations import CONFIRMATION_TIMEOUT


class Clock:
    def __init__(self):
        self.current = time.monotonic()
        self.sleeps = []

    def monotonic(self):
        return self.current

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.current += seconds


def desired(*, blocked: bool = False, disabled: list[str] | None = None, port: int = 443) -> NodeDesired:
    return NodeDesired(
        "de-1",
        1,
        [UserAssignment("user-1", "one@example.test", blocked=blocked, disabled_protocols=disabled or [])],
        [ProtocolAssignment("vless", {"port": port})],
    )


def test_pending_remote_apply_preserves_install_handoff(tmp_path: Path):
    frozen = desired()
    operation = Operation("install-1", "install", "de-1", "a" * 64, "running",
                          completed_steps=["bootstrap", "management_identity", "management_verified"],
                          error={"stage": "apply", "reason": "pending"})
    worker = service(tmp_path, operation, Client(frozen))
    worker._records.store_apply_intent(operation.id, frozen)
    result, error = worker._apply_operations.remote_apply(
        worker._client_factory(None), "de-1", operation, frozen, deadline=time.monotonic() + 10,
    )
    assert result is not None and result.state == "running" and error == CONFIRMATION_TIMEOUT
    current = worker._records.find_operation(operation.id)
    assert current is not None and current.error is not None
    assert current.error["stage"] == "apply"
    assert worker._apply_operations.operation_for("de-1", frozen).id == operation.id


def test_legacy_lost_install_handoff_recovers_only_with_frozen_intent_and_enrollment_proof(tmp_path: Path):
    frozen = desired()
    operation = Operation("install-1", "install", "de-1", "a" * 64, "running",
                          completed_steps=["bootstrap", "management_identity", "management_verified"])
    worker = service(tmp_path, operation, Client(frozen))
    with pytest.raises(RuntimeError, match="install-1.*unresolved"):
        worker._apply_operations.operation_for("de-1", frozen)
    worker._records.store_apply_intent(operation.id, frozen)
    assert worker._apply_operations.operation_for("de-1", frozen).id == operation.id


def test_install_without_verified_management_cannot_be_taken_over_by_apply(tmp_path: Path):
    frozen = desired()
    operation = Operation("install-1", "install", "de-1", "a" * 64, "running",
                          completed_steps=["bootstrap", "management_identity"])
    worker = service(tmp_path, operation, Client(frozen))
    worker._records.store_apply_intent(operation.id, frozen)
    with pytest.raises(RuntimeError, match="unresolved"):
        worker._apply_operations.operation_for("de-1", frozen)


def test_remote_apply_failure_keeps_reason_in_targeted_report(tmp_path: Path):
    frozen = desired()
    operation = Operation("apply-1", "apply", "de-1", frozen.digest, "running", plan=frozen.to_document())
    client = Client(frozen)
    client.operation = lambda op_id, deadline: Operation(
        op_id, "apply", "de-1", frozen.digest, "failed", error={"stage": "apply", "reason": "AWG profile missing"},
    )
    worker = service(tmp_path, operation, client)
    result, error = worker._apply_operations.remote_apply(client, "de-1", operation, frozen, deadline=time.monotonic() + 10)
    assert result is not None and result.state == "failed"
    assert error == "AWG profile missing"


def service(tmp_path: Path, operation: Operation, client: Client, *, clock=None):
    clock = clock or Clock()
    state = AppState()

    def update(mutate):
        result = mutate(state)
        return state, result

    records = ManagedNodeRecords(state_reader=lambda: state, state_updater=update)
    records.begin_operation(operation)
    profiles = ManagedNodeProfileStore(host=HOST, root=tmp_path / "profiles")
    observations = ManagedNodeObservationStore(host=HOST, root=tmp_path / "observations")
    checks = ManagedNodeCheckService(
        records=records,
        state_reader=lambda: state,
        client_factory=lambda _definition: client,
        profile_store=profiles,
        observations=observations,
        probe_client=ManagedNodeProbeClient(host=HOST),
    )
    return ManagedNodeSyncService(
        records=records,
        state_reader=lambda: state,
        state_updater=update,
        client_factory=lambda _definition: cast(Any, client),
        profile_store=profiles,
        observations=observations,
        checks=checks,
        local_user_sync=lambda: (state, {}, []),
        operation_id_factory=lambda: "apply-new",
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )


class Client:
    def __init__(self, old: NodeDesired):
        self.old = old
        self.submitted = []
        self.calls = []

    def operation(self, operation_id, deadline):
        self.calls.append(("operation", operation_id))
        if not self.submitted:
            raise ManagedNodeError("not_found", "http", "not found")
        return Operation(operation_id, "apply", "de-1", self.old.digest, "running", plan=self.old.to_document())

    def submit(self, operation_id, candidate, deadline):
        self.calls.append(("submit", operation_id))
        self.submitted.append((operation_id, candidate))
        return Operation(operation_id, "apply", "de-1", candidate.digest, "running", plan=candidate.to_document())

    def sync_sample(self, deadline) -> NodeSample:
        del deadline
        raise ManagedNodeError("unavailable", "http", "offline")


class UnknownSendClient(Client):
    def __init__(self, frozen: NodeDesired):
        super().__init__(frozen)
        self.operation_reads = 0

    def operation(self, operation_id, deadline):
        del deadline
        self.operation_reads += 1
        self.calls.append(("operation", operation_id))
        if not self.submitted:
            raise ManagedNodeError("not_found", "http", "not found")
        if self.operation_reads == 2:
            return Operation(operation_id, "apply", "de-1", self.old.digest, "running", plan=self.old.to_document())
        receipt = ApplyReceipt(
            operation_id,
            self.old.revision,
            self.old.digest,
            "engine-generation",
            self.old.users_digest,
            canonical_digest([]),
        )
        return Operation(
            operation_id,
            "apply",
            "de-1",
            self.old.digest,
            "succeeded",
            receipt=receipt,
            plan=self.old.to_document(),
        )

    def submit(self, operation_id, candidate, deadline):
        del deadline
        self.calls.append(("submit", operation_id))
        self.submitted.append((operation_id, candidate))
        raise ManagedNodeError("timeout", "http", "send outcome is unknown")

    def sync_sample(self, deadline) -> NodeSample:
        del deadline
        return NodeSample(
            "de-1",
            users_applied=0,
            users_digest=canonical_digest([]),
            runtime={"engine_active": True, "apply_generation": "engine-generation"},
        )


class CompletingClient(Client):
    """The agent acknowledges a POST before its asynchronous apply finishes."""
    def __init__(self, candidate, *, final_state="succeeded", lost_send_reply=False):
        super().__init__(candidate)
        self.reads = 0
        self.final_state = final_state
        self.lost_send_reply = lost_send_reply
        self.request_deadlines = []
        self.receipt = None

    def operation(self, operation_id, deadline):
        self.request_deadlines.append(deadline)
        self.calls.append(("operation", operation_id))
        self.reads += 1
        if not self.submitted:
            raise ManagedNodeError("not_found", "http", "not found")
        if self.reads < 5:
            return Operation(operation_id, "apply", "de-1", self.old.digest, "running")
        if self.final_state != "succeeded":
            return Operation(operation_id, "apply", "de-1", self.old.digest, self.final_state,
                             error={"stage": "apply", "reason": "cannot confirm runtime"})
        self.receipt = ApplyReceipt(operation_id, self.old.revision, self.old.digest,
                                    "engine-generation", self.old.users_digest, canonical_digest([]))
        return Operation(operation_id, "apply", "de-1", self.old.digest, "succeeded", receipt=self.receipt)

    def submit(self, operation_id, candidate, deadline):
        self.request_deadlines.append(deadline)
        result = super().submit(operation_id, candidate, deadline)
        if self.lost_send_reply:
            raise ManagedNodeError("http_failed", "http", "connection closed after sending")
        return result

    def sync_sample(self, deadline):
        return NodeSample("de-1", users_applied=0, users_digest=canonical_digest([]),
                          runtime={"engine_active": True, "apply_generation": "engine-generation"})

    def state(self, deadline):
        self.calls.append(("state", "de-1"))
        return replace(self.sync_sample(deadline), receipt=self.receipt)

    def profiles(self, deadline):
        self.calls.append(("profiles", "de-1"))
        return ConfirmedProfiles("de-1", self.receipt, [], canonical_digest([]))


def completing_service(tmp_path, *, final_state="succeeded", lost_send_reply=False):
    frozen = NodeDesired("de-1", 1, [], [])
    operation = Operation("apply-1", "apply", "de-1", frozen.digest, "pending", plan=frozen.to_document())
    clock = Clock()
    client = CompletingClient(frozen, final_state=final_state, lost_send_reply=lost_send_reply)
    worker = service(tmp_path, operation, client, clock=clock)
    worker._records.put_definition(NodeDefinition("de-1", "Germany", "203.0.113.4", "root", "dev", "a" * 40,
                                                  25555, [], "managed-node/de-1"))
    return worker, client, clock


@pytest.mark.parametrize("lost_send_reply", [False, True])
def test_one_sync_waits_for_async_apply_and_commits_profiles_before_return(tmp_path, lost_send_reply):
    worker, client, clock = completing_service(tmp_path, lost_send_reply=lost_send_reply)
    started = clock.monotonic()
    events = []
    report = worker.sync("de-1", progress=events.append)

    assert report.nodes["de-1"]["status"] == "ok"
    assert not report.pending_operations
    assert client.reads == 5
    assert len(client.submitted) == 1
    assert 0 < clock.monotonic() - started < 60
    assert all(started < deadline <= clock.monotonic() + 10 for deadline in client.request_deadlines)
    committed = worker._records.find_operation("apply-1")
    assert committed.state == "succeeded" and committed.receipt == client.receipt
    bundle = worker._profile_store.read("de-1", receipt_is_committed=lambda item: item.receipt == committed.receipt)
    assert bundle is not None and bundle.receipt == client.receipt
    assert client.calls[-2:] == [("state", "de-1"), ("profiles", "de-1")]
    assert [event["state"] for event in events] == ["pending", "succeeded"]


@pytest.mark.parametrize("final_state", ["failed", "recovery_required"])
def test_wait_returns_immediately_on_terminal_node_failure(tmp_path, final_state):
    worker, client, clock = completing_service(tmp_path, final_state=final_state)
    started = clock.monotonic()
    report = worker.sync("de-1")
    assert report.nodes["de-1"]["status"] == ("failed" if final_state == "failed" else "pending")
    assert worker._records.find_operation("apply-1").state == final_state
    assert client.reads == 5 and clock.monotonic() - started < 60
    assert not any(method in {"state", "profiles"} for method, _target in client.calls)


@pytest.mark.parametrize("field,value", [("id", "other-operation"), ("target_id", "other-node"),
                                        ("desired_digest", "b" * 64), ("kind", "install")])
def test_each_polled_response_must_match_the_frozen_operation(tmp_path, field, value):
    worker, client, _clock = completing_service(tmp_path)
    original = client.operation
    def changed(operation_id, deadline):
        result = original(operation_id, deadline)
        return replace(result, **{field: value}) if client.reads == 3 else result
    client.operation = changed
    report = worker.sync("de-1")
    assert report.nodes["de-1"]["status"] == "pending"
    assert "identity does not match" in report.nodes["de-1"]["error"]
    assert client.reads == 3 and len(client.submitted) == 1
    assert worker._records.find_operation("apply-1").state != "succeeded"


def test_wait_timeout_keeps_same_operation_for_automatic_cycle(tmp_path):
    worker, client, clock = completing_service(tmp_path)
    original = client.operation
    def still_running(operation_id, deadline):
        client.calls.append(("operation", operation_id))
        if not client.submitted:
            raise ManagedNodeError("not_found", "http", "not found")
        return Operation(operation_id, "apply", "de-1", client.old.digest, "running")
    client.operation = still_running
    started = clock.monotonic()
    report = worker.sync("de-1")
    assert clock.monotonic() - started == pytest.approx(60)
    assert report.nodes["de-1"]["error"] == CONFIRMATION_TIMEOUT
    assert report.pending_operations == ["apply-1"]
    assert worker._records.find_operation("apply-1").state == "running"
    frozen = worker._records.find_apply_intent("apply-1")

    client.operation = original
    _state, _blocked, errors = worker.run_cycle(lambda: (worker._state_reader(), {}, []))
    assert errors == []
    assert len(client.submitted) == 1
    assert worker._records.find_operation("apply-1").state == "succeeded"
    assert worker._records.find_apply_intent("apply-1") == frozen


@pytest.mark.parametrize("mismatch", ["runtime", "profiles"])
def test_remote_success_is_not_local_success_without_runtime_and_profiles(tmp_path, mismatch):
    worker, client, _clock = completing_service(tmp_path)
    if mismatch == "runtime":
        state = client.state
        client.state = lambda deadline: replace(state(deadline), runtime={"engine_active": False})
    else:
        profiles = client.profiles
        client.profiles = lambda deadline: replace(profiles(deadline), node_id="another-node")
    report = worker.sync("de-1")
    assert report.nodes["de-1"]["status"] == "pending"
    assert worker._records.find_operation("apply-1").state != "succeeded"
    assert worker._profile_store.read("de-1", receipt_is_committed=lambda _bundle: True) is None


@pytest.mark.parametrize("error_kind", ["http_failed", "not_found", "identity_mismatch"])
def test_poll_read_errors_never_resubmit_and_identity_errors_stop_waiting(tmp_path, error_kind):
    worker, client, _clock = completing_service(tmp_path)
    original = client.operation
    def interrupted(operation_id, deadline):
        result = original(operation_id, deadline)
        if client.reads == 3:
            raise ManagedNodeError(error_kind, "http" if error_kind != "identity_mismatch" else "tls", "read failed")
        return result
    client.operation = interrupted
    report = worker.sync("de-1")
    assert len(client.submitted) == 1
    assert report.nodes["de-1"]["status"] == ("pending" if error_kind == "identity_mismatch" else "ok")
    assert client.reads == (3 if error_kind == "identity_mismatch" else 5)


def test_expired_wait_does_not_send_another_request(tmp_path):
    worker, client, _clock = completing_service(tmp_path)
    operation = worker._records.find_operation("apply-1")
    result, error = worker._apply_operations.remote_apply(client, "de-1", operation, client.old,
                                                          deadline=worker._clock())
    assert result is None and error == CONFIRMATION_TIMEOUT
    assert client.calls == []


def test_counter_sample_endpoint_is_explicit_and_state_get_remains_read_only():
    calls = []
    sample = NodeSample("de-1", users_applied=0, users_digest="a" * 64)
    agent = ManagedNodeAgent(
        node_id="de-1",
        state_provider=lambda: sample,
        submit_provider=None,
        operation_provider=lambda _operation_id: None,
        profiles_provider=None,
        sync_sample_provider=lambda: calls.append("sync") or sample,
    )

    assert agent.dispatch("GET", "/v1/state").status == 200
    assert calls == []
    assert agent.dispatch("POST", "/v1/sync/sample", {"unexpected": True}).status == 400
    assert calls == []
    assert agent.dispatch("POST", "/v1/sync/sample", {}).status == 200
    assert calls == ["sync"]


def test_status_rejects_secret_shaped_fields_without_running_sync():
    calls = []

    class LeakySample(NodeSample):
        def to_document(self):
            return {**super().to_document(), "private_key": "node-private-secret"}

    agent = ManagedNodeAgent(
        node_id="de-1",
        state_provider=lambda: (
            calls.append("state") or LeakySample("de-1", users_applied=0, users_digest=canonical_digest([]))
        ),
        submit_provider=None,
        sync_sample_provider=lambda: calls.append("sync") or NodeSample("de-1"),
        operation_provider=lambda _operation_id: None,
        profiles_provider=None,
    )

    result = agent.dispatch("GET", "/v1/state")

    assert result.status == 400
    assert "node-private-secret" not in str(result.document)
    assert calls == ["state"]


def test_agent_rejects_malformed_and_cross_node_apply_before_submit():
    submitted = []

    def record_submit(operation_id, node_desired):
        submitted.append((operation_id, node_desired))
        return Operation(
            operation_id,
            "apply",
            node_desired.node_id,
            node_desired.digest,
            "pending",
            plan=node_desired.to_document(),
        )

    agent = ManagedNodeAgent(
        node_id="de-1",
        state_provider=lambda: NodeSample("de-1", users_applied=0, users_digest=canonical_digest([])),
        submit_provider=record_submit,
        operation_provider=lambda _operation_id: None,
        profiles_provider=None,
    )
    valid = NodeDesired("de-1", 1, [], []).to_document()

    malformed = agent.dispatch("POST", "/v1/apply", {"operation_id": "apply-1", "desired": {**valid, "extra": True}})
    foreign = NodeDesired("uk-1", 1, [], []).to_document()
    cross_node = agent.dispatch("POST", "/v1/apply", {"operation_id": "apply-2", "desired": foreign})

    assert malformed.status == 400
    assert cross_node.status == 400
    assert submitted == []


def test_agent_rejects_cross_node_profiles_before_response():
    digest = canonical_digest([])
    receipt = ApplyReceipt("apply-1", 1, "a" * 64, "runtime-1", "b" * 64, digest)
    foreign = ConfirmedProfiles("uk-1", receipt, [], digest)
    agent = ManagedNodeAgent(
        node_id="de-1",
        state_provider=lambda: NodeSample("de-1"),
        submit_provider=None,
        operation_provider=lambda _operation_id: None,
        profiles_provider=lambda: foreign,
    )

    result = agent.dispatch("GET", "/v1/profiles")

    assert result.status == 400
    assert result.document == {
        "error": {
            "kind": "invalid_request",
            "stage": "http",
            "reason": "profiles provider returned a different node identity",
        }
    }


def test_user_disabled_for_every_selected_protocol_needs_no_profile_entry():
    from hydra.services.managed_nodes.sync import (
        expected_profile_pairs,
        expected_profile_users,
        _validate_profile_coverage,
    )
    from hydra.contracts.managed_node_observations import ConfirmedProfiles
    from hydra.contracts.managed_node_models import ApplyReceipt
    from hydra.contracts.managed_node_models import canonical_digest

    candidate = desired(disabled=["vless"])
    pairs = expected_profile_pairs(candidate.users, candidate.protocols)
    assert pairs == set()
    assert expected_profile_users(pairs) == set()
    empty = ConfirmedProfiles(
        "de-1",
        ApplyReceipt("apply-1", 1, candidate.digest, "runtime-1", candidate.users_digest, canonical_digest([])),
        [],
        canonical_digest([]),
    )
    _validate_profile_coverage(empty, candidate)


def test_active_operation_is_polled_with_its_frozen_desired_even_when_current_state_changes(tmp_path: Path):
    frozen = desired(port=443)
    latest = desired(blocked=True, port=8443)
    operation = Operation(
        "apply-old", "apply", "de-1", frozen.digest, "running", plan=frozen.to_document(), active_step="remote_apply"
    )
    worker = service(tmp_path, operation, Client(frozen))

    assert worker._apply_operations.operation_for("de-1", latest) == operation
    assert worker._apply_operations.operation_desired(operation, latest) == frozen
    client = Client(frozen)
    remote, error = worker._apply_operations.remote_apply(
        client,
        "de-1",
        operation,
        frozen,
        deadline=time.monotonic() + 10.0,
    )

    assert error == CONFIRMATION_TIMEOUT
    assert remote is not None and remote.desired_digest == frozen.digest
    assert client.submitted == [("apply-old", frozen)]
    assert client.calls[:2] == [("operation", "apply-old"), ("submit", "apply-old")]
    assert all(call == ("operation", "apply-old") for call in client.calls[2:])


def test_install_apply_intent_is_frozen_durably_across_retry(tmp_path: Path):
    latest = desired(port=8443)
    operation = Operation(
        "install-1",
        "install",
        "de-1",
        "a" * 64,
        "running",
        error={"stage": "apply", "reason": "retry"},
        plan={"branch": "dev"},
    )
    worker = service(tmp_path, operation, Client(latest))

    assert worker._apply_operations.operation_for("de-1", latest) == operation
    frozen = worker._apply_operations.operation_desired(operation, latest)
    assert worker._records.find_apply_intent("install-1") == frozen
    with pytest.raises(ValueError, match="immutable"):
        worker._records.store_apply_intent("install-1", desired(port=443))


def test_apply_intent_survives_runtime_merge_but_is_not_persisted_config():
    state = AppState()

    def update(mutate):
        result = mutate(state)
        return state, result

    records = ManagedNodeRecords(state_reader=lambda: state, state_updater=update)
    operation = Operation(
        "install-1",
        "install",
        "de-1",
        "a" * 64,
        "running",
        error={"stage": "apply", "reason": "retry"},
        plan={"branch": "dev"},
    )
    records.begin_operation(operation)
    stale = copy.deepcopy(state)
    records.store_apply_intent("install-1", desired())

    persisted = desired_payload(state)
    merge_runtime_state(stale, state, set())

    persisted_nodes = persisted["feature_extensions"]["managed_nodes"]
    assert "operations" not in persisted_nodes
    assert "apply_intents" not in persisted_nodes
    managed = stale.feature_extensions.get("managed_nodes")
    assert isinstance(managed, dict)
    intents = managed.get("apply_intents")
    assert isinstance(intents, dict)
    assert intents["install-1"] == desired().to_document()


def test_unknown_submit_outcome_retries_by_frozen_id_without_blind_resubmit(tmp_path: Path):
    frozen = desired()
    operation = Operation("apply-unknown", "apply", "de-1", frozen.digest, "pending", plan=frozen.to_document())
    remote = UnknownSendClient(frozen)
    worker = service(tmp_path, operation, remote)
    worker._records.store_apply_intent(operation.id, frozen)

    first, first_error = worker._apply_operations.remote_apply(
        remote,
        "de-1",
        operation,
        frozen,
        deadline=worker._clock() + 0.5,
    )
    assert first is None and first_error == CONFIRMATION_TIMEOUT
    pending = worker._records.find_operation(operation.id)
    assert pending is not None and pending.state == "running"

    resumed, error = worker._apply_operations.remote_apply(
        remote,
        "de-1",
        pending,
        frozen,
        deadline=worker._clock() + 10.0,
    )

    assert error == ""
    assert resumed is not None and resumed.state == "succeeded"
    assert remote.submitted == [(operation.id, frozen)]
    assert remote.calls == [
        ("operation", operation.id),
        ("submit", operation.id),
        ("operation", operation.id),
        ("operation", operation.id),
    ]
    assert worker._records.find_apply_intent(operation.id) == frozen


def test_sync_after_crash_before_send_uses_atomic_protocol_payload_and_id(tmp_path: Path):
    frozen = NodeDesired(
        "de-1",
        1,
        [],
        [ProtocolAssignment("vless", {"port": 8443})],
    )
    operation = Operation(
        "protocol-apply-1",
        "apply",
        "de-1",
        frozen.digest,
        "pending",
        plan=frozen.to_document(),
    )
    remote = UnknownSendClient(frozen)
    worker = service(tmp_path, operation, remote)
    worker._records.put_definition(
        NodeDefinition(
            "de-1",
            "Germany",
            "203.0.113.4",
            "root",
            "dev",
            "a" * 40,
            25555,
            [ProtocolAssignment("vless", {"port": 8443})],
            "managed-node/de-1",
        )
    )
    worker._records.store_apply_intent(operation.id, frozen)

    report = worker.sync("de-1")

    assert report.nodes["de-1"]["status"] == "pending"
    assert report.nodes["de-1"]["operation_id"] == operation.id
    assert remote.submitted == [(operation.id, frozen)]
    persisted = worker._records.find_operation(operation.id)
    assert persisted is not None and persisted.plan == frozen.to_document()
    assert worker._records.find_apply_intent(operation.id) == frozen


def test_targeted_manual_sync_does_not_run_base_user_maintenance(tmp_path: Path):
    frozen = desired()
    operation = Operation(
        "apply-1", "apply", "de-1", frozen.digest, "running", plan=frozen.to_document(), active_step="remote_apply"
    )
    client = Client(frozen)
    worker = service(tmp_path, operation, client)
    worker._records.put_definition(
        NodeDefinition(
            "de-1",
            "Germany",
            "203.0.113.4",
            "root",
            "dev",
            "a" * 40,
            25555,
            [ProtocolAssignment("vless", {"port": 443})],
            "managed-node/de-1",
        )
    )
    local_sync_calls = []
    worker._local_user_sync = lambda: local_sync_calls.append(True) or (AppState(), {}, [])

    report = worker.sync("de-1")

    assert report.local == "ok"
    assert local_sync_calls == []


def test_offline_collection_does_not_skip_local_limits_or_final_reconciliation(tmp_path: Path):
    frozen = desired()
    operation = Operation("apply-1", "apply", "de-1", frozen.digest, "pending", plan=frozen.to_document())
    worker = service(tmp_path, operation, Client(frozen))
    worker._records.put_definition(
        NodeDefinition(
            "de-1",
            "Germany",
            "203.0.113.4",
            "root",
            "dev",
            "a" * 40,
            25555,
            [ProtocolAssignment("vless", {"port": 443})],
            "managed-node/de-1",
        )
    )
    events = []
    reconcile = worker._reconcile

    def tracked_reconcile(*args, **kwargs):
        events.append("reconcile")
        return reconcile(*args, **kwargs)

    worker._reconcile = tracked_reconcile

    _state, blocked, errors = worker.run_cycle(lambda: (events.append("limits") or AppState(), {}, []))

    assert events == ["limits", "reconcile"]
    assert blocked == {}
    assert any("offline" in error for error in errors)
    assert any("management response is unavailable" in error for error in errors)


def test_replayed_absolute_samples_do_not_create_a_second_apply_intent(tmp_path: Path):
    frozen = desired()
    operation = Operation(
        "apply-1", "apply", "de-1", frozen.digest, "running", plan=frozen.to_document(), active_step="remote_apply"
    )
    worker = service(tmp_path, operation, Client(frozen))
    operation = worker._apply_operations.operation_for("de-1", frozen)
    assert operation is not None and operation.id == "apply-1"
