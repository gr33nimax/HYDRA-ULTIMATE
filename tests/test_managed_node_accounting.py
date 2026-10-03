from __future__ import annotations

from subprocess import CompletedProcess
from pathlib import Path

from hydra.contracts.managed_node_models import ApplyReceipt, NodeDesired, Operation, ProtocolAssignment
from hydra.contracts.managed_node_observations import TrafficSample
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState, PluginState, User
from hydra.services.managed_nodes.access import assignment_from_user
from hydra.services.managed_nodes.accounting import (
    apply_traffic_samples,
    record_node_counters,
    reset_managed_node_traffic,
    retire_node_traffic,
)
from hydra.services.managed_nodes.observations import ManagedNodeObservationProvider
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.runtime import ManagedNodeRuntime


def sample(user_id: str, epoch: int, counter_epoch: str, used: int) -> TrafficSample:
    return TrafficSample(user_id, "vless", "direct", epoch, counter_epoch, used)


def _produce_wire_sample(state: AppState, protocol: str, raw: int, runtime_id: str) -> list[TrafficSample]:
    produced = record_node_counters(state, [("user-1", protocol, raw)], runtime_id=runtime_id)
    return [TrafficSample.from_document(item.to_document()) for item in produced]


def test_wire_consumer_uses_cumulative_context_total_across_processes():
    node_user = User("one@example.test", "user-1")
    node_state = AppState(users=[node_user])
    base_user = User("one@example.test", "user-1")
    base_state = AppState(users=[base_user])

    first = _produce_wire_sample(node_state, "vless", 100, "process-one")
    assert first[0].used_bytes == 100
    apply_traffic_samples(base_state, "de-1", first)
    assert base_user.traffic_used_bytes == 100

    restarted = _produce_wire_sample(node_state, "vless", 30, "process-two")
    assert restarted[0].used_bytes == 130
    assert restarted[0].counter_epoch != first[0].counter_epoch
    apply_traffic_samples(base_state, "de-1", restarted)
    assert base_user.traffic_used_bytes == 130

    apply_traffic_samples(base_state, "de-1", first)
    apply_traffic_samples(base_state, "de-1", restarted)
    assert base_user.traffic_used_bytes == 130


def test_wire_consumer_handles_increments_duplicates_stale_and_raw_reset():
    node_state = AppState(users=[User("one@example.test", "user-1")])
    base_user = User("one@example.test", "user-1")
    base_state = AppState(users=[base_user])

    first = _produce_wire_sample(node_state, "vless", 100, "process-one")
    increment = _produce_wire_sample(node_state, "vless", 160, "process-one")
    apply_traffic_samples(base_state, "de-1", first)
    apply_traffic_samples(base_state, "de-1", increment)
    apply_traffic_samples(base_state, "de-1", increment)
    apply_traffic_samples(base_state, "de-1", first)
    assert base_user.traffic_used_bytes == 160

    restarted = _produce_wire_sample(node_state, "vless", 30, "process-two")
    apply_traffic_samples(base_state, "de-1", restarted)
    assert restarted[0].used_bytes == 190
    assert base_user.traffic_used_bytes == 190

    raw_reset = _produce_wire_sample(node_state, "vless", 5, "process-two")
    assert raw_reset[0].used_bytes == 195
    assert raw_reset[0].counter_epoch != restarted[0].counter_epoch
    apply_traffic_samples(base_state, "de-1", raw_reset)
    apply_traffic_samples(base_state, "de-1", restarted)
    assert base_user.traffic_used_bytes == 195


def test_wire_consumer_sums_distinct_nodes_and_protocol_contexts():
    base_user = User("one@example.test", "user-1")
    base_state = AppState(users=[base_user])
    entry_state = AppState(users=[User("one@example.test", "user-1")])
    other_state = AppState(users=[User("one@example.test", "user-1")])

    for protocol, raw in (("vless", 40), ("anytls", 25)):
        apply_traffic_samples(
            base_state,
            "de-1",
            _produce_wire_sample(entry_state, protocol, raw, "entry-process"),
        )
    apply_traffic_samples(
        base_state,
        "fi-2",
        _produce_wire_sample(other_state, "vless", 30, "other-process"),
    )

    assert base_user.traffic_used_bytes == 95


def test_wire_reset_ignores_late_epoch_and_retire_uses_context_high_water():
    node_user = User("one@example.test", "user-1")
    node_state = AppState(users=[node_user])
    base_user = User("one@example.test", "user-1")
    base_state = AppState(users=[base_user])

    old_first = _produce_wire_sample(node_state, "vless", 100, "process-one")
    old_restart = _produce_wire_sample(node_state, "vless", 30, "process-two")
    apply_traffic_samples(base_state, "de-1", old_first)
    apply_traffic_samples(base_state, "de-1", old_restart)
    assert base_user.traffic_used_bytes == 130

    reset_managed_node_traffic(base_state, base_user)
    reset_managed_node_traffic(node_state, node_user)
    apply_traffic_samples(base_state, "de-1", old_restart)
    assert base_user.traffic_used_bytes == 0

    after_reset = _produce_wire_sample(node_state, "vless", 200, "process-two")
    after_increment = _produce_wire_sample(node_state, "vless", 215, "process-two")
    after_restart = _produce_wire_sample(node_state, "vless", 7, "process-three")
    assert [item[0].used_bytes for item in (after_reset, after_increment, after_restart)] == [0, 15, 22]
    for produced in (after_reset, after_increment, after_restart):
        apply_traffic_samples(base_state, "de-1", produced)
    assert base_user.traffic_used_bytes == 22

    retire_node_traffic(base_state, "de-1")
    assert base_user.traffic_used_bytes == 22
    assert base_state.install["managed_node_retired_usage"]["user-1"] == {
        "reset_epoch": 1,
        "used_bytes": 22,
    }


def test_base_traffic_is_absolute_idempotent_and_not_double_counted():
    user = User("one@example.test", "user-1", traffic_used_bytes=400)
    state = AppState(users=[user])
    report = [sample("user-1", 0, "counter-1", 120)]

    apply_traffic_samples(state, "de-1", report)
    apply_traffic_samples(state, "de-1", report)
    assert user.traffic_used_bytes == 520

    apply_traffic_samples(state, "fi-2", [sample("user-1", 0, "counter-2", 60)])
    assert user.traffic_used_bytes == 580
    apply_traffic_samples(state, "de-1", [sample("user-1", 0, "counter-1", 80)])
    assert user.traffic_used_bytes == 580


def test_node_counter_first_sample_and_new_runtime_epoch_preserve_all_bytes():
    user = User("one@example.test", "user-1")
    state = AppState(users=[user])
    first = record_node_counters(state, [("user-1", "vless", 100)], runtime_id="engine-1")
    same_runtime = record_node_counters(state, [("user-1", "vless", 150)], runtime_id="engine-1")
    restarted = record_node_counters(state, [("user-1", "vless", 200)], runtime_id="engine-2")

    assert first[0].used_bytes == 100
    assert same_runtime[0].used_bytes == 150
    assert restarted[0].used_bytes == 350
    assert user.traffic_used_bytes == 350


def test_config_change_invalidates_apply_proof_without_rebilling_same_runtime(tmp_path: Path):
    class TestHost(HostBackend):
        def run(self, args, **_kwargs):
            return CompletedProcess(
                args,
                0,
                "ActiveState=active\nMainPID=123\nActiveEnterTimestampMonotonic=1000000\n",
                "",
            )

    config = tmp_path / "sing-box.json"
    config.write_text("{}", encoding="utf-8")
    runtime = ManagedNodeRuntime(host=TestHost(), config_path=config)
    first = runtime.observe()
    user = User("one@example.test", "user-1")
    state = AppState(
        users=[user],
        protocols={"vless": PluginState(enabled=True, port=8443, installed=True, config={"port": 8443})},
    )
    desired = NodeDesired(
        "de-1",
        1,
        [assignment_from_user(user, reset_epoch=0)],
        [ProtocolAssignment("vless", {"port": 8443})],
    )
    receipt = ApplyReceipt(
        "apply-config-proof",
        1,
        desired.digest,
        first["apply_generation"],
        desired.users_digest,
        "b" * 64,
    )
    operation = Operation(
        receipt.operation_id,
        "apply",
        "de-1",
        desired.digest,
        "succeeded",
        completed_steps=["apply"],
        receipt=receipt,
        plan=desired.to_document(),
    )

    def update(mutate):
        result = mutate(state)
        return state, result

    records = ManagedNodeRecords(state_reader=lambda: state, state_updater=update)
    records.begin_operation(operation)
    observations = ManagedNodeObservationProvider(
        node_id="de-1",
        records=records,
        runtime=runtime,
        protocols=None,
        state_reader=lambda: state,
    )
    assert observations._current_receipt(state, first) == receipt

    first_sample = record_node_counters(state, [("user-1", "vless", 100)], runtime_id=first["runtime_id"])
    config.write_text('{"log":{"level":"debug"}}', encoding="utf-8")
    second = runtime.observe()
    second_sample = record_node_counters(state, [("user-1", "vless", 150)], runtime_id=second["runtime_id"])
    replayed_sample = record_node_counters(state, [("user-1", "vless", 150)], runtime_id=second["runtime_id"])

    assert first["config_sha256"] != second["config_sha256"]
    assert first["runtime_id"] == second["runtime_id"]
    assert first["apply_generation"] != second["apply_generation"]
    assert observations._current_receipt(state, second) is None
    assert first_sample[0].counter_epoch == second_sample[0].counter_epoch
    assert second_sample[0].used_bytes == replayed_sample[0].used_bytes == 150
    assert user.traffic_used_bytes == 150


def test_retiring_after_reset_uses_the_current_user_epoch():
    user = User("one@example.test", "user-1")
    state = AppState(users=[user])
    state.install["managed_node_user_reset_epochs"] = {"user-1": 3}
    state.install["managed_node_usage_contributions"] = {
        "de-1": {"user-1": {"vless": {"reset_epoch": 3, "epochs": {"counter-1": 75}}}}
    }

    retire_node_traffic(state, "de-1")

    assert state.install["managed_node_retired_usage"]["user-1"] == {"reset_epoch": 3, "used_bytes": 75}
    assert user.traffic_used_bytes == 75


def test_reset_discards_late_samples_from_the_previous_epoch():
    user = User("one@example.test", "user-1")
    state = AppState(users=[user])
    apply_traffic_samples(state, "de-1", [sample("user-1", 0, "counter-1", 100)])
    reset_managed_node_traffic(state, user)
    apply_traffic_samples(state, "de-1", [sample("user-1", 0, "counter-1", 200)])
    assert user.traffic_used_bytes == 0
