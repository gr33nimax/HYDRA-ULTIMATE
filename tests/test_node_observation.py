"""Node observations: runtime facts kept out of desired state."""

from datetime import datetime, timezone

from hydra.core.host import HostBackend
from hydra.services.nodes.control_client import NodeControlError
from hydra.services.nodes.observation import (
    CONTROL_ERROR,
    CONTROL_OK,
    NodeObservationStore,
    describe_failure,
)
from hydra.services.nodes.snapshot_store import SnapshotStoreError

FIXED = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _store(tmp_path):
    return NodeObservationStore(host=HostBackend(), path=tmp_path / "observations.json", now=lambda: FIXED)


def test_observation_survives_reopening_and_records_the_success_time(tmp_path):
    store = _store(tmp_path)

    store.succeeded("de-1", applied_generation=3, published_generation=3, coverage={"vless": 2})

    reopened = _store(tmp_path)
    observation = reopened.get("de-1")
    assert observation is not None
    assert observation.control == CONTROL_OK
    assert observation.published is True
    assert observation.ready is True
    assert observation.coverage == {"vless": 2}
    assert observation.checked_at == observation.last_success_at == FIXED.isoformat()


def test_a_failure_replaces_the_message_without_losing_the_last_success(tmp_path):
    store = _store(tmp_path)
    store.succeeded("de-1", applied_generation=3, published_generation=3)

    store.failed("de-1", RuntimeError("node export contains no client profiles"))

    observation = store.get("de-1")
    assert observation is not None
    assert observation.control == CONTROL_ERROR
    assert observation.stage == "export"
    assert observation.code == "empty_export"
    assert observation.ready is False
    # The last good moment stays visible: "when did this work" is what an operator asks.
    assert observation.last_success_at == FIXED.isoformat()


def test_failures_are_classified_by_what_broke_not_by_the_message_alone():
    assert describe_failure(NodeControlError("control request failed")) == ("connect", "control_unavailable")
    assert describe_failure(SnapshotStoreError("snapshot file is unavailable")) == ("publish", "publication_storage")
    assert describe_failure(RuntimeError("node did not confirm the requested generation")) == (
        "apply",
        "apply_not_confirmed",
    )
    assert describe_failure(RuntimeError("node health or contract check failed")) == ("connect", "health_or_contract")


def test_observations_are_redacted_never_raise_and_stay_out_of_state(tmp_path):
    store = _store(tmp_path)

    observation = store.failed("de-1", RuntimeError("token=supersecret authorization: Bearer abcdef"))

    assert "supersecret" not in observation.message
    assert "abcdef" not in observation.message
    # A diagnostics store must never break the operation it reports on.
    broken = NodeObservationStore(host=HostBackend(), path=tmp_path / "missing" / "deep" / "file.json")
    broken.record("de-1", control=CONTROL_OK)


def test_an_unreadable_or_foreign_document_reads_as_empty(tmp_path):
    path = tmp_path / "observations.json"
    path.write_text("{not json", encoding="utf-8")
    store = NodeObservationStore(host=HostBackend(), path=path)

    assert store.load() == {}

    path.write_text('{"nodes": {"de-1": "not an object"}}', encoding="utf-8")
    observation = store.load()["de-1"]
    assert observation.node_id == "de-1"
    assert observation.control == "unknown"


def test_forgetting_a_node_removes_only_that_node(tmp_path):
    store = _store(tmp_path)
    store.succeeded("de-1")
    store.succeeded("uk-1")

    store.forget("de-1")

    assert set(store.load()) == {"uk-1"}


def test_the_store_is_bounded(tmp_path):
    store = NodeObservationStore(
        host=HostBackend(),
        path=tmp_path / "observations.json",
        max_observations=2,
        now=lambda: FIXED,
    )
    for node_id in ("de-1", "uk-1", "fr-1"):
        store.succeeded(node_id, applied_generation=1)

    assert len(store.load()) == 2
