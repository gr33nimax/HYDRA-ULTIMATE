from datetime import datetime, timedelta, timezone

from hydra.core.host import HostBackend
from hydra.services.calls_health import CallsProbeStore, ProbeDecision


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _store(tmp_path):
    return CallsProbeStore(HostBackend(), tmp_path / "probe-state.json")


def test_claims_one_unchecked_slot_and_enforces_start_spacing(tmp_path) -> None:
    store = _store(tmp_path)

    assert store.claim_due(["one", "two"], now=NOW) == ProbeDecision(1, False)
    assert store.claim_due(["one", "two"], now=NOW + timedelta(seconds=59)) is None

    store.record(["one", "two"], ProbeDecision(1, False), "healthy", now=NOW)
    assert store.claim_due(["one", "two"], now=NOW + timedelta(minutes=1)) == ProbeDecision(2, False)


def test_dead_result_requires_delayed_confirmation_before_replacement(tmp_path) -> None:
    store = _store(tmp_path)
    hashes = ["one"]
    first = store.claim_due(hashes, now=NOW)
    assert first == ProbeDecision(1, False)
    assert first is not None

    store.record(hashes, first, "dead", now=NOW)
    assert store.claim_due(hashes, now=NOW + timedelta(minutes=14)) is None
    assert store.claim_due(hashes, now=NOW + timedelta(minutes=15)) == ProbeDecision(1, True)


def test_non_dead_outcomes_do_not_trigger_confirmation(tmp_path) -> None:
    store = _store(tmp_path)
    hashes = ["one"]
    decision = store.claim_due(hashes, now=NOW)
    assert decision is not None

    store.record(hashes, decision, "network", now=NOW)
    assert store.claim_due(hashes, now=NOW + timedelta(minutes=15)) is None


def test_new_room_hash_resets_its_probe_history(tmp_path) -> None:
    store = _store(tmp_path)
    hashes = ["one"]
    decision = store.claim_due(hashes, now=NOW)
    assert decision is not None
    store.record(hashes, decision, "healthy", now=NOW)

    assert store.claim_due(["replacement"], now=NOW + timedelta(minutes=1)) == ProbeDecision(1, False)
