import pytest

from hydra.core.apply_transaction import ApplyTransaction


def test_rollback_runs_in_priority_order_once():
    events = []
    transaction = ApplyTransaction()
    transaction.add_rollback("plugins", lambda: events.append("plugins"), priority=30)
    transaction.add_rollback("config", lambda: events.append("config"), priority=10)
    transaction.add_rollback("network", lambda: events.append("network"), priority=20)

    assert transaction.rollback() == []
    assert transaction.rollback() == []
    assert events == ["config", "network", "plugins"]
    assert transaction.phase == "rolled_back"


def test_rollback_continues_after_failure_and_reports_it():
    events = []
    errors = []
    transaction = ApplyTransaction()

    def fail():
        raise RuntimeError("boom")

    transaction.add_rollback("broken", fail, priority=10)
    transaction.add_rollback("healthy", lambda: events.append("healthy"), priority=20)

    failures = transaction.rollback(errors.append)

    assert [(failure.action, failure.error) for failure in failures] == [("broken", "boom")]
    assert events == ["healthy"]
    assert errors == ["Rollback broken failed: boom"]


def test_commit_discards_rollback_actions():
    events = []
    transaction = ApplyTransaction()
    transaction.add_rollback("unused", lambda: events.append("rollback"))

    transaction.commit()

    assert transaction.rollback() == []
    assert transaction.phase == "committed"
    assert events == []


def test_finalized_transaction_rejects_new_actions():
    transaction = ApplyTransaction()
    transaction.commit()

    with pytest.raises(RuntimeError, match="finalized"):
        transaction.add_rollback("late", lambda: None)
