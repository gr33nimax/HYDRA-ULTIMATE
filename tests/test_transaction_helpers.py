from hydra.core.transaction_helpers import state_transaction


def test_state_transaction_registers_canonical_restore_order():
    events: list[str] = []
    transaction = state_transaction(
        lambda: events.append("state"),
        lambda: events.append("config"),
    )
    transaction.add_rollback("plugin", lambda: events.append("plugin"), priority=10)
    transaction.rollback(lambda _: None)
    assert events == ["plugin", "state", "config"]


def test_state_transaction_rollback_is_at_most_once():
    calls: list[str] = []
    transaction = state_transaction(
        lambda: calls.append("state"),
        lambda: calls.append("config"),
    )
    transaction.rollback(lambda _: None)
    transaction.rollback(lambda _: None)
    assert calls == ["state", "config"]
