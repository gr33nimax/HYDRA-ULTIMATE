"""Reusable transaction registration helpers for stateful operations."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.apply_transaction import ApplyTransaction


Rollback = Callable[[], object]


def state_transaction(
    restore_state: Rollback,
    restore_config: Rollback,
) -> ApplyTransaction:
    """Create the canonical state/config rollback skeleton.

    Lifecycle operations may add plugin-specific rollback actions around this
    skeleton, but state restoration always precedes configuration re-apply.
    ``ApplyTransaction`` still enforces at-most-once execution and priority
    ordering.
    """
    transaction = ApplyTransaction()
    transaction.advance("apply")
    transaction.add_rollback("application state", restore_state, priority=20)
    transaction.add_rollback("restored configuration", restore_config, priority=30)
    return transaction
