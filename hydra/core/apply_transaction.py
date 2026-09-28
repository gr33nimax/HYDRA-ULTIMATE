"""Explicit lifecycle and rollback plan for configuration application."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


RollbackCallback = Callable[[], object]
ErrorCallback = Callable[[str], None]


@dataclass(frozen=True)
class RollbackFailure:
    action: str
    error: str


@dataclass(order=True)
class _RollbackAction:
    priority: int
    sequence: int
    name: str = field(compare=False)
    callback: RollbackCallback = field(compare=False, repr=False)


class ApplyTransaction:
    """Collect rollback actions and guarantee at-most-once finalization."""

    def __init__(self) -> None:
        self.phase = "validate"
        self._actions: list[_RollbackAction] = []
        self._sequence = 0
        self._finalized = False

    def advance(self, phase: str) -> None:
        if self._finalized:
            raise RuntimeError("apply transaction is already finalized")
        self.phase = phase

    def add_rollback(
        self,
        name: str,
        callback: RollbackCallback,
        *,
        priority: int = 100,
    ) -> None:
        if self._finalized:
            raise RuntimeError("cannot add rollback action to finalized transaction")
        self._actions.append(_RollbackAction(priority, self._sequence, name, callback))
        self._sequence += 1

    def rollback(self, on_error: ErrorCallback | None = None) -> list[RollbackFailure]:
        """Run the registered rollbacks once; a ``False`` return is a failure.

        Plugin rollbacks signal failure by returning ``False`` instead of
        raising, so their result must not be discarded here.
        """
        if self._finalized:
            return []
        self.phase = "rollback"
        failures: list[RollbackFailure] = []
        for action in sorted(self._actions):
            try:
                outcome = action.callback()
                if isinstance(outcome, bool) and not outcome:
                    raise RuntimeError("rollback step reported failure")
            except Exception as exc:
                detail = str(exc)
                failure = RollbackFailure(action.name, detail if detail else exc.__class__.__name__)
                failures.append(failure)
                if on_error is not None:
                    on_error(f"Rollback {action.name} failed: {failure.error}")
        self.phase = "rolled_back"
        self._finalized = True
        return failures

    def commit(self) -> None:
        if self._finalized:
            raise RuntimeError("apply transaction is already finalized")
        self.phase = "committed"
        self._finalized = True
        self._actions.clear()
