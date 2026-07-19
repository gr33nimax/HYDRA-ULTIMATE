"""Safe desired-vs-actual reconciliation for plugin runtime state."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from hydra.core.state import AppState


class ReconciliationOperations(Protocol):
    def statuses(self, state: AppState | None = None) -> dict[str, dict]: ...
    def enable(self, state: AppState, name: str) -> bool: ...
    def disable(self, state: AppState, name: str) -> bool: ...


@dataclass(frozen=True)
class ReconcileAction:
    plugin: str
    drift: str
    operation: str | None
    reason: str


@dataclass
class ReconcileReport:
    planned: list[ReconcileAction] = field(default_factory=list)
    applied: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ReconciliationService:
    operations: ReconciliationOperations

    def plan(self, state: AppState) -> list[ReconcileAction]:
        actions: list[ReconcileAction] = []
        for name, status in self.operations.statuses(state).items():
            drift = status.get("drift", "none")
            if drift == "stopped":
                actions.append(ReconcileAction(name, drift, "enable", "сервис должен работать"))
            elif drift == "unexpectedly_running":
                actions.append(ReconcileAction(name, drift, "disable", "сервис выключен в настройках"))
            elif drift == "missing":
                actions.append(ReconcileAction(name, drift, None, "требуется установка зависимостей"))
            elif drift == "unknown":
                actions.append(ReconcileAction(name, drift, None, "фактическое состояние неизвестно"))
        return actions

    def apply(self, state: AppState) -> ReconcileReport:
        report = ReconcileReport(planned=self.plan(state))
        for action in report.planned:
            if action.operation is None:
                continue
            try:
                operation = getattr(self.operations, action.operation)
                if operation(state, action.plugin):
                    report.applied.append(action.plugin)
                else:
                    report.failed[action.plugin] = "операция не выполнена"
            except Exception as exc:
                report.failed[action.plugin] = str(exc) or exc.__class__.__name__
        return report
