from unittest.mock import Mock

from hydra.core.state import AppState
from hydra.services.reconciliation import ReconciliationService


def test_plan_contains_only_actionable_drift():
    operations = Mock()
    operations.statuses.return_value = {
        "stopped": {"drift": "stopped"},
        "unexpected": {"drift": "unexpectedly_running"},
        "missing": {"drift": "missing"},
        "unknown": {"drift": "unknown"},
        "healthy": {"drift": "none"},
    }

    actions = ReconciliationService(operations).plan(AppState())

    assert [(action.plugin, action.operation) for action in actions] == [
        ("stopped", "enable"),
        ("unexpected", "disable"),
        ("missing", None),
        ("unknown", None),
    ]
    operations.enable.assert_not_called()
    operations.disable.assert_not_called()


def test_apply_executes_only_safe_runtime_operations():
    operations = Mock()
    operations.statuses.return_value = {
        "stopped": {"drift": "stopped"},
        "unexpected": {"drift": "unexpectedly_running"},
        "missing": {"drift": "missing"},
    }
    operations.enable.return_value = True
    operations.disable.return_value = True

    report = ReconciliationService(operations).apply(AppState())

    assert report.applied == ["stopped", "unexpected"]
    assert report.failed == {}
    operations.enable.assert_called_once()
    operations.disable.assert_called_once()


def test_apply_reports_false_operations():
    operations = Mock()
    operations.statuses.return_value = {"stopped": {"drift": "stopped"}}
    operations.enable.return_value = False

    report = ReconciliationService(operations).apply(AppState())

    assert report.applied == []
    assert report.failed == {"stopped": "операция не выполнена"}


def test_apply_contains_exception_details():
    operations = Mock()
    operations.statuses.return_value = {"stopped": {"drift": "stopped"}}
    operations.enable.side_effect = RuntimeError("busy")

    report = ReconciliationService(operations).apply(AppState())

    assert report.failed == {"stopped": "busy"}
