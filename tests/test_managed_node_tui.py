from datetime import datetime, timezone

from hydra.contracts.managed_node_models import NodeDefinition, Operation, ProtocolAssignment
from hydra.contracts.managed_node_observations import CheckResult, NodeView
from hydra.core.host import HOST
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.observations import ManagedNodeObservationStore, NodeObservation
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.status import ManagedNodeStatusService
from hydra.ui._menus.managed_nodes import render_node_card


def test_node_card_uses_clock_users_sub_and_protocol_label_fallback():
    definition = NodeDefinition(
        "de-1",
        "Germany",
        "203.0.113.4",
        "root",
        "dev",
        "a" * 40,
        25555,
        [ProtocolAssignment("vless")],
        "credential-de-1",
    )
    view = NodeView(
        definition,
        management_check=CheckResult("management", "de-1", "ok", "2026-10-01T22:34:00+00:00"),
        users_applied=3,
        users_total=4,
        sub_state="wait",
        protocol_checks={"vless": CheckResult("connection", "de-1", "error", reason="connection refused")},
    )

    text = render_node_card(view, now=datetime(2026, 10, 1, 22, 35, tzinfo=timezone.utc), display_names={"vless": ""})
    assert "22:34" in text
    assert "Пользователи 3/4" in text
    assert "SUB : ⏳WAIT" in text
    assert "VLESS" in text
    assert "connection refused" in text
    assert "контакт" not in text and "публикация" not in text
    assert "\\n" not in text
    assert text.splitlines() == [
        "Germany · 22:34", "Управление: 🟢 Online", "Пользователи 3/4",
        "SUB : ⏳WAIT", "VLESS: ❌", "ошибка: connection refused",
    ]


def test_online_management_with_failed_apply_renders_subscription_error(tmp_path):
    now = datetime.now(timezone.utc)
    definition = NodeDefinition(
        "de-1",
        "Germany",
        "203.0.113.4",
        "root",
        "dev",
        "a" * 40,
        25555,
        [ProtocolAssignment("vless")],
        "credential-de-1",
    )
    failed_apply = Operation(
        "apply-1",
        "apply",
        "de-1",
        "b" * 64,
        "failed",
        error={"stage": "apply", "reason": "runtime config rejected"},
    )
    observation = NodeObservation(
        "de-1",
        CheckResult("management", "de-1", "ok", now.isoformat()),
        checked_at=now.isoformat(),
    )
    state = AppState()

    def update(mutate):
        result = mutate(state)
        return state, result

    records = ManagedNodeRecords(state_reader=lambda: state, state_updater=update)
    records.put_definition(definition)
    records.begin_operation(failed_apply)
    observations = ManagedNodeObservationStore(host=HOST, root=tmp_path / "observations")
    observations.write(observation)
    service = ManagedNodeStatusService(records=records, observations=observations, state_reader=lambda: state)

    view = service.list()[0]
    text = render_node_card(view, now=now)

    assert view.management_check is not None and view.management_check.outcome == "ok"
    assert view.operation == failed_apply
    assert view.sub_state == "error"
    assert "Управление: 🟢 Online" in text
    assert "SUB : ❌ERROR" in text


def test_stale_management_check_is_no_data_not_offline():
    definition = NodeDefinition(
        "de-1",
        "Germany",
        "203.0.113.4",
        "root",
        "dev",
        "a" * 40,
        25555,
        [ProtocolAssignment("vless")],
        "credential-de-1",
    )
    view = NodeView(
        definition,
        management_check=CheckResult("management", "de-1", "error", "2026-10-01T22:34:00+00:00"),
    )

    text = render_node_card(view, now=datetime(2026, 10, 1, 23, 0, tzinfo=timezone.utc))

    assert "нет данных" in text
    assert "Offline" not in text


def test_diagnostic_report_has_separate_readable_checks(monkeypatch):
    from hydra.contracts.managed_node_observations import DiagnosticReport
    from hydra.ui._menus import managed_nodes

    ok = CheckResult("management", "uk-1", "ok")
    report = DiagnosticReport(
        ok, ok,
        CheckResult("users", "uk-1", "error", reason="applied user identities or restrictions differ from the base"),
        CheckResult("subscription", "uk-1", "unknown", reason="no committed apply receipt"),
        {"amneziawg": {"configuration": CheckResult("configuration", "uk-1", "error",
                                                   reason="configured inbound is not confirmed")}},
    )
    captured = []
    monkeypatch.setattr(managed_nodes, "panel", lambda title, lines, **kwargs: captured.extend(lines))
    managed_nodes._show_report("ДИАГНОСТИКА", report)
    text = "\n".join(captured)
    assert "Управление: ✅ OK" in captured
    assert "Пользователи: ❌ Ошибка" in captured
    assert "Применение конфигурации ещё не подтверждено" in text
    assert "AmneziaWG" in captured
    assert "CheckResult(" not in text and "DiagnosticReport(" not in text


def test_resume_install_keeps_original_operation_and_ssh_key(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from hydra.ui._menus import managed_nodes

    operation = Operation("install-original", "install", "uk-1", "a" * 64, "running")
    view = SimpleNamespace(operation=operation, definition=SimpleNamespace(name="Великобритания"))
    app = MagicMock()
    monkeypatch.setattr(managed_nodes, "confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(managed_nodes, "ask_secret", lambda *args: "")
    monkeypatch.setattr(managed_nodes, "_show_report", lambda *args: None)
    managed_nodes._resume_install(view, app)
    app.nodes.resume.assert_called_once_with("install-original", None)
    app.nodes.install.assert_not_called()


def test_sync_report_includes_operation_and_actual_failure(monkeypatch):
    from hydra.contracts.managed_node_observations import SyncReport
    from hydra.ui._menus import managed_nodes

    captured = []
    monkeypatch.setattr(managed_nodes, "panel", lambda title, lines, **kwargs: captured.extend(lines))
    managed_nodes._show_report("СИНХРОНИЗАЦИЯ", SyncReport(
        {"uk-1": {"status": "failed", "operation_id": "apply-1", "error": "profile export failed"}},
        errors=["profile export failed"],
    ))
    assert captured == ["uk-1: failed", "Операция: apply-1", "Причина: profile export failed"]


def test_awg_card_reports_configuration_when_native_connection_probe_is_unavailable(tmp_path):
    now = datetime.now(timezone.utc)
    state = AppState()
    def update(mutate):
        return state, mutate(state)
    records = ManagedNodeRecords(state_reader=lambda: state, state_updater=update)
    records.put_definition(NodeDefinition("uk-1", "UK", "203.0.113.4", "root", "dev", "a" * 40,
                                         24443, [ProtocolAssignment("amneziawg")], "node/uk-1"))
    observations = ManagedNodeObservationStore(host=HOST, root=tmp_path / "observations")
    configuration = CheckResult("configuration", "uk-1", "ok", now.isoformat())
    observations.write(NodeObservation(
        "uk-1", CheckResult("management", "uk-1", "ok", now.isoformat()),
        protocols={"amneziawg": {"configuration": configuration,
            "connection": CheckResult("connection", "uk-1", "not_applicable", now.isoformat())}},
        checked_at=now.isoformat(),
    ))
    view = ManagedNodeStatusService(records=records, observations=observations, state_reader=lambda: state).list()[0]
    assert view.protocol_checks["amneziawg"] == configuration
    assert "AmneziaWG: ✅ (конфигурация)" in render_node_card(view, now=now)
