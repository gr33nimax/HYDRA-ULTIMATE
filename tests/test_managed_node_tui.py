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
