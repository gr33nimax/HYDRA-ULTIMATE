from __future__ import annotations

import pytest

from hydra.contracts.node_traffic import NodeTrafficReport, NodeTrafficUsage
from hydra.contracts.node_validation import NodeContractError
from hydra.core import state as storage
from hydra.core.state_models import AppState, User
from hydra.services.node_traffic_accounting import apply_node_traffic_reports
from hydra.services.traffic import reset_user_traffic


def _report(node_id: str, *, epoch: int, used: int, generation: int = 1) -> NodeTrafficReport:
    return NodeTrafficReport(
        node_id=node_id,
        generation=generation,
        users={"user-1": NodeTrafficUsage(reset_epoch=epoch, used_bytes=used)},
    )


def test_node_traffic_report_round_trips_absolute_user_counters():
    report = _report("de-1", epoch=2, used=4096)

    assert NodeTrafficReport.from_document(report.to_document()) == report


def test_node_traffic_report_rejects_invalid_counters_and_unknown_fields():
    with pytest.raises(NodeContractError, match="used_bytes"):
        NodeTrafficUsage(reset_epoch=0, used_bytes=-1).validate()

    document = _report("de-1", epoch=0, used=0).to_document()
    document["secret"] = "must-not-cross-control-api"
    with pytest.raises(NodeContractError, match="unsupported fields"):
        NodeTrafficReport.from_document(document)


def test_node_usage_is_absolute_idempotent_and_out_of_order_safe():
    user = User(email="u@example.com", uuid="user-1", traffic_used_bytes=100)
    state = AppState(users=[user])

    apply_node_traffic_reports(state, [_report("de-1", epoch=0, used=50)])
    apply_node_traffic_reports(state, [_report("de-1", epoch=0, used=50)])
    apply_node_traffic_reports(state, [_report("de-1", epoch=0, used=35)])

    assert user.traffic_used_bytes == 150
    assert state.install["node_traffic_contributions"]["de-1"]["user-1"] == {
        "reset_epoch": 0,
        "used_bytes": 50,
    }


def test_user_reset_invalidates_old_node_reports_and_accepts_new_epoch():
    user = User(email="u@example.com", uuid="user-1", traffic_used_bytes=100)
    state = AppState(users=[user])
    apply_node_traffic_reports(state, [_report("de-1", epoch=0, used=50)])

    reset_user_traffic(state, user.email)
    apply_node_traffic_reports(state, [_report("de-1", epoch=0, used=80)])
    assert user.traffic_used_bytes == 0

    apply_node_traffic_reports(state, [_report("de-1", epoch=1, used=7)])
    assert user.traffic_used_bytes == 7


def test_saved_node_reset_survives_runtime_merge_and_stale_menu_save():
    storage.save_state(AppState(users=[User(email="u@example.com", uuid="user-1", traffic_used_bytes=100)]))
    stale = storage.load_state()
    current = storage.load_state()
    reset_user_traffic(current, "u@example.com")
    storage.save_state(current)
    assert storage.load_state().users[0].traffic_used_bytes == 0
    assert storage.load_state().install["traffic_user_reset_epochs"]["user-1"] == 1
    storage.save_state(stale)
    assert storage.load_state().users[0].traffic_used_bytes == 0


def test_node_poll_does_not_change_desired_revision_or_get_erased_by_menu_save():
    storage.save_state(AppState(users=[User(email="u@example.com", uuid="user-1", traffic_used_bytes=100)]))
    stale = storage.load_state()
    revision = stale.revision
    updated, _ = storage.update_state(lambda state: apply_node_traffic_reports(state, [_report("de-1", epoch=0, used=50)]))
    assert updated.revision == revision
    storage.save_state(stale)
    saved = storage.load_state()
    assert saved.users[0].traffic_used_bytes == 150
    assert saved.install["local_user_traffic_totals"]["user-1"] == 100
    assert saved.install["node_traffic_contributions"]["de-1"]["user-1"]["used_bytes"] == 50


def test_multiple_nodes_are_summed_once_and_kept_separate_from_local_usage():
    user = User(email="u@example.com", uuid="user-1", traffic_used_bytes=100)
    state = AppState(users=[user])

    apply_node_traffic_reports(
        state,
        [
            _report("de-1", epoch=0, used=50),
            _report("us-1", epoch=0, used=20),
        ],
    )
    assert user.traffic_used_bytes == 170
    assert state.install["local_user_traffic_totals"]["user-1"] == 100
