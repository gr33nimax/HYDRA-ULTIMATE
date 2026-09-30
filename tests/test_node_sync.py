"""Node polling surrounds the local sync cycle, never a state-lock mutator."""

from unittest.mock import Mock, patch

from hydra.services import sync_agent
from hydra.services.sync_ports import SyncOperations


def test_node_traffic_is_collected_before_limits_and_reconciled_after_blocking():
    events = []
    operations = SyncOperations(
        protocols=Mock(),
        apply_config=lambda state: True,
        check_traffic_limits=lambda state: [],
        run_maintenance=lambda state, forced: [],
        collect_node_traffic=lambda: events.append("collect"),
        reconcile_nodes=lambda: events.append("reconcile"),
    )
    with patch.object(sync_agent, "_run_sync", side_effect=lambda **kwargs: events.append("limits") or (True, "ok")):
        assert sync_agent.run_sync(operations=operations) == (True, "ok")
    assert events == ["collect", "limits", "reconcile"]


def test_offline_collection_does_not_skip_local_limits_or_final_reconciliation():
    reconcile = Mock()
    operations = SyncOperations(
        protocols=Mock(),
        apply_config=lambda state: True,
        check_traffic_limits=lambda state: [],
        run_maintenance=lambda state, forced: [],
        collect_node_traffic=Mock(side_effect=OSError("offline")),
        reconcile_nodes=reconcile,
    )
    with (
        patch.object(sync_agent, "_run_sync", return_value=(False, "apply failed")) as local,
        patch.object(sync_agent, "_log"),
    ):
        assert sync_agent.run_sync(operations=operations) == (False, "apply failed")
    local.assert_called_once()
    reconcile.assert_called_once()
