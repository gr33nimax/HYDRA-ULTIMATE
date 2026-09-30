from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hydra.contracts.node_snapshot import NodeDesiredSnapshot, NodeProtocolSpec
from hydra.core.errors import ServiceResult
from hydra.core.state_models import AppState, PluginState
from hydra.services.nodes.reconcile import NodeReconciler


def _setup(enabled=False):
    state = AppState(protocols={"calls": PluginState(installed=True, enabled=enabled)})
    app = MagicMock()
    app.protocols.list.return_value = [
        SimpleNamespace(
            meta=SimpleNamespace(
                name="calls",
                capabilities=SimpleNamespace(subscription_enabled=False, hydra_v2_subscription_enabled=True),
            )
        )
    ]
    app.protocols.enabled_subscription_names.return_value = set()
    app.calls.snapshot_managed_vk_pool.return_value = object()

    def enable(current):
        current.protocols["calls"].enabled = True
        return ServiceResult(True)

    def disable(current):
        current.protocols["calls"].enabled = False
        return ServiceResult(True)

    app.calls.enable_native_vk.side_effect = enable
    app.calls.disable_native_vk.side_effect = disable
    return state, app, NodeReconciler("de-1", app, state_reader=lambda: state)


def test_node_first_enable_uses_native_creator_lifecycle_and_is_idempotent():
    state, app, reconciler = _setup()
    snapshot = NodeDesiredSnapshot(node_id="de-1", generation=1, protocols={"calls": NodeProtocolSpec(enabled=True)})
    reconciler.apply(snapshot)
    reconciler.apply(snapshot)
    assert state.protocols["calls"].enabled
    app.calls.enable_native_vk.assert_called_once_with(state)
    app.calls.snapshot_managed_vk_pool.assert_called_once()
    app.protocols.enable.assert_not_called()
    app.calls.restore_managed_vk_pool.assert_not_called()


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("failure", ["lifecycle", "export", "save"])
def test_failed_node_transition_restores_captured_pool_and_generation(enabled, failure):
    state, app, reconciler = _setup(enabled)
    desired = not enabled
    snapshot = NodeDesiredSnapshot(node_id="de-1", generation=1, protocols={"calls": NodeProtocolSpec(enabled=desired)})
    if failure == "lifecycle":
        operation = app.calls.disable_native_vk if enabled else app.calls.enable_native_vk
        operation.side_effect = RuntimeError("injected lifecycle failure")
    elif failure == "export":
        reconciler._export_state = MagicMock(side_effect=RuntimeError("injected export failure"))
    else:
        app.admin.save_state.side_effect = [RuntimeError("injected save failure"), None]
    with pytest.raises(RuntimeError, match="injected"):
        reconciler.apply(snapshot)
    app.calls.restore_managed_vk_pool.assert_called_once_with(app.calls.snapshot_managed_vk_pool.return_value)
    assert state.protocols["calls"].enabled == enabled
    assert reconciler.current_generation() == 0
