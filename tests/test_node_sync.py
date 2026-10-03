"""Managed-node polling surrounds one base quota update, never a retry wrapper."""

from hydra.core.state_models import AppState
from hydra.services.sync_cycle import run_sync_cycle
from hydra.services.sync_ports import SyncOperations


class _NodeSync:
    def __init__(self, events, *, errors=None):
        self.events = events
        self.errors = errors or []

    def run_cycle(self, local_sync):
        self.events.append("collect")
        state, blocked, failures = local_sync()
        self.events.append("reconcile")
        return state, blocked, [*failures, *self.errors]


def _operations(events, *, node_sync=None):
    state = AppState()
    state.install.update({
        "sync_limits_enabled": True,
        "sync_updates_enabled": False,
        "sync_certificates_enabled": False,
    })
    return SyncOperations(
        protocols=type("Protocols", (), {"notify_user_block": lambda *_: [], "maintenance_jobs": lambda *_: []})(),
        apply_config=lambda _state: True,
        check_traffic_limits=lambda _state: events.append("limits") or [],
        run_maintenance=lambda _state, _forced: [],
        managed_node_sync=node_sync,
    ), state


def test_node_traffic_is_collected_before_limits_and_reconciled_after_blocking():
    events = []
    node_sync = _NodeSync(events)
    operations, state = _operations(events, node_sync=node_sync)
    ok, message = run_sync_cycle(
        state,
        operations=operations,
        update_state=lambda mutate: (state, mutate(state)),
        log=lambda _message: None,
    )
    assert ok is True
    assert "Sync completed" in message
    assert events == ["collect", "limits", "reconcile"]


def test_node_failures_are_combined_after_local_limits_complete():
    events = []
    node_sync = _NodeSync(events, errors=["node de-1: management offline"])
    operations, state = _operations(events, node_sync=node_sync)
    ok, message = run_sync_cycle(
        state,
        operations=operations,
        update_state=lambda mutate: (state, mutate(state)),
        log=lambda _message: None,
    )
    assert ok is False
    assert "node de-1: management offline" in message
    assert events == ["collect", "limits", "reconcile"]
