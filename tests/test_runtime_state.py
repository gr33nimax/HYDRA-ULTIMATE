from hydra.core.runtime_state import RuntimeSnapshot
from hydra.core.state import AppState, PluginState, _to_dict


def test_runtime_snapshot_is_immutable_and_has_explicit_drift_view():
    snapshot = RuntimeSnapshot.from_statuses({
        "demo": {"desired_enabled": True, "installed": True, "running": False, "drift": "stopped"},
        "idle": {"desired_enabled": False, "installed": True, "running": False, "drift": "none"},
    })
    assert snapshot.drifts() == {"demo": "stopped"}
    assert snapshot.plugins["demo"].desired_enabled is True


def test_runtime_snapshot_is_not_persisted_in_state_json():
    state = AppState(protocols={"demo": PluginState(enabled=True, installed=True)})
    persisted = _to_dict(state)
    assert "runtime" not in persisted
    assert "runtime_snapshot" not in persisted
