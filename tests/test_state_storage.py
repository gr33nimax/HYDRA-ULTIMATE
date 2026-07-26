import json
from unittest.mock import patch

import pytest

from hydra.core import state as state_module
from hydra.core.errors import StateConflictError
from hydra.core.state import AppState, UnsupportedStateVersion
from hydra.core.state_models import User


def _use_temp_state(monkeypatch, tmp_path):
    monkeypatch.setattr(state_module, "STATE_DIR", tmp_path)
    monkeypatch.setattr(state_module, "STATE_FILE", tmp_path / "state.json")


def test_future_schema_is_never_silently_downgraded(monkeypatch, tmp_path):
    _use_temp_state(monkeypatch, tmp_path)
    state_module.STATE_FILE.write_text(json.dumps({"version": 999}), encoding="utf-8")
    state_module.STATE_FILE.with_suffix(".json.bak").write_text(
        json.dumps({"version": state_module.SCHEMA_VERSION}), encoding="utf-8"
    )
    with pytest.raises(UnsupportedStateVersion, match="newer than supported"):
        state_module.load_state()


def test_migration_registry_runs_in_order_without_mutating_source():
    source = {"version": 0, "users": [{"email": "u", "uuid": "id"}]}
    migrated = state_module._migrate(source, 0)
    assert source["version"] == 0
    assert migrated["version"] == state_module.SCHEMA_VERSION
    assert migrated["users"][0]["credentials"] == {}


def test_missing_migration_fails_closed(monkeypatch):
    monkeypatch.setattr(state_module, "_MIGRATIONS", {0: state_module._migrate_v0_to_v1})
    with pytest.raises(RuntimeError, match="missing state migration 1 -> 2"):
        state_module._migrate({"version": 0, "users": []}, 0)


def test_save_atomically_replaces_backup_and_syncs_directory(monkeypatch, tmp_path):
    _use_temp_state(monkeypatch, tmp_path)
    state_module.save_state(AppState())
    with patch.object(state_module, "_fsync_directory") as sync:
        state_module.save_state(AppState())
    assert state_module.STATE_FILE.with_suffix(".json.bak").is_file()
    assert not state_module.STATE_FILE.with_suffix(".bak.pending").exists()
    sync.assert_called_once_with(tmp_path)


def test_double_corruption_creates_quarantine_copy(monkeypatch, tmp_path):
    _use_temp_state(monkeypatch, tmp_path)
    state_module.STATE_FILE.write_text("{broken", encoding="utf-8")
    state_module.STATE_FILE.with_suffix(".json.bak").write_text("{also-broken", encoding="utf-8")
    with pytest.raises(RuntimeError, match="State file is corrupt"):
        state_module.load_state()
    assert state_module.STATE_FILE.with_suffix(".json.corrupt").read_text(encoding="utf-8") == "{broken"


def test_stale_desired_state_write_is_rejected(monkeypatch, tmp_path):
    _use_temp_state(monkeypatch, tmp_path)
    state_module.save_state(AppState())
    first = state_module.load_state()
    stale = state_module.load_state()

    first.network.domain = "first.example"
    state_module.save_state(first)

    stale.network.domain = "stale.example"
    with pytest.raises(StateConflictError, match="reload and retry"):
        state_module.save_state(stale)

    persisted = state_module.load_state()
    assert persisted.network.domain == "first.example"
    assert persisted.revision == first.revision


def test_runtime_updates_do_not_conflict_with_stale_settings(
    monkeypatch,
    tmp_path,
):
    _use_temp_state(monkeypatch, tmp_path)
    initial = AppState(users=[User(email="u@example.com", uuid="u1")])
    state_module.save_state(initial)
    stale = state_module.load_state()
    initial_revision = stale.revision

    def record_runtime(current):
        current.users[0].traffic_used_bytes = 500
        current.install["traffic_daemon_last_poll"] = "now"
        current.install["singbox_latest_version"] = "2.0"

    runtime, _ = state_module.update_state(record_runtime)
    assert runtime.revision == initial_revision

    stale.network.domain = "settings.example"
    state_module.save_state(stale)
    persisted = state_module.load_state()

    assert persisted.revision == initial_revision + 1
    assert persisted.network.domain == "settings.example"
    assert persisted.users[0].traffic_used_bytes == 500
    assert persisted.install["traffic_daemon_last_poll"] == "now"
    assert persisted.install["singbox_latest_version"] == "2.0"
