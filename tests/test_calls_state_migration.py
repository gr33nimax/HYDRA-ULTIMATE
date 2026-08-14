from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from hydra.core import state as state_module
from hydra.core.state_migrations import (
    migrate_state,
    migrate_v6_to_v7,
    migrate_v7_to_v8,
    migrate_v8_to_v9,
    migrate_v9_to_v10,
    migrate_v10_to_v11,
    migrate_v11_to_v12,
    migrate_v12_to_v13,
)
from hydra.core.state_models import UnsupportedStateVersion, validate_supported_version


def _v6() -> dict:
    return {
        "version": 6,
        "revision": 3,
        "install": {"sync_wdtt_headless_enabled": False},
        "protocols": {
            "wdtt": {
                "enabled": True,
                "installed": True,
                "port": 56000,
                "config": {
                    "headless_enabled": True,
                    "headless_refresh_interval_seconds": 7200,
                    "main_password": "kept",
                },
            },
        },
        "users": [],
        "telegram": {},
        "network": {},
    }


def test_v6_to_v7_moves_creator_desired_state_without_native_auto_enable() -> None:
    source = _v6()
    original = copy.deepcopy(source)

    migrated = migrate_v6_to_v7(source)

    assert source == original
    assert migrated["version"] == 7
    assert "headless_enabled" not in migrated["protocols"]["wdtt"]["config"]
    assert "headless_refresh_interval_seconds" not in migrated["protocols"]["wdtt"]["config"]
    assert migrated["protocols"]["wdtt"]["config"]["main_password"] == "kept"
    calls = migrated["protocols"]["calls"]
    assert calls["enabled"] is False
    assert calls["installed"] is False
    assert calls["config"] == {
        "qwdtt_pool_enabled": True,
        "legacy_creator_reinstall_required": True,
        "qwdtt_refresh_interval_seconds": 7200,
    }
    assert migrated["install"]["sync_calls_qwdtt_pool_enabled"] is False
    assert "sync_wdtt_headless_enabled" not in migrated["install"]


def test_v6_to_v7_is_idempotent() -> None:
    once = migrate_v6_to_v7(_v6())
    assert migrate_v6_to_v7(once) == once
    assert migrate_state(_v6(), 6) == migrate_v12_to_v13(migrate_v11_to_v12(
        migrate_v10_to_v11(
            migrate_v9_to_v10(migrate_v8_to_v9(migrate_v7_to_v8(once))),
        ),
    ))


def test_v6_disabled_creator_becomes_disabled_calls_pool() -> None:
    raw = _v6()
    raw["protocols"]["wdtt"]["config"]["headless_enabled"] = False
    migrated = migrate_v6_to_v7(raw)
    assert migrated["protocols"]["calls"]["config"]["qwdtt_pool_enabled"] is False
    assert "legacy_creator_reinstall_required" not in migrated["protocols"]["calls"]["config"]


def test_v7_to_v8_extracts_creator_from_calls() -> None:
    source = migrate_v6_to_v7(_v6())
    migrated = migrate_v7_to_v8(source)

    assert migrated["version"] == 8
    assert migrated["protocols"]["calls"]["config"] == {}
    assert migrated["headless_creator"]["providers"]["vk"] == {
        "qwdtt_pool_enabled": True,
        "qwdtt_refresh_interval_seconds": 7200,
        "legacy_creator_reinstall_required": True,
    }
    assert migrated["install"]["sync_headless_creator_vk_qwdtt_enabled"] is False
    assert "sync_calls_qwdtt_pool_enabled" not in migrated["install"]
    assert migrate_v7_to_v8(migrated) == migrated


def test_v8_to_v9_separates_qwdtt_consumer_from_vk_provider() -> None:
    source = migrate_v7_to_v8(migrate_v6_to_v7(_v6()))
    migrated = migrate_v8_to_v9(source)

    assert migrated["version"] == 9
    assert migrated["headless_creator"]["providers"] == {}
    assert migrated["headless_creator"]["consumers"]["qwdtt"] == {
        "provider": "vk",
        "pool_enabled": True,
        "refresh_interval_seconds": 7200,
        "legacy_creator_reinstall_required": True,
        "room_count": 4,
    }
    assert migrate_v8_to_v9(migrated) == migrated


def test_v10_to_v11_disables_legacy_calls_without_touching_other_protocols() -> None:
    source = {
        "version": 10,
        "kernel": {"provider": "sing-box-extended", "channel": "stable"},
        "protocols": {
            "calls": {
                "installed": True,
                "enabled": True,
                "config": {"mode": "p2p", "read_buffer": 65536},
            },
            "vless": {"installed": True, "enabled": True, "config": {}},
        },
    }
    original = copy.deepcopy(source)

    migrated = migrate_v10_to_v11(source)

    assert source == original
    assert migrated["version"] == 11
    assert migrated["protocols"]["calls"] == {
        "installed": True,
        "enabled": False,
        "config": {"mode": "vk_parasite"},
    }
    assert migrated["protocols"]["vless"] == original["protocols"]["vless"]
    assert migrate_v10_to_v11(migrated) == migrated


def test_v10_to_v11_preserves_active_vk_parasite_calls_on_hydracore() -> None:
    migrated = migrate_v10_to_v11({
        "version": 10,
        "kernel": {"provider": "hydracore", "channel": "stable"},
        "protocols": {
            "calls": {
                "installed": True,
                "enabled": True,
                "config": {"mode": "vk_parasite", "room_count": 4},
            },
        },
    })

    assert migrated["protocols"]["calls"]["enabled"] is True
    assert migrated["protocols"]["calls"]["config"] == {
        "mode": "vk_parasite",
        "room_count": 4,
    }


def test_v11_to_v12_selects_exact_four_lane_contract() -> None:
    source = {
        "version": 11,
        "protocols": {
            "calls": {
                "installed": True,
                "enabled": True,
                "config": {
                    "mode": "vk_parasite",
                    "multipath_profile": "adaptive",
                    "workers": 16,
                    "max_workers_per_session": 16,
                },
            },
        },
    }

    migrated = migrate_v11_to_v12(source)

    assert migrated["version"] == 12
    assert migrated["protocols"]["calls"]["enabled"] is True
    assert migrated["protocols"]["calls"]["config"] == {
        "mode": "vk_parasite",
        "workers": 4,
        "max_workers_per_session": 4,
    }
    assert migrate_v11_to_v12(migrated) == migrated


def test_v12_to_v13_selects_exact_eight_lane_contract() -> None:
    source = {
        "version": 12,
        "protocols": {
            "calls": {
                "installed": True,
                "enabled": True,
                "config": {
                    "mode": "vk_parasite",
                    "workers": 4,
                    "max_workers_per_session": 4,
                },
            },
        },
    }

    migrated = migrate_v12_to_v13(source)

    assert migrated["version"] == 13
    assert migrated["protocols"]["calls"]["enabled"] is False
    assert migrated["protocols"]["calls"]["config"] == {
        "mode": "vk_parasite",
        "workers": 8,
        "max_workers_per_session": 8,
    }
    assert migrate_v12_to_v13(migrated) == migrated


def test_v10_calls_fixture_is_atomically_disabled_and_idempotent(
    tmp_path,
    monkeypatch,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "state-schema-10-calls-p2p.json"
    state_file = tmp_path / "state.json"
    shutil.copy2(fixture, state_file)
    monkeypatch.setattr(state_module, "STATE_DIR", tmp_path)
    monkeypatch.setattr(state_module, "STATE_FILE", state_file)

    first = state_module.migrate_persisted_state()
    migrated_bytes = state_file.read_bytes()
    second = state_module.migrate_persisted_state()
    loaded = state_module.load_state()

    assert first == {"from": 10, "to": 13, "changed": True}
    assert second == {"from": 13, "to": 13, "changed": False}
    assert state_file.read_bytes() == migrated_bytes
    assert loaded.revision == 42
    assert loaded.protocols["calls"].installed is True
    assert loaded.protocols["calls"].enabled is False
    assert loaded.protocols["calls"].config == {
        "mode": "vk_parasite",
        "workers": 8,
        "max_workers_per_session": 8,
    }
    assert loaded.protocols["vless"].enabled is True
    assert loaded.install["preserved_upgrade_marker"] == "keep"
    assert state_file.with_suffix(".json.bak").is_file()


def test_future_schema_is_rejected_after_v13() -> None:
    with pytest.raises(UnsupportedStateVersion):
        validate_supported_version({"version": 14})


def test_migrated_state_is_json_serializable_without_secret_artifacts() -> None:
    payload = json.dumps(migrate_state(_v6(), 6))
    assert "cookies-vk" not in payload
    assert "vk.com/call/join" not in payload
