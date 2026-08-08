from __future__ import annotations

import copy
import json

import pytest

from hydra.core.state_migrations import migrate_state, migrate_v6_to_v7
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
    assert migrate_state(_v6(), 6) == once


def test_v6_disabled_creator_becomes_disabled_calls_pool() -> None:
    raw = _v6()
    raw["protocols"]["wdtt"]["config"]["headless_enabled"] = False
    migrated = migrate_v6_to_v7(raw)
    assert migrated["protocols"]["calls"]["config"]["qwdtt_pool_enabled"] is False
    assert "legacy_creator_reinstall_required" not in migrated["protocols"]["calls"]["config"]


def test_future_schema_is_rejected_after_v7() -> None:
    with pytest.raises(UnsupportedStateVersion):
        validate_supported_version({"version": 8})


def test_migrated_state_is_json_serializable_without_secret_artifacts() -> None:
    payload = json.dumps(migrate_v6_to_v7(_v6()))
    assert "cookies-vk" not in payload
    assert "vk.com/call/join" not in payload
