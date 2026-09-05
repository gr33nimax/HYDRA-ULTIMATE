"""Compatibility coverage for the single legacy-state importer."""
from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from hydra.core import state as state_module
from hydra.core.state_format import unpack_state_document
from hydra.core.state_migrations import import_legacy_state
from hydra.core.state_models import UnsupportedStateVersion


def _runtime_payload(legacy: dict) -> dict:
    return unpack_state_document(import_legacy_state(legacy))


def test_importer_moves_legacy_creator_directly_to_its_current_namespace() -> None:
    source = {
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
    original = copy.deepcopy(source)

    imported = _runtime_payload(source)

    assert source == original
    assert imported["format_version"] == 1
    assert imported["protocols"]["wdtt"]["config"] == {
        "main_password": "kept",
        "dtls_port": 56000,
        "wg_port": 56001,
    }
    assert imported["headless_creator"]["consumers"]["qwdtt"] == {
        "provider": "vk",
        "pool_enabled": True,
        "refresh_interval_seconds": 7200,
        "legacy_creator_reinstall_required": True,
        "room_count": 4,
    }
    assert imported["install"]["sync_headless_creator_vk_qwdtt_enabled"] is False
    assert "calls" not in imported["protocols"]


@pytest.mark.parametrize("legacy_version", range(11, 19))
def test_debug_calls_schemas_import_directly_without_wire_transitions(
    legacy_version: int,
) -> None:
    imported = _runtime_payload({
        "version": legacy_version,
        "kernel": {"provider": "hydracore", "channel": "debug"},
        "protocols": {
            "calls": {
                "installed": True,
                "enabled": True,
                "config": {
                    "mode": "vk_parasite",
                    "workers": 12,
                    "room_count": 4,
                    "max_workers_per_session": 16,
                    "multipath_profile": "legacy",
                    "read_buffer": 65536,
                    "custom": "preserved",
                },
            },
        },
    })

    calls = imported["protocols"]["calls"]
    assert calls["installed"] is True
    assert calls["enabled"] is True
    assert calls["config"] == {
        "mode": "vk_parasite",
        "workers": 12,
        "custom": "preserved",
    }


def test_importer_disables_only_semantically_incompatible_calls() -> None:
    imported = _runtime_payload({
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
    })

    assert imported["protocols"]["calls"] == {
        "installed": True,
        "enabled": False,
        "config": {"mode": "vk_parasite", "workers": 4},
    }
    assert imported["protocols"]["vless"]["enabled"] is True


def test_v10_calls_fixture_is_atomically_imported_and_idempotent(
    tmp_path,
    monkeypatch,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "state-schema-10-calls-p2p.json"
    state_file = tmp_path / "state.json"
    shutil.copy2(fixture, state_file)
    monkeypatch.setattr(state_module, "STATE_DIR", tmp_path)
    monkeypatch.setattr(state_module, "STATE_FILE", state_file)

    first = state_module.migrate_persisted_state()
    imported_bytes = state_file.read_bytes()
    second = state_module.migrate_persisted_state()
    loaded = state_module.load_state()

    assert first == {"from": 10, "to": 1, "changed": True}
    assert second == {"from": 1, "to": 1, "changed": False}
    assert state_file.read_bytes() == imported_bytes
    assert loaded.revision == 42
    assert loaded.protocols["calls"].installed is True
    assert loaded.protocols["calls"].enabled is False
    assert loaded.protocols["calls"].config == {
        "mode": "vk_parasite",
        "workers": 4,
    }
    assert loaded.protocols["vless"].enabled is True
    assert loaded.install["preserved_upgrade_marker"] == "keep"
    assert state_file.with_suffix(".json.bak").is_file()


def test_future_legacy_schema_is_rejected() -> None:
    with pytest.raises(UnsupportedStateVersion):
        import_legacy_state({"version": 19})


def test_imported_state_has_no_host_runtime_or_secret_artifacts() -> None:
    payload = json.dumps(import_legacy_state({
        "version": 6,
        "protocols": {"wdtt": {"config": {"headless_enabled": True}}},
    }))
    assert "cookies-vk" not in payload
    assert "vk.com/call/join" not in payload
