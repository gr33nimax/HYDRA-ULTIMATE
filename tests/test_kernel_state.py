from __future__ import annotations

import pytest

from hydra.core.state_kernel_models import (
    KernelConfig,
    validate_kernel_config,
    validate_raw_kernel_config,
)
from hydra.core.state_migration_kernel import migrate_v9_to_v10
from hydra.core.state_models import AppState, PluginState, validate_state


def test_v9_to_v10_preserves_stock_core_and_legacy_calls() -> None:
    original = {
        "version": 9,
        "protocols": {
            "calls": {"config": {"read_buffer": 32768}},
            "wdtt": {"enabled": True, "config": {}},
        },
    }

    migrated = migrate_v9_to_v10(original)

    assert migrated["version"] == 10
    assert migrated["kernel"] == {
        "provider": "sing-box-extended",
        "channel": "stable",
    }
    assert migrated["protocols"]["calls"]["config"]["mode"] == "p2p"
    assert migrated["protocols"]["wdtt"]["config"] == {
        "dtls_port": 56000,
        "wg_port": 56001,
    }
    assert "kernel" not in original


def test_v9_to_v10_is_idempotent_for_explicit_selection() -> None:
    migrated = migrate_v9_to_v10({
        "version": 9,
        "kernel": {"provider": "hydracore", "channel": "preview"},
    })
    assert migrate_v9_to_v10(migrated) == migrated


def test_kernel_selection_rejects_unknown_provider_or_channel() -> None:
    with pytest.raises(ValueError, match="provider"):
        validate_kernel_config(KernelConfig(provider="unknown"))
    with pytest.raises(ValueError, match="channel"):
        validate_kernel_config(KernelConfig(channel="nightly"))
    with pytest.raises(ValueError, match="must be an object"):
        validate_raw_kernel_config("hydracore")
    with pytest.raises(ValueError, match="provider"):
        validate_raw_kernel_config({"provider": "unknown"})


def test_debug_channel_is_reserved_for_hydracore() -> None:
    validate_kernel_config(KernelConfig(provider="hydracore", channel="debug"))

    with pytest.raises(ValueError, match="only for hydracore"):
        validate_kernel_config(KernelConfig(
            provider="sing-box-extended",
            channel="debug",
        ))


def test_current_state_rejects_legacy_calls_mode() -> None:
    state = AppState(protocols={
        "calls": PluginState(config={"mode": "p2p"}),
    })

    with pytest.raises(ValueError, match="must be vk_parasite"):
        validate_state(state)


def test_current_state_rejects_enabled_calls_on_stock_core() -> None:
    state = AppState(protocols={
        "calls": PluginState(
            installed=True,
            enabled=True,
            config={"mode": "vk_parasite"},
        ),
    })

    with pytest.raises(ValueError, match="requires the Hydracore kernel"):
        validate_state(state)
