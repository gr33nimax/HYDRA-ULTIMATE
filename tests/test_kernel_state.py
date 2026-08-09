from __future__ import annotations

import pytest

from hydra.core.state_kernel_models import (
    KernelConfig,
    validate_kernel_config,
    validate_raw_kernel_config,
)
from hydra.core.state_migration_kernel import migrate_v9_to_v10


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
