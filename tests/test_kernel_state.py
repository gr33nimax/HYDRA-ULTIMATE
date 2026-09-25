from __future__ import annotations

import pytest

from hydra.core.state_kernel_models import (
    DEFAULT_KERNEL_CHANNEL,
    KERNEL_HYDRACORE,
    OFFERED_KERNEL_CHANNELS,
    KernelConfig,
    resolve_kernel_channel,
    validate_kernel_config,
    validate_raw_kernel_config,
)
from hydra.core.state_format import unpack_state_document
from hydra.core.state_migrations import import_legacy_state, normalize_state_document
from hydra.core.state_models import AppState, PluginState, validate_state


def test_legacy_importer_moves_stock_core_to_hydracore_stable() -> None:
    original = {
        "version": 9,
        "protocols": {
            "calls": {"config": {"read_buffer": 32768}},
            "wdtt": {"enabled": True, "config": {}},
        },
    }

    migrated = unpack_state_document(import_legacy_state(original))

    assert migrated["format_version"] == 1
    assert migrated["kernel"] == {
        "provider": "hydracore",
        "channel": "stable",
    }
    assert migrated["protocols"]["calls"]["enabled"] is False
    assert migrated["protocols"]["calls"]["config"] == {
        "mode": "vk_parasite",
        "workers": 4,
    }
    assert migrated["protocols"]["wdtt"]["config"] == {
        "dtls_port": 56000,
        "wg_port": 56001,
    }
    assert "kernel" not in original


def test_legacy_importer_preserves_explicit_kernel_selection() -> None:
    migrated = unpack_state_document(import_legacy_state({
        "version": 9,
        "kernel": {"provider": "hydracore", "channel": "preview"},
    }))
    assert migrated["kernel"] == {"provider": "hydracore", "channel": "preview"}


def test_current_document_normalizes_removed_kernel_without_mutating_source() -> None:
    source = {
        "format_version": 1,
        "revision": 7,
        "core": {},
        "features": {
            "kernel": {"provider": "sing-box-extended", "channel": "stable"},
        },
    }

    migrated = unpack_state_document(normalize_state_document(source))

    assert source["features"]["kernel"] == {
        "provider": "sing-box-extended",
        "channel": "stable",
    }
    assert migrated["kernel"] == {"provider": "hydracore", "channel": "stable"}


def test_kernel_selection_rejects_unknown_provider_or_channel() -> None:
    with pytest.raises(ValueError, match="provider"):
        validate_kernel_config(KernelConfig(provider="unknown"))
    with pytest.raises(ValueError, match="channel"):
        validate_kernel_config(KernelConfig(channel="nightly"))
    with pytest.raises(ValueError, match="must be an object"):
        validate_raw_kernel_config("hydracore")
    with pytest.raises(ValueError, match="provider"):
        validate_raw_kernel_config({"provider": "unknown"})


def test_only_hydracore_is_a_supported_kernel() -> None:
    validate_kernel_config(KernelConfig(provider="hydracore", channel="debug"))

    with pytest.raises(ValueError, match="provider"):
        validate_kernel_config(KernelConfig(
            provider="sing-box-extended",
            channel="debug",
        ))


def test_offered_kernel_channels_are_stable_and_debug() -> None:
    assert OFFERED_KERNEL_CHANNELS == ("stable", "debug")
    assert KernelConfig().channel == DEFAULT_KERNEL_CHANNEL


def test_retired_preview_channel_still_resolves() -> None:
    # `preview` is no longer offered, but a state that persisted it keeps a
    # valid channel instead of failing validation.
    validate_kernel_config(KernelConfig(channel="preview"))

    assert resolve_kernel_channel("preview") == "debug"
    assert resolve_kernel_channel("stable") == "stable"
    assert resolve_kernel_channel("debug") == "debug"
    assert KERNEL_HYDRACORE == KernelConfig().provider


def test_current_state_rejects_legacy_calls_mode() -> None:
    state = AppState(protocols={
        "calls": PluginState(config={"mode": "p2p"}),
    })

    with pytest.raises(ValueError, match="must be vk_parasite"):
        validate_state(state)


def test_current_state_accepts_enabled_calls_on_hydracore() -> None:
    state = AppState(protocols={
        "calls": PluginState(
            installed=True,
            enabled=True,
            config={"mode": "vk_parasite"},
        ),
    })

    validate_state(state)
