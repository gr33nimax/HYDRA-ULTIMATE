"""Pure migration making native VK Calls VK-parasite only."""
from __future__ import annotations

import copy

from hydra.core.state_kernel_models import KERNEL_HYDRACORE, KERNEL_SINGBOX_EXTENDED


def migrate_v10_to_v11(data: dict) -> dict:
    """Disable incompatible Calls state before selecting the VK-parasite mode."""
    migrated = copy.deepcopy(data)
    protocols = migrated.get("protocols", {})
    calls = protocols.get("calls", {}) if isinstance(protocols, dict) else {}
    kernel = migrated.get("kernel", {})
    provider = (
        kernel.get("provider", KERNEL_SINGBOX_EXTENDED)
        if isinstance(kernel, dict)
        else ""
    )
    if isinstance(calls, dict):
        config = calls.setdefault("config", {})
        if isinstance(config, dict):
            legacy_mode = config.get("mode", "p2p") != "vk_parasite"
            if legacy_mode or provider != KERNEL_HYDRACORE:
                calls["enabled"] = False
            config["mode"] = "vk_parasite"
            config.pop("read_buffer", None)
    migrated["version"] = 11
    return migrated


def migrate_v11_to_v12(data: dict) -> dict:
    """Select the four-lane wire-v4 Calls contract in persisted state."""
    migrated = copy.deepcopy(data)
    protocols = migrated.get("protocols", {})
    calls = protocols.get("calls", {}) if isinstance(protocols, dict) else {}
    if isinstance(calls, dict):
        config = calls.setdefault("config", {})
        if isinstance(config, dict):
            config["mode"] = "vk_parasite"
            config["workers"] = 4
            config["max_workers_per_session"] = 4
            config.pop("multipath_profile", None)
            config.pop("read_buffer", None)
    migrated["version"] = 12
    return migrated


def migrate_v12_to_v13(data: dict) -> dict:
    """Quiesce wire v4 and select the eight-lane wire-v5 Calls contract."""
    migrated = copy.deepcopy(data)
    protocols = migrated.get("protocols", {})
    calls = protocols.get("calls", {}) if isinstance(protocols, dict) else {}
    if isinstance(calls, dict):
        calls["enabled"] = False
        config = calls.setdefault("config", {})
        if isinstance(config, dict):
            config["mode"] = "vk_parasite"
            config["workers"] = 8
            config["max_workers_per_session"] = 8
            config.pop("multipath_profile", None)
            config.pop("read_buffer", None)
    migrated["version"] = 13
    return migrated


__all__ = ["migrate_v10_to_v11", "migrate_v11_to_v12", "migrate_v12_to_v13"]
