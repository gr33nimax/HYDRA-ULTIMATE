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


def migrate_v13_to_v14(data: dict) -> dict:
    """Quiesce wire v5 and select the canonical four-lane wire-v6 contract."""
    migrated = copy.deepcopy(data)
    protocols = migrated.get("protocols", {})
    calls = protocols.get("calls", {}) if isinstance(protocols, dict) else {}
    if isinstance(calls, dict):
        calls["enabled"] = False
        config = calls.setdefault("config", {})
        if isinstance(config, dict):
            config["mode"] = "vk_parasite"
            config["workers"] = 4
            config["max_workers_per_session"] = 4
            config.pop("multipath_profile", None)
            config.pop("read_buffer", None)
    migrated["version"] = 14
    return migrated


def migrate_v14_to_v15(data: dict) -> dict:
    """Quiesce wire v8 before enabling the incompatible wire-v9 contract."""
    migrated = copy.deepcopy(data)
    protocols = migrated.get("protocols", {})
    calls = protocols.get("calls", {}) if isinstance(protocols, dict) else {}
    if isinstance(calls, dict):
        calls["enabled"] = False
        config = calls.setdefault("config", {})
        if isinstance(config, dict):
            config["mode"] = "vk_parasite"
            config["workers"] = 4
            config["max_workers_per_session"] = 4
            config.pop("multipath_profile", None)
            config.pop("read_buffer", None)
    migrated["version"] = 15
    return migrated


def migrate_v15_to_v16(data: dict) -> dict:
    """Migrate server max_workers_per_session to 16 and strip client workers topology."""
    migrated = copy.deepcopy(data)
    protocols = migrated.get("protocols", {})
    calls = protocols.get("calls", {}) if isinstance(protocols, dict) else {}
    if isinstance(calls, dict):
        config = calls.setdefault("config", {})
        if isinstance(config, dict):
            if config.get("mode") == "vk_parasite":
                if config.get("max_workers_per_session") == 4:
                    config["max_workers_per_session"] = 16
                if config.get("workers") == 4:
                    config.pop("workers")
    migrated["version"] = 16
    return migrated


def migrate_v16_to_v17(data: dict) -> dict:
    """Fix native Calls at four rooms and sixteen workers."""
    migrated = copy.deepcopy(data)
    protocols = migrated.get("protocols", {})
    calls = protocols.get("calls", {}) if isinstance(protocols, dict) else {}
    if isinstance(calls, dict):
        config = calls.setdefault("config", {})
        if isinstance(config, dict) and config.get("mode") == "vk_parasite":
            config.pop("room_count", None)
            config["max_workers_per_session"] = 16
    migrated["version"] = 17
    return migrated


def migrate_v17_to_v18(data: dict) -> dict:
    """Move the Calls worker setting to its single client/server source."""
    migrated = copy.deepcopy(data)
    protocols = migrated.get("protocols", {})
    calls = protocols.get("calls", {}) if isinstance(protocols, dict) else {}
    if isinstance(calls, dict):
        config = calls.setdefault("config", {})
        if isinstance(config, dict) and config.get("mode") == "vk_parasite":
            workers = config.get("workers", 4)
            config["workers"] = workers if workers in (4, 8, 12, 16, 20) else 4
            config.pop("room_count", None)
            config.pop("max_workers_per_session", None)
    migrated["version"] = 18
    return migrated


__all__ = [
    "migrate_v10_to_v11",
    "migrate_v11_to_v12",
    "migrate_v12_to_v13",
    "migrate_v13_to_v14",
    "migrate_v14_to_v15",
    "migrate_v15_to_v16",
    "migrate_v16_to_v17",
    "migrate_v17_to_v18",
]
