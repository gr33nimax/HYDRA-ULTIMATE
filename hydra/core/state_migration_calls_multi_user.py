"""Pure migration making native VK Calls multi-user only."""
from __future__ import annotations

import copy

from hydra.core.state_kernel_models import KERNEL_HYDRACORE, KERNEL_SINGBOX_EXTENDED


def migrate_v10_to_v11(data: dict) -> dict:
    """Disable incompatible Calls state before selecting the multi-user mode."""
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
            legacy_mode = config.get("mode", "p2p") != "multi_user"
            if legacy_mode or provider != KERNEL_HYDRACORE:
                calls["enabled"] = False
            config["mode"] = "multi_user"
            config.pop("read_buffer", None)
    migrated["version"] = 11
    return migrated


__all__ = ["migrate_v10_to_v11"]
