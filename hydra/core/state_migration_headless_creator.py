"""Pure schema step that extracts headless creator state from Calls."""
from __future__ import annotations

import copy


def migrate_v7_to_v8(data: dict) -> dict:
    """Move provider runtime ownership without touching the host."""
    migrated = copy.deepcopy(data)
    if migrated.get("version", 0) >= 8:
        return migrated

    calls = migrated.setdefault("protocols", {}).get("calls", {})
    calls_config = calls.setdefault("config", {}) if isinstance(calls, dict) else {}
    creator = migrated.setdefault("headless_creator", {})
    providers = creator.setdefault("providers", {})
    vk = providers.setdefault("vk", {})

    pool_enabled = calls_config.pop("qwdtt_pool_enabled", False)
    vk.setdefault("qwdtt_pool_enabled", bool(pool_enabled))
    interval = calls_config.pop("qwdtt_refresh_interval_seconds", None)
    if interval is not None:
        vk.setdefault("qwdtt_refresh_interval_seconds", interval)
    reinstall = calls_config.pop("legacy_creator_reinstall_required", False)
    if pool_enabled or reinstall:
        vk.setdefault("legacy_creator_reinstall_required", True)

    install = migrated.setdefault("install", {})
    old_flag = install.pop("sync_calls_qwdtt_pool_enabled", None)
    if old_flag is not None:
        install.setdefault("sync_headless_creator_vk_qwdtt_enabled", bool(old_flag))

    migrated["version"] = 8
    return migrated


__all__ = ["migrate_v7_to_v8"]
