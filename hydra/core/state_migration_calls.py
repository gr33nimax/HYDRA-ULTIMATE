"""Pure schema step that transfers VK creator ownership to Calls."""
from __future__ import annotations

import copy


def migrate_v6_to_v7(data: dict) -> dict:
    """Move VK creator desired state without touching host runtime."""
    migrated = copy.deepcopy(data)
    protocols = migrated.setdefault("protocols", {})
    wdtt = protocols.get("wdtt")
    wdtt_config = wdtt.setdefault("config", {}) if isinstance(wdtt, dict) else {}
    calls = protocols.setdefault("calls", {})
    calls.setdefault("enabled", False)
    calls.setdefault("installed", False)
    calls.setdefault("port", 0)
    calls_config = calls.setdefault("config", {})

    configured = bool(wdtt_config.pop("headless_enabled", False))
    calls_config.setdefault("qwdtt_pool_enabled", configured)
    interval = wdtt_config.pop("headless_refresh_interval_seconds", None)
    if configured:
        calls_config.setdefault("legacy_creator_reinstall_required", True)
    if interval is not None:
        calls_config.setdefault("qwdtt_refresh_interval_seconds", interval)

    install = migrated.setdefault("install", {})
    old_flag = install.pop("sync_wdtt_headless_enabled", None)
    if old_flag is not None:
        install.setdefault("sync_calls_qwdtt_pool_enabled", bool(old_flag))

    migrated["version"] = 7
    return migrated


__all__ = ["migrate_v6_to_v7"]
