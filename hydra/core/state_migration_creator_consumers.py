"""Pure migration separating creator providers from their consumers."""
from __future__ import annotations

import copy

from hydra.core.state_creator_models import DEFAULT_QWDTT_ROOM_COUNT


def migrate_v8_to_v9(data: dict) -> dict:
    """Move qWDTT desired state out of the VK provider configuration."""
    migrated = copy.deepcopy(data)
    if migrated.get("version", 0) >= 9:
        return migrated

    creator = migrated.setdefault("headless_creator", {})
    providers = creator.setdefault("providers", {})
    consumers = creator.setdefault("consumers", {})
    vk = providers.get("vk", {})
    qwdtt = consumers.setdefault("qwdtt", {})
    if isinstance(vk, dict):
        moved = {
            "qwdtt_pool_enabled": "pool_enabled",
            "qwdtt_refresh_interval_seconds": "refresh_interval_seconds",
            "legacy_creator_reinstall_required": "legacy_creator_reinstall_required",
        }
        for old_key, new_key in moved.items():
            if old_key in vk:
                qwdtt.setdefault(new_key, vk.pop(old_key))
        if not vk:
            providers.pop("vk", None)
    qwdtt.setdefault("provider", "vk")
    qwdtt.setdefault("room_count", DEFAULT_QWDTT_ROOM_COUNT)
    migrated["version"] = 9
    return migrated


__all__ = ["migrate_v8_to_v9"]
