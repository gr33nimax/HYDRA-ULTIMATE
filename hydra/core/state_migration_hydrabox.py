"""Pure schema migration for per-user HydraBox JWE keys."""
from __future__ import annotations

import copy


def migrate_v5_to_v6(data: dict) -> dict:
    """Reserve keys; the persistence adapter injects randomness atomically."""
    migrated = copy.deepcopy(data)
    for user in migrated.get("users", []):
        user.setdefault("hydrabox_jwe_key", "")
    migrated["version"] = 6
    return migrated


__all__ = ["migrate_v5_to_v6"]
