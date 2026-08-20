"""Ordered pure migrations for persisted HYDRA state."""
from __future__ import annotations
import copy
from collections.abc import Callable, Mapping

from hydra.core import state_migration_calls_vk_parasite as calls_vk
from hydra.core.state_migration_calls import migrate_v6_to_v7
from hydra.core.state_migration_creator_consumers import migrate_v8_to_v9
from hydra.core.state_migration_headless_creator import migrate_v7_to_v8
from hydra.core.state_migration_hydrabox import migrate_v5_to_v6
from hydra.core.state_migration_kernel import migrate_v9_to_v10
from hydra.core.state_models import SCHEMA_VERSION, validate_raw_state
Migration = Callable[[dict], dict]
migrate_v10_to_v11 = calls_vk.migrate_v10_to_v11
migrate_v11_to_v12 = calls_vk.migrate_v11_to_v12
migrate_v12_to_v13 = calls_vk.migrate_v12_to_v13
migrate_v13_to_v14 = calls_vk.migrate_v13_to_v14
migrate_v14_to_v15 = calls_vk.migrate_v14_to_v15
migrate_v15_to_v16 = calls_vk.migrate_v15_to_v16
def migrate_v0_to_v1(data: dict) -> dict:
    data["version"] = 1
    data.setdefault("install", {})
    data.setdefault("protocols", {})
    data.setdefault("telegram", {})
    data.setdefault("network", {})
    data.setdefault("security", {})
    return data


def migrate_v1_to_v2(data: dict) -> dict:
    for user in data.get("users", []):
        user.setdefault("credentials", {})
    network = data.setdefault("network", {})
    network.setdefault("tproxy_enabled", False)
    network.setdefault("tproxy_port", 1081)
    data["version"] = 2
    return data


def migrate_v2_to_v3(data: dict) -> dict:
    """Add the device-binding fields released with persisted schema 3."""
    for user in data.get("users", []):
        user.setdefault("device_limit", 0)
        user.setdefault("devices", {})
    data["version"] = 3
    return data


def migrate_v3_to_v4(data: dict) -> dict:
    """Canonicalize plugin flags and add optimistic concurrency metadata."""
    protocols = data.setdefault("protocols", {})
    network = data.setdefault("network", {})
    security = data.pop("security", {})

    legacy_flags = {
        "warp": network.pop("warp_enabled", False),
        "dnscrypt": network.pop("dnscrypt_enabled", False),
        "fail2ban": security.get("fail2ban_enabled", False),
        "honeypot": security.get("honeypot_enabled", False),
        "ipban": security.get("ipban_enabled", False),
        "antidpi": security.get("antidpi_enabled", False),
    }
    for name, legacy_enabled in legacy_flags.items():
        current = protocols.get(name)
        if current is None:
            if not legacy_enabled:
                continue
            current = {}
            protocols[name] = current
        current["enabled"] = bool(current.get("enabled") or legacy_enabled)

    data.setdefault("revision", 0)
    data["version"] = 4
    return data


def migrate_v4_to_v5(data: dict) -> dict:
    """Turn device bindings into records describing what connected."""
    for user in data.get("users", []):
        devices = user.get("devices", {})
        if not isinstance(devices, dict):
            user["devices"] = {}
            continue
        user["devices"] = {
            device_id: (
                dict(record)
                if isinstance(record, dict)
                else {
                    "first_seen": str(record),
                    "last_seen": str(record),
                    "source": "",
                    "user_agent": "",
                    "address": "",
                }
            )
            for device_id, record in devices.items()
        }
    data["version"] = 5
    return data


MIGRATIONS: dict[int, Migration] = {
    0: migrate_v0_to_v1, 1: migrate_v1_to_v2,
    2: migrate_v2_to_v3, 3: migrate_v3_to_v4,
    4: migrate_v4_to_v5,
    5: migrate_v5_to_v6,
    6: migrate_v6_to_v7,
    7: migrate_v7_to_v8,
    8: migrate_v8_to_v9,
    9: migrate_v9_to_v10,
    10: calls_vk.migrate_v10_to_v11,
    11: calls_vk.migrate_v11_to_v12,
    12: calls_vk.migrate_v12_to_v13,
    13: calls_vk.migrate_v13_to_v14,
    14: calls_vk.migrate_v14_to_v15,
    15: calls_vk.migrate_v15_to_v16,
}


def migrate_state(
    data: dict,
    from_version: int,
    *,
    migrations: Mapping[int, Migration] = MIGRATIONS,
) -> dict:
    """Run every schema migration exactly once without mutating the source."""
    migrated = copy.deepcopy(data)
    version = from_version
    while version < SCHEMA_VERSION:
        migration = migrations.get(version)
        if migration is None:
            raise RuntimeError(f"missing state migration {version} -> {version + 1}")
        migrated = migration(migrated)
        expected = version + 1
        if migrated.get("version") != expected:
            raise RuntimeError(
                f"state migration {version} did not produce schema {expected}"
            )
        validate_raw_state(migrated)
        version = expected
    return migrated
