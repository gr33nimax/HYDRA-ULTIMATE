"""One-time importer from historical state schemas to State Format v1."""
from __future__ import annotations

import copy

from hydra.core.state_creator_models import DEFAULT_QWDTT_ROOM_COUNT
from hydra.core.state_format import STATE_FORMAT_VERSION, pack_state_document
from hydra.core.state_kernel_models import KERNEL_HYDRACORE
from hydra.core.state_validation import (
    LEGACY_SCHEMA_VERSION,
    validate_raw_state,
    validate_supported_version,
)


_CALLS_WORKERS = (4, 8, 12, 16, 20)


def _normalize_users(raw: dict) -> None:
    for user in raw.setdefault("users", []):
        user.setdefault("credentials", {})
        user.setdefault("device_limit", 0)
        devices = user.setdefault("devices", {})
        if not isinstance(devices, dict):
            user["devices"] = {}
        else:
            user["devices"] = {
                device_id: dict(record) if isinstance(record, dict) else {
                    "first_seen": str(record),
                    "last_seen": str(record),
                    "source": "",
                    "user_agent": "",
                    "address": "",
                }
                for device_id, record in devices.items()
            }
        user.setdefault("hydrabox_jwe_key", "")


def _normalize_plugin_flags(raw: dict) -> None:
    protocols = raw.setdefault("protocols", {})
    network = raw.setdefault("network", {})
    security = raw.pop("security", {})
    flags = {
        "warp": network.pop("warp_enabled", False),
        "dnscrypt": network.pop("dnscrypt_enabled", False),
        "fail2ban": security.get("fail2ban_enabled", False),
        "honeypot": security.get("honeypot_enabled", False),
        "ipban": security.get("ipban_enabled", False),
        "antidpi": security.get("antidpi_enabled", False),
    }
    for name, enabled in flags.items():
        if enabled or name in protocols:
            plugin = protocols.setdefault(name, {})
            plugin["enabled"] = bool(plugin.get("enabled") or enabled)


def _normalize_creator(raw: dict) -> None:
    protocols = raw["protocols"]
    install = raw.setdefault("install", {})
    creator = raw.setdefault("headless_creator", {})
    providers = creator.setdefault("providers", {})
    consumers = creator.setdefault("consumers", {})
    qwdtt = consumers.get("qwdtt")
    sources: list[dict] = []

    wdtt = protocols.get("wdtt")
    wdtt_config = wdtt.setdefault("config", {}) if isinstance(wdtt, dict) else {}
    if "headless_enabled" in wdtt_config or "headless_refresh_interval_seconds" in wdtt_config:
        pool_enabled = bool(wdtt_config.pop("headless_enabled", False))
        sources.append({
            "pool_enabled": pool_enabled,
            "refresh_interval_seconds": wdtt_config.pop(
                "headless_refresh_interval_seconds", 86_400
            ),
            "legacy_creator_reinstall_required": pool_enabled,
        })

    calls = protocols.get("calls")
    calls_config = calls.setdefault("config", {}) if isinstance(calls, dict) else {}
    if any(key in calls_config for key in (
        "qwdtt_pool_enabled", "qwdtt_refresh_interval_seconds",
        "legacy_creator_reinstall_required",
    )):
        sources.append({
            "pool_enabled": bool(calls_config.pop("qwdtt_pool_enabled", False)),
            "refresh_interval_seconds": calls_config.pop(
                "qwdtt_refresh_interval_seconds", 86_400
            ),
            "legacy_creator_reinstall_required": bool(calls_config.pop(
                "legacy_creator_reinstall_required", False
            )),
        })

    vk = providers.get("vk")
    if isinstance(vk, dict) and any(key in vk for key in (
        "qwdtt_pool_enabled", "qwdtt_refresh_interval_seconds",
        "legacy_creator_reinstall_required",
    )):
        sources.append({
            "pool_enabled": bool(vk.pop("qwdtt_pool_enabled", False)),
            "refresh_interval_seconds": vk.pop(
                "qwdtt_refresh_interval_seconds", 86_400
            ),
            "legacy_creator_reinstall_required": bool(vk.pop(
                "legacy_creator_reinstall_required", False
            )),
        })
        if not vk:
            providers.pop("vk", None)

    if sources:
        qwdtt = consumers.setdefault("qwdtt", {})
        for source in sources:
            for key, value in source.items():
                qwdtt.setdefault(key, value)
    if isinstance(qwdtt, dict):
        qwdtt.setdefault("provider", "vk")
        qwdtt.setdefault("room_count", DEFAULT_QWDTT_ROOM_COUNT)

    for old in ("sync_wdtt_headless_enabled", "sync_calls_qwdtt_pool_enabled"):
        value = install.pop(old, None)
        if value is not None:
            install.setdefault("sync_headless_creator_vk_qwdtt_enabled", bool(value))


def _normalize_calls(raw: dict) -> None:
    calls = raw["protocols"].get("calls")
    if not isinstance(calls, dict):
        return
    config = calls.setdefault("config", {})
    if not isinstance(config, dict):
        return
    old_mode = config.get("mode", "p2p")
    if old_mode != "vk_parasite" or raw["kernel"]["provider"] != KERNEL_HYDRACORE:
        calls["enabled"] = False
    config["mode"] = "vk_parasite"
    workers = config.get("workers", 4)
    config["workers"] = workers if workers in _CALLS_WORKERS else 4
    for key in ("room_count", "max_workers_per_session", "multipath_profile", "read_buffer"):
        config.pop(key, None)


def import_legacy_state(data: dict) -> dict:
    """Convert any supported legacy schema directly to State Format v1."""
    validate_raw_state(data)
    validate_supported_version(data)
    raw = copy.deepcopy(data)
    raw.pop("version", None)
    raw.setdefault("revision", 0)
    raw.setdefault("install", {})
    raw.setdefault("telegram", {})
    raw.setdefault("network", {})
    _normalize_users(raw)
    _normalize_plugin_flags(raw)
    _normalize_creator(raw)
    kernel = raw.setdefault("kernel", {})
    kernel.setdefault("provider", "sing-box-extended")
    kernel.setdefault("channel", "stable")
    wdtt = raw["protocols"].get("wdtt")
    if isinstance(wdtt, dict):
        config = wdtt.setdefault("config", {})
        if isinstance(config, dict):
            config.setdefault("dtls_port", 56000)
            config.setdefault("wg_port", 56001)
    _normalize_calls(raw)

    return pack_state_document({
        "format_version": STATE_FORMAT_VERSION,
        "revision": raw.pop("revision"),
        "core_extensions": {},
        "feature_extensions": {},
        **raw,
    })


__all__ = ["LEGACY_SCHEMA_VERSION", "import_legacy_state"]
