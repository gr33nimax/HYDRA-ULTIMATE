"""Hydra subscription grants and durable WDTT access-state projection."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any

from hydra.core.hydrabox_keys import decode_hydrabox_jwe_key
from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.wdtt import observation
from hydra.plugins.wdtt.model import WdttEnvironment


DEFAULT_WORKERS = 18
MINIMUM_WORKERS = 9
MAXIMUM_WORKERS = 36
DEFAULT_LEGACY_SCAN_LIMIT = 16
_DEVICE_ID = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_VK_HASH = re.compile(r"^[A-Za-z0-9._~:-]{1,256}$")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _device_grant(user: User, device_id: str) -> tuple[str, str]:
    if not _DEVICE_ID.fullmatch(device_id):
        raise ValueError("invalid HydraBox WDTT device id")
    if not _IDENTIFIER.fullmatch(user.uuid) or len(user.uuid) > 128:
        raise ValueError("invalid HydraBox WDTT user id")
    key = decode_hydrabox_jwe_key(user.hydrabox_jwe_key)
    credential_ref = f"wdtt:{user.uuid}:{device_id}"
    message = (
        "HYDRA-WDTT-DEVICE-GRANT-v1\0"
        f"{user.uuid}\0{device_id}"
    ).encode("utf-8")
    grant = "hwdtt1_" + _b64url(hmac.new(key, message, hashlib.sha256).digest())
    return credential_ref, grant


def _wrap_key(secret: str) -> bytes:
    salt = b"WDTT-WRAP-v1"
    info = b"rtp-obfs/chacha20poly1305"
    extracted = hmac.new(salt, secret.encode("utf-8"), hashlib.sha256).digest()
    return hmac.new(extracted, info + b"\x01", hashlib.sha256).digest()


def _key_hint(secret: str) -> str:
    value = b"HYDRA-WDTT-WRAP-HINT-v1\x00" + secret.encode("utf-8")
    return hashlib.sha256(value).digest()[:8].hex()


def _expiry_epoch(value: str) -> int:
    source = str(value or "").strip()
    if not source:
        return 0
    if "T" not in source:
        source += "T23:59:59Z"
    if source.endswith("Z"):
        source = source[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(source)
    except ValueError as exc:
        raise ValueError("invalid WDTT subscription expiry") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _worker_policy(state: PluginStateAccess) -> tuple[int, int, int]:
    protocol = state.protocols.get("wdtt")
    config = protocol.config if protocol else {}
    workers = config.get("subscription_workers", DEFAULT_WORKERS)
    if (
        type(workers) is not int
        or workers < MINIMUM_WORKERS
        or workers > MAXIMUM_WORKERS
        or workers % MINIMUM_WORKERS
    ):
        raise ValueError("WDTT subscription workers must be 9..36 in groups of 9")
    burst = workers + MINIMUM_WORKERS
    legacy_limit = config.get("legacy_scan_limit", DEFAULT_LEGACY_SCAN_LIMIT)
    if type(legacy_limit) is not int or not 1 <= legacy_limit <= 64:
        raise ValueError("WDTT legacy scan limit must be between 1 and 64")
    return workers, burst, legacy_limit


def _credential(user: User, device_id: str, workers: int, burst: int) -> dict:
    credential_ref, grant = _device_grant(user, device_id)
    return {
        "credential_ref": credential_ref,
        "subject": user.uuid,
        "device_id": device_id,
        "token_sha256": hashlib.sha256(grant.encode("utf-8")).hexdigest(),
        "wrap_key": _b64url(_wrap_key(grant)),
        "key_hint": _key_hint(grant),
        "expires_at": _expiry_epoch(user.expiry_date),
        "revoked": bool(user.blocked),
        "max_workers": workers,
        "max_burst_workers": burst,
    }


def build_access_state(state: PluginStateAccess) -> dict[str, Any]:
    """Build the complete verifier-only file consumed by hydra-wdtt."""
    workers, burst, legacy_limit = _worker_policy(state)
    credentials = [
        _credential(user, device_id, workers, burst)
        for user in sorted(state.users, key=lambda item: item.uuid)
        for device_id in sorted(user.devices)
        if _DEVICE_ID.fullmatch(device_id)
    ]
    protocol = state.protocols.get("wdtt")
    config = protocol.config if protocol else {}
    configured_total = config.get("subscription_max_total_workers", 0)
    if type(configured_total) is not int or configured_total < 0:
        raise ValueError("WDTT global worker limit must be a non-negative integer")
    automatic_total = max(burst, len(credentials) * burst)
    if configured_total and configured_total < burst:
        raise ValueError("WDTT global worker limit is below one device burst")
    return {
        "version": 1,
        "max_total_workers": configured_total or automatic_total,
        "legacy_scan_limit": legacy_limit,
        "credentials": credentials,
    }


def _call_hashes(env: WdttEnvironment) -> list[str]:
    try:
        metadata = env.json_module.loads(
            env.headless_state_file.read_text(encoding="utf-8"),
        )
    except (OSError, TypeError, ValueError, env.json_module.JSONDecodeError) as exc:
        raise ValueError("WDTT VK call state is unavailable") from exc
    hashes = metadata.get("hashes", []) if isinstance(metadata, dict) else []
    if (
        not isinstance(hashes, list)
        or len(hashes) != env.headless_call_count
        or len(hashes) != len(set(hashes))
        or any(not isinstance(value, str) or not _VK_HASH.fullmatch(value) for value in hashes)
    ):
        raise ValueError("WDTT requires four unique VK call hashes")
    return hashes


def _endpoint(
    env: WdttEnvironment,
    state: PluginStateAccess,
    credential_ref: str,
) -> dict[str, Any]:
    protocol = state.protocols.get("wdtt")
    config = protocol.config if protocol else {}
    server = str(state.network.server_ip or observation.public_server_ip(env)).strip()
    if (
        not server
        or len(server) > 253
        or any(character.isspace() or ord(character) < 32 for character in server)
        or any(character in server for character in "/?#@")
    ):
        raise ValueError("WDTT public server address is invalid")
    port = config.get("dtls_port", env.default_dtls_port)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("WDTT DTLS port is invalid")
    workers, _burst, _legacy_limit = _worker_policy(state)
    tag = "wdtt-" + hashlib.sha256(credential_ref.encode()).hexdigest()[:16]
    return {
        "type": "wdtt",
        "tag": tag,
        "server": server,
        "server_port": port,
        "credential_ref": credential_ref,
        "vk_hashes": _call_hashes(env),
        "workers": workers,
        "obfs": str(config.get("subscription_obfs", "audio")),
        "vk_auth": "auto",
        "vk_anon_path": "vkcalls",
    }


def _replace_access_state(env: WdttEnvironment, state: dict[str, Any]) -> None:
    previous = None
    if env.access_file.exists():
        previous = env.access_file.read_bytes()
    content = env.json_module.dumps(
        state,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ) + "\n"
    env.host.atomic_write(env.access_file, content, mode=0o600)
    if observation.hot_reload(env):
        return
    if previous is None:
        env.host.remove_file(env.access_file)
    else:
        env.host.atomic_write(env.access_file, previous, mode=0o600)
        observation.hot_reload(env)
    raise RuntimeError("WDTT server did not accept the subscription access update")


def activate_subscription(
    env: WdttEnvironment,
    *,
    user: User,
    state: PluginStateAccess,
    device_id: str,
) -> dict[str, Any]:
    """Activate one device grant and return JWE-only client material."""
    protocol = state.protocols.get("wdtt")
    if protocol is None or not protocol.enabled:
        raise ValueError("WDTT is not enabled")
    current = next((item for item in state.users if item.uuid == user.uuid), None)
    if current is None or current.blocked or device_id not in current.devices:
        raise ValueError("WDTT subscription device is not active")
    credential_ref, grant = _device_grant(current, device_id)
    access_state = build_access_state(state)
    _replace_access_state(env, access_state)
    return {
        "projection": {"endpoints": [_endpoint(env, state, credential_ref)]},
        "credentials": [{
            "kind": "wdtt_device_grant",
            "credential_ref": credential_ref,
            "device_id": device_id,
            "device_grant": grant,
        }],
    }


def access_snapshot(env: WdttEnvironment) -> bytes | None:
    return env.access_file.read_bytes() if env.access_file.exists() else None


def restore_access_snapshot(env: WdttEnvironment, snapshot: bytes | None) -> bool:
    if snapshot is None:
        env.host.remove_file(env.access_file)
    else:
        env.host.atomic_write(env.access_file, snapshot, mode=0o600)
    if observation.hot_reload(env):
        return True
    running = env.host.run(
        ["pidof", "wdtt-server"],
        capture_output=True,
        text=True,
    )
    return not running.stdout.split()


__all__ = [
    "DEFAULT_WORKERS",
    "MINIMUM_WORKERS",
    "MAXIMUM_WORKERS",
    "access_snapshot",
    "activate_subscription",
    "build_access_state",
    "restore_access_snapshot",
]
