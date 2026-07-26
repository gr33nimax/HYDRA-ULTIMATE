"""Device fingerprinting and atomic subscription binding enforcement."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timezone

from hydra.core.state import update_state
from hydra.core.state_models import AppState, User


def subscription_device_id(
    headers: Mapping[str, str],
    client_ip: str,
    params: Mapping[str, list[str]],
) -> str:
    """Return a privacy-preserving stable identifier for a subscription client."""
    raw = ""
    source = ""
    for name in (
        "X-Hydra-HWID",
        "X-HWID",
        "X-Device-ID",
        "X-Client-ID",
        "X-Installation-ID",
    ):
        raw = str(headers.get(name, "") or "").strip()
        if raw:
            source = name.lower()
            break
    if not raw:
        for name in ("hwid", "device_id"):
            values = params.get(name, [])
            raw = str(values[0] if values else "").strip()
            if raw:
                source = name
                break
    if not raw:
        raw = f"{client_ip}|{headers.get('User-Agent', '')}"
        source = "network-client"
    return hashlib.sha256(f"{source}:{raw}".encode()).hexdigest()


def register_subscription_device(
    token: str,
    device_id: str,
) -> tuple[AppState, User | None, str]:
    """Atomically register a device, rejecting new devices above the user limit."""
    now = datetime.now(timezone.utc).isoformat()

    def mutate(state: AppState) -> tuple[str, str]:
        user = next((item for item in state.users if item.uuid == token), None)
        if user is None:
            return "missing", ""
        if user.device_limit <= 0:
            return "allowed", user.email
        if device_id not in user.devices and len(user.devices) >= user.device_limit:
            return "limit", user.email
        user.devices[device_id] = now
        return "allowed", user.email

    state, (status, email) = update_state(mutate)
    user = next((item for item in state.users if item.email == email), None)
    return state, user, status
