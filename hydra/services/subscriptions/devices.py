"""Device fingerprinting and atomic subscription binding enforcement."""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone

from hydra.core.state import update_state
from hydra.core.state_models import AppState, User


HWID_HEADERS = (
    "X-Hydra-HWID",
    "X-HWID",
    "X-Device-ID",
    "X-Client-ID",
    "X-Installation-ID",
)
HWID_PARAMS = ("hwid", "device_id")
NETWORK_SOURCE = "network-client"
_MAX_AGENT = 120
_HYDRABOX_HWID = re.compile(r"^hbx1_[A-Za-z0-9_-]{43}$")
_HYDRABOX_AGENT = re.compile(r"^HydraBox/[^\s/]+(?:\s|$)")


@dataclass(frozen=True)
class DeviceFingerprint:
    """What a subscription request tells us about the client behind it."""

    device_id: str
    source: str
    user_agent: str = ""
    address: str = ""

    @property
    def reported_hwid(self) -> bool:
        """Report whether the client identified itself instead of being guessed."""
        return self.source != NETWORK_SOURCE

    def record(self, now: str, previous: Mapping[str, str] | None = None) -> dict:
        """Return the persisted record, keeping the first sighting stable."""
        first_seen = str((previous or {}).get("first_seen", "")) or now
        return {
            "first_seen": first_seen,
            "last_seen": now,
            "source": self.source,
            "user_agent": self.user_agent[:_MAX_AGENT],
            "address": self.address,
        }


def _normalized_agent(value: object) -> str:
    """Normalize harmless User-Agent spacing without changing its identity."""
    return " ".join(str(value or "").split())[:_MAX_AGENT]


def subscription_fingerprint(
    headers: Mapping[str, str],
    client_ip: str,
    params: Mapping[str, list[str]],
) -> DeviceFingerprint:
    """Identify a subscription client, preferring what the client reports."""
    raw = ""
    source = ""
    for name in HWID_HEADERS:
        raw = str(headers.get(name, "") or "").strip()
        if raw:
            source = name.lower()
            break
    if not raw:
        for name in HWID_PARAMS:
            values = params.get(name, [])
            raw = str(values[0] if values else "").strip()
            if raw:
                source = name
                break
    agent = _normalized_agent(headers.get("User-Agent", ""))
    if not raw:
        # A client name is less precise than HWID, but unlike an address it
        # survives normal mobile/Wi-Fi network changes.  If the client does not
        # identify itself at all, the peer address remains the last signal.
        raw = f"client:{agent}" if agent else f"address:{client_ip}"
        source = NETWORK_SOURCE
    return DeviceFingerprint(
        device_id=hashlib.sha256(f"{source}:{raw}".encode()).hexdigest(),
        source=source,
        user_agent=agent,
        address=str(client_ip or ""),
    )


def hydrabox_client_fingerprint(
    headers: Mapping[str, str],
    client_ip: str,
) -> DeviceFingerprint:
    """Validate the strict HydraBox identity contract and hash its HWID."""
    agent = _normalized_agent(headers.get("User-Agent", ""))
    if not _HYDRABOX_AGENT.match(agent):
        raise ValueError("HydraBox User-Agent is required")
    raw_hwid = str(headers.get("X-Hydra-HWID", "") or "").strip()
    if not _HYDRABOX_HWID.fullmatch(raw_hwid):
        raise ValueError("Valid X-Hydra-HWID is required")
    return DeviceFingerprint(
        device_id=hashlib.sha256(raw_hwid.encode("ascii")).hexdigest(),
        source="x-hydra-hwid",
        user_agent=agent,
        address=str(client_ip or ""),
    )


def subscription_device_id(
    headers: Mapping[str, str],
    client_ip: str,
    params: Mapping[str, list[str]],
) -> str:
    """Return the stable identifier of a subscription client."""
    return subscription_fingerprint(headers, client_ip, params).device_id


def register_subscription_device(
    token: str,
    device: DeviceFingerprint | str,
) -> tuple[AppState, User | None, str]:
    """Atomically register a device, rejecting new devices above the user limit."""
    fingerprint = (
        device
        if isinstance(device, DeviceFingerprint)
        else DeviceFingerprint(device_id=str(device), source=NETWORK_SOURCE)
    )
    now = datetime.now(timezone.utc).isoformat()
    device_id = fingerprint.device_id

    def mutate(state: AppState) -> tuple[str, str]:
        user = next((item for item in state.users if item.uuid == token), None)
        if user is None:
            return "missing", ""
        legacy_ids = [
            known_id
            for known_id, record in user.devices.items()
            if (
                known_id != device_id
                and fingerprint.source == NETWORK_SOURCE
                and bool(fingerprint.user_agent)
                and str(record.get("source", "")) == NETWORK_SOURCE
                and _normalized_agent(record.get("user_agent", ""))
                == fingerprint.user_agent
            )
        ]
        known = device_id in user.devices or bool(legacy_ids)
        if user.device_limit > 0 and not known:
            if len(user.devices) >= user.device_limit:
                return "limit", user.email
        previous_records = [
            user.devices[known_id]
            for known_id in (device_id, *legacy_ids)
            if known_id in user.devices
        ]
        previous = min(
            previous_records,
            key=lambda record: str(record.get("first_seen", "")) or now,
            default=None,
        )
        for known_id in legacy_ids:
            user.devices.pop(known_id, None)
        user.devices[device_id] = fingerprint.record(
            now,
            previous,
        )
        return "allowed", user.email

    state, (status, email) = update_state(mutate)
    user = next((item for item in state.users if item.email == email), None)
    return state, user, status


__all__ = [
    "HWID_HEADERS",
    "HWID_PARAMS",
    "NETWORK_SOURCE",
    "DeviceFingerprint",
    "hydrabox_client_fingerprint",
    "register_subscription_device",
    "subscription_device_id",
    "subscription_fingerprint",
]
