"""Live device sessions derived from attributed connections.

A device on the data path is one source address: the transport sees no HWID,
only where the connection comes from. The subscription server knows the HWID
and records it separately, so operator views can join the two by address.
"""
from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from hydra.core.state_models import AppState


SESSIONS_KEY = "device_sessions"
COUNTERS_KEY = "traffic_connection_counters"
SESSION_TTL_SECONDS = 600
MAX_SESSIONS_PER_USER = 32


@dataclass(frozen=True)
class DeviceSession:
    """One address a user is currently connected from."""

    user: str
    address: str
    first_seen: float
    last_seen: float
    connections: int
    bytes_total: int
    allowed: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "connections": self.connections,
            "bytes_total": self.bytes_total,
            "allowed": self.allowed,
        }


def _records(state: AppState) -> Mapping[str, Mapping[str, object]]:
    counters = state.install.get(COUNTERS_KEY, {})
    return counters if isinstance(counters, dict) else {}


def observed_devices(
    state: AppState,
    *,
    now: float | None = None,
) -> dict[str, dict[str, dict[str, object]]]:
    """Group the current connection snapshot into per-user device sessions."""
    timestamp = time.time() if now is None else now
    sessions: dict[str, dict[str, dict[str, object]]] = {}
    for record in _records(state).values():
        if int(record.get("missed_polls", 0) or 0):
            continue
        user = str(record.get("user") or "")
        address = str(record.get("address") or "")
        if not user or not address:
            continue
        device = sessions.setdefault(user, {}).setdefault(
            address,
            {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "connections": 0,
                "bytes_total": 0,
            },
        )
        device["connections"] = int(device["connections"]) + 1
        device["bytes_total"] = int(device["bytes_total"]) + int(
            record.get("total", 0) or 0,
        )
    return sessions


def update_sessions(
    state: AppState,
    *,
    now: float | None = None,
    ttl: int = SESSION_TTL_SECONDS,
) -> dict[str, list[str]]:
    """Refresh persisted sessions and return the addresses over each limit.

    Devices are ordered by when they were first seen, so an established
    device keeps working and a newcomer beyond the limit is the one refused.
    """
    timestamp = time.time() if now is None else now
    stored = state.install.get(SESSIONS_KEY)
    stored = dict(stored) if isinstance(stored, dict) else {}
    observed = observed_devices(state, now=timestamp)
    limits = {user.email: int(user.device_limit or 0) for user in state.users}
    refused: dict[str, list[str]] = {}
    result: dict[str, dict[str, dict[str, object]]] = {}

    for user, devices in observed.items():
        previous = stored.get(user, {})
        previous = previous if isinstance(previous, dict) else {}
        merged: dict[str, dict[str, object]] = {}
        for address, device in devices.items():
            known = previous.get(address, {})
            known = known if isinstance(known, dict) else {}
            merged[address] = {
                **device,
                "first_seen": float(
                    known.get("first_seen", device["first_seen"]),
                ),
                "last_seen": timestamp,
            }
        limit = limits.get(user, 0)
        order = sorted(merged, key=lambda item: merged[item]["first_seen"])
        over_limit = order[limit:] if limit > 0 else []
        for address in order:
            merged[address]["allowed"] = address not in over_limit
        if over_limit:
            refused[user] = over_limit
        result[user] = _retain(merged, previous, timestamp, ttl)

    for user, previous in stored.items():
        if user in result or not isinstance(previous, dict):
            continue
        retained = _retain({}, previous, timestamp, ttl)
        if retained:
            result[user] = retained

    state.install[SESSIONS_KEY] = result
    return refused


def _retain(
    active: dict[str, dict[str, object]],
    previous: Mapping[str, object],
    now: float,
    ttl: int,
) -> dict[str, dict[str, object]]:
    """Keep recent history so a short reconnect is not a new device."""
    merged = dict(active)
    for address, device in previous.items():
        if address in merged or not isinstance(device, dict):
            continue
        if now - float(device.get("last_seen", 0) or 0) > ttl:
            continue
        merged[address] = {**device, "connections": 0}
    if len(merged) <= MAX_SESSIONS_PER_USER:
        return merged
    newest = sorted(
        merged,
        key=lambda item: float(merged[item].get("last_seen", 0) or 0),
        reverse=True,
    )[:MAX_SESSIONS_PER_USER]
    return {address: merged[address] for address in newest}


def connections_to_close(
    state: AppState,
    refused: Mapping[str, Sequence[str]],
) -> list[str]:
    """Return connection ids belonging to devices beyond a user's limit."""
    unwanted = {
        (user, address)
        for user, addresses in refused.items()
        for address in addresses
    }
    if not unwanted:
        return []
    return sorted(
        connection_id
        for connection_id, record in _records(state).items()
        if (
            not int(record.get("missed_polls", 0) or 0)
            and (
                str(record.get("user") or ""),
                str(record.get("address") or ""),
            )
            in unwanted
        )
    )


def user_sessions(state: AppState, email: str) -> list[DeviceSession]:
    """Return the recorded sessions of one user, newest activity first."""
    stored = state.install.get(SESSIONS_KEY, {})
    devices = stored.get(email, {}) if isinstance(stored, dict) else {}
    if not isinstance(devices, dict):
        return []
    sessions = [
        DeviceSession(
            user=email,
            address=address,
            first_seen=float(device.get("first_seen", 0) or 0),
            last_seen=float(device.get("last_seen", 0) or 0),
            connections=int(device.get("connections", 0) or 0),
            bytes_total=int(device.get("bytes_total", 0) or 0),
            allowed=bool(device.get("allowed", True)),
        )
        for address, device in devices.items()
        if isinstance(device, dict)
    ]
    return sorted(sessions, key=lambda item: item.last_seen, reverse=True)


__all__ = [
    "COUNTERS_KEY",
    "MAX_SESSIONS_PER_USER",
    "SESSIONS_KEY",
    "SESSION_TTL_SECONDS",
    "DeviceSession",
    "connections_to_close",
    "observed_devices",
    "update_sessions",
    "user_sessions",
]
