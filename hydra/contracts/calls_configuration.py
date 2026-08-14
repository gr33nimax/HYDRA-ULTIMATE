"""Validated Hydracore VK parasite Calls projections."""
from __future__ import annotations

import re
from typing import Callable, Mapping, Protocol, Sequence


CALL_MODE_VK_PARASITE = "vk_parasite"
DEFAULT_CALL_PORT = 56002
DEFAULT_ROOM_COUNT = 4
DEFAULT_PEER_READ_QUEUE_PACKETS = 512
MAX_JOIN_LINKS = 4
MAX_WORKERS = 8


class CallsProtocolState(Protocol):
    enabled: bool
    port: int
    config: dict


class CallsUser(Protocol):
    email: str
    uuid: str
    blocked: bool


class CallsNetworkState(Protocol):
    server_ip: str


class CallsStateAccess(Protocol):
    protocols: Mapping[str, CallsProtocolState]
    users: Sequence[CallsUser]
    network: CallsNetworkState


def public_endpoint(
    state: CallsStateAccess,
    observed: str | Callable[[], str] = "",
) -> str:
    """Return the explicit Calls endpoint without borrowing a transport SNI."""
    desired = state.protocols.get("calls")
    configured = desired.config.get("public_endpoint", "") if desired else ""
    fallback = (
        observed()
        if callable(observed) and not configured and not state.network.server_ip
        else observed
    )
    endpoint = str(configured or state.network.server_ip or fallback).strip().strip("[]")
    if not endpoint or len(endpoint) > 253 or any(char.isspace() for char in endpoint):
        raise ValueError("Calls public_endpoint must be an IP address or DNS name")
    if endpoint.startswith(("http://", "https://")) or "/" in endpoint or ":" in endpoint:
        raise ValueError("Calls public_endpoint must not contain a scheme, port, or path")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", endpoint):
        raise ValueError("Calls public_endpoint must be an IP address or DNS name")
    return endpoint


def call_mode(state: CallsStateAccess) -> str:
    desired = state.protocols.get("calls")
    value = (
        str(desired.config.get("mode", CALL_MODE_VK_PARASITE))
        if desired
        else CALL_MODE_VK_PARASITE
    )
    if value != CALL_MODE_VK_PARASITE:
        raise ValueError("Calls mode must be vk_parasite")
    return value


def peer_read_queue_packets(config: dict) -> int:
    return _integer(
        config,
        "peer_read_queue_packets",
        DEFAULT_PEER_READ_QUEUE_PACKETS,
        16,
        4096,
    )


def _integer(config: dict, name: str, default: int, minimum: int, maximum: int) -> int:
    value = config.get(name, default)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Calls {name} must be between {minimum} and {maximum}")
    return value


def _duration(config: dict, name: str, default: str) -> str:
    value = str(config.get(name, default)).strip()
    if len(value) > 32 or re.fullmatch(r"(?:[1-9][0-9]*(?:ms|s|m|h)){1,4}", value) is None:
        raise ValueError(f"Calls {name} must be a bounded duration")
    return value


def _listen_port(state: CallsStateAccess, config: dict) -> int:
    port = _integer(config, "listen_port", DEFAULT_CALL_PORT, 1, 65535)
    for name, protocol in state.protocols.items():
        if name == "calls" or not protocol.enabled:
            continue
        for field_name in ("dtls_port", "wg_port", "udp_port"):
            value = protocol.config.get(field_name)
            if type(value) is int and value == port:
                raise ValueError(
                    f"Calls listen_port conflicts with enabled {name}.{field_name}",
                )
        if name == "amneziawg":
            awg_ports: list[tuple[str, object]] = []
            if protocol.port:
                awg_ports.append(("port", protocol.port))
            profiles = protocol.config.get("profiles", {})
            if isinstance(profiles, dict):
                awg_ports.extend(
                    (f"profiles.{profile_name}.port", profile.get("port"))
                    for profile_name, profile in profiles.items()
                    if isinstance(profile, dict) and profile.get("port")
                )
            if not awg_ports:
                awg_ports.append(("port", 51820))
            for field_name, value in awg_ports:
                if type(value) is int and value == port:
                    raise ValueError(
                        f"Calls listen_port conflicts with enabled {name}.{field_name}",
                    )
    return port


def _join_links(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        link = str(value).strip()
        if not link or len(link) > 2048:
            raise ValueError("Calls vk_parasite contains an invalid VK join link")
        if link in normalized:
            raise ValueError("Calls vk_parasite requires unique VK join links")
        normalized.append(link)
    if not 1 <= len(normalized) <= MAX_JOIN_LINKS:
        raise ValueError("Calls vk_parasite requires 1..4 unique VK join links")
    return normalized


def _obfs_password(config: dict) -> str:
    password = str(config.get("obfs_password", "")).strip()
    if not 32 <= len(password.encode("utf-8")) <= 256:
        raise ValueError("Calls obfs_password must contain 32..256 bytes")
    return password


def vk_parasite_inbound(
    state: CallsStateAccess,
    user_password: Callable[[CallsUser], str],
) -> dict:
    desired = state.protocols["calls"]
    config = desired.config
    password = _obfs_password(config)
    users = [
        {
            "name": user.email,
            "password": user_password(user),
            "max_sessions": _integer(config, "max_sessions_per_user", 1, 1, 16),
        }
        for user in state.users
        if not user.blocked
    ]
    if not users:
        raise ValueError("Calls vk_parasite requires at least one active user")
    return {
        "type": "call",
        "tag": "calls-vk-in",
        "platform": "vk",
        "mode": CALL_MODE_VK_PARASITE,
        "listen": "0.0.0.0",
        "listen_port": _listen_port(state, config),
        "obfs_password": password,
        "users": users,
        "max_sessions": _integer(config, "max_sessions", 128, 1, 4096),
        "max_workers_per_session": _integer(
            config,
            "max_workers_per_session",
            MAX_WORKERS,
            MAX_WORKERS,
            MAX_WORKERS,
        ),
        "max_pending_handshakes": _integer(
            config,
            "max_pending_handshakes",
            256,
            1,
            4096,
        ),
        "handshake_timeout": _duration(config, "handshake_timeout", "10s"),
        "session_idle_timeout": _duration(config, "session_idle_timeout", "5m"),
        "udp_receive_buffer_bytes": _integer(
            config,
            "udp_receive_buffer_bytes",
            4 * 1024 * 1024,
            256 * 1024,
            64 * 1024 * 1024,
        ),
        "udp_send_buffer_bytes": _integer(
            config,
            "udp_send_buffer_bytes",
            4 * 1024 * 1024,
            256 * 1024,
            64 * 1024 * 1024,
        ),
        "ingress_workers": _integer(config, "ingress_workers", 0, 0, 32),
        "ingress_queue_packets": _integer(
            config,
            "ingress_queue_packets",
            4096,
            1,
            65536,
        ),
        "peer_read_queue_packets": peer_read_queue_packets(config),
    }


def vk_parasite_outbound(
    user: CallsUser,
    state: CallsStateAccess,
    join_links: list[str],
    user_password: Callable[[CallsUser], str],
    *,
    server_address: str,
) -> dict:
    desired = state.protocols["calls"]
    config = desired.config
    join_links = _join_links(join_links)
    server = str(server_address).strip().strip("[]")
    if not server:
        raise ValueError("Calls vk_parasite server address is not configured")
    _integer(config, "max_workers_per_session", MAX_WORKERS, MAX_WORKERS, MAX_WORKERS)
    workers = _integer(config, "workers", MAX_WORKERS, MAX_WORKERS, MAX_WORKERS)
    return {
        "type": "call",
        "tag": "call-vk-out",
        "platform": "vk",
        "mode": CALL_MODE_VK_PARASITE,
        "server": server,
        "server_port": _listen_port(state, config),
        "join_links": join_links,
        "user": user.email,
        "password": user_password(user),
        "obfs_password": _obfs_password(config),
        "workers": workers,
        "worker_connect_timeout": _duration(
            config,
            "worker_connect_timeout",
            "15s",
        ),
    }


__all__ = [
    "CALL_MODE_VK_PARASITE",
    "DEFAULT_CALL_PORT",
    "DEFAULT_ROOM_COUNT",
    "DEFAULT_PEER_READ_QUEUE_PACKETS",
    "MAX_JOIN_LINKS",
    "MAX_WORKERS",
    "call_mode",
    "vk_parasite_inbound",
    "vk_parasite_outbound",
    "peer_read_queue_packets",
    "public_endpoint",
]
