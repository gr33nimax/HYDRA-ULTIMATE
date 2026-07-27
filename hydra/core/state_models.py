"""Pure persisted-state schema and semantic validation.

This module deliberately has no filesystem, locking, or process concerns.
Domain and plugin code can depend on these types without depending on the
state-storage adapter exposed by :mod:`hydra.core.state`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from hydra.contracts import JsonValue, PluginConfig, validate_json_object


from hydra.core.state_devices import validate_device_map


SCHEMA_VERSION = 5


class UnsupportedStateVersion(RuntimeError):
    """Persisted state was produced by a newer HYDRA schema."""


@dataclass
class PluginState:
    """Persisted desired and observed state for one plugin."""

    enabled: bool = False
    port: int = 0
    installed: bool = False
    config: PluginConfig = field(default_factory=dict)


@dataclass
class User:
    """Persisted user account and per-plugin credentials."""

    email: str
    uuid: str
    traffic_limit_gb: float = 0
    traffic_used_bytes: int = 0
    expiry_date: str = ""
    blocked: bool = False
    created_at: str = ""
    telegram_id: Optional[int] = None
    credentials: dict[str, dict] = field(default_factory=dict)
    device_limit: int = 0
    # device id -> {first_seen, last_seen, source, user_agent, address}
    devices: dict[str, dict] = field(default_factory=dict)


@dataclass
class TelegramConfig:
    """Persisted Telegram adapter settings."""

    admin_token: str = ""
    admin_chat_id: str = ""
    bot_token: str = ""
    bot_enabled: bool = False
    admin_enabled: bool = False
    allowed_users: list[int] = field(default_factory=list)
    notifications_enabled: bool = True
    notify_antidpi: bool = True
    notify_honeypot: bool = True
    notify_fail2ban: bool = True
    notify_unbans: bool = False
    notify_system: bool = True
    notify_only_blocks: bool = False
    quiet_hours_enabled: bool = False
    quiet_hours_start: int = 23
    quiet_hours_end: int = 8


@dataclass
class NetworkConfig:
    """Persisted network settings that are not owned by a plugin."""

    domain: str = ""
    sub_domain: str = ""
    server_ip: str = ""
    dns_servers: list[str] = field(default_factory=list)
    dnscrypt_port: int = 5300
    tproxy_enabled: bool = False
    tproxy_port: int = 1081
    clash_api_enabled: bool = False
    clash_api_port: int = 9090
    clash_api_secret: str = ""


@dataclass
class AppState:
    """Persisted aggregate root."""

    version: int = SCHEMA_VERSION
    revision: int = 0
    install: dict = field(default_factory=dict)
    protocols: dict[str, PluginState] = field(default_factory=dict)
    users: list[User] = field(default_factory=list)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)


def validate_raw_state(raw: object) -> None:
    """Reject structurally invalid serialized state before construction."""
    if not isinstance(raw, dict):
        raise ValueError("state root must be an object")
    version = raw.get("version", 0)
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError("state version must be a non-negative integer")
    revision = raw.get("revision", 0)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("state revision must be a non-negative integer")
    for key in ("protocols", "install", "telegram", "network", "security"):
        if key in raw and not isinstance(raw[key], dict):
            raise ValueError(f"state field '{key}' must be an object")
    if "users" in raw:
        users = raw["users"]
        if not isinstance(users, list) or any(not isinstance(user, dict) for user in users):
            raise ValueError("state field 'users' must be a list of objects")
        for user in users:
            if (
                not isinstance(user.get("email", ""), str)
                or not isinstance(user.get("uuid", ""), str)
            ):
                raise ValueError("user email and uuid must be strings")
            device_limit = user.get("device_limit", 0)
            if type(device_limit) is not int or device_limit < 0:
                raise ValueError("user device limit must be a non-negative integer")
            validate_device_map(
                user.get("devices", {}),
                legacy=int(raw.get("version", SCHEMA_VERSION)) < 5,
            )
    if "protocols" in raw:
        for name, protocol in raw["protocols"].items():
            if not isinstance(name, str) or not isinstance(protocol, dict):
                raise ValueError("protocol entries must be named objects")


def validate_supported_version(raw: dict) -> None:
    """Reject future schemas instead of silently dropping their fields."""
    version = raw.get("version", 0)
    if version > SCHEMA_VERSION:
        raise UnsupportedStateVersion(
            f"state schema {version} is newer than supported schema "
            f"{SCHEMA_VERSION}"
        )


def get_protocol(state: AppState, name: str) -> PluginState:
    """Return a plugin state, creating its canonical entry if necessary."""
    if name not in state.protocols:
        state.protocols[name] = PluginState()
    return state.protocols[name]


def find_user(state: AppState, email: str) -> Optional[User]:
    """Return the user with the exact persisted identifier."""
    return next((user for user in state.users if user.email == email), None)


def add_user(state: AppState, user: User) -> None:
    """Add or replace a user while preserving global UUID uniqueness."""
    duplicate_uuid = next(
        (item for item in state.users
         if item.uuid == user.uuid and item.email != user.email),
        None,
    )
    if duplicate_uuid is not None:
        raise ValueError(
            f"UUID уже используется пользователем {duplicate_uuid.email}"
        )
    existing = find_user(state, user.email)
    if existing is None:
        state.users.append(user)
        return
    state.users[state.users.index(existing)] = user


def validate_state(state: AppState) -> None:
    """Validate semantic invariants before persisting or applying state."""
    if type(state.version) is not int or state.version < 0:
        raise ValueError("state version must be non-negative")
    if type(state.revision) is not int or state.revision < 0:
        raise ValueError("state revision must be non-negative")
    if state.version > SCHEMA_VERSION:
        raise UnsupportedStateVersion(
            f"state schema {state.version} is newer than supported schema "
            f"{SCHEMA_VERSION}"
        )
    for user in state.users:
        if (
            not isinstance(user.email, str)
            or not user.email.strip()
            or any(char.isspace() for char in user.email)
        ):
            raise ValueError(f"invalid user identifier: {user.email!r}")
        if not user.uuid or not isinstance(user.uuid, str):
            raise ValueError(f"invalid UUID for user {user.email}")
        if user.traffic_limit_gb < 0 or user.traffic_used_bytes < 0:
            raise ValueError(
                f"traffic counters cannot be negative for {user.email}"
            )
        if type(user.device_limit) is not int or user.device_limit < 0:
            raise ValueError(
                f"device limit must be a non-negative integer for {user.email}"
            )
        try:
            validate_device_map(user.devices, legacy=False)
        except ValueError as exc:
            raise ValueError(
                f"device bindings are invalid for {user.email}: {exc}",
            ) from None
    ports = {
        "network.tproxy_port": state.network.tproxy_port,
        "network.clash_api_port": state.network.clash_api_port,
        "network.dnscrypt_port": state.network.dnscrypt_port,
    }
    for name, port in ports.items():
        if not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError(f"{name} must be between 0 and 65535")
    for name, protocol in state.protocols.items():
        if (
            not isinstance(name, str) or not name.strip()
            or not isinstance(protocol.config, dict)
        ):
            raise ValueError("protocol entries must have a name and object config")
        try:
            validate_json_object(protocol.config, path=f"protocols.{name}.config")
        except Exception as exc:
            raise ValueError(str(exc)) from exc
        if not isinstance(protocol.port, int) or not 0 <= protocol.port <= 65535:
            raise ValueError(f"protocol {name} has an invalid port")
