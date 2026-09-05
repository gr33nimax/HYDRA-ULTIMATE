"""Pure persisted-state schema and semantic validation.

This module deliberately has no filesystem, locking, or process concerns.
Domain and plugin code can depend on these types without the storage adapter.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from hydra.contracts import JsonValue, PluginConfig, validate_json_object
from hydra.core.state_calls_models import validate_calls_protocol
from hydra.core.hydrabox_keys import validate_optional_hydrabox_jwe_key
from hydra.core.state_creator_models import HeadlessCreatorConfig
from hydra.core.state_creator_models import validate_headless_creator
from hydra.core.state_devices import validate_device_map
from hydra.core.state_format import STATE_FORMAT_VERSION, UnsupportedStateVersion
from hydra.core.state_kernel_models import (
    KernelConfig,
    validate_kernel_config,
)
from hydra.core.state_network_models import NetworkConfig
from hydra.core.state_validation import validate_raw_state, validate_supported_version


# Compatibility alias for public status/CLI code. This is the stable document
# format, not a product or feature version.
SCHEMA_VERSION = STATE_FORMAT_VERSION


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
    hydrabox_jwe_key: str = ""

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
class AppState:
    """Runtime aggregate projected from the stable persisted document."""

    format_version: int = STATE_FORMAT_VERSION
    revision: int = 0
    install: dict = field(default_factory=dict)
    protocols: dict[str, PluginState] = field(default_factory=dict)
    users: list[User] = field(default_factory=list)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    headless_creator: HeadlessCreatorConfig = field(default_factory=HeadlessCreatorConfig)
    kernel: KernelConfig = field(default_factory=KernelConfig)
    core_extensions: dict[str, JsonValue] = field(default_factory=dict)
    feature_extensions: dict[str, JsonValue] = field(default_factory=dict)

    @property
    def version(self) -> int:
        """Compatibility name used by existing status and service DTOs."""
        return self.format_version


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
    if type(state.format_version) is not int or state.format_version < 1:
        raise ValueError("state format_version must be positive")
    if type(state.revision) is not int or state.revision < 0:
        raise ValueError("state revision must be non-negative")
    if state.format_version != STATE_FORMAT_VERSION:
        raise UnsupportedStateVersion(
            f"state format {state.format_version} is not supported; expected "
            f"{STATE_FORMAT_VERSION}"
        )
    validate_headless_creator(state.headless_creator)
    validate_kernel_config(state.kernel)
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
        validate_optional_hydrabox_jwe_key(
            user.hydrabox_jwe_key,
            owner=user.email,
        )
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
        validate_calls_protocol(
            name, enabled=protocol.enabled, config=protocol.config,
            kernel_provider=state.kernel.provider,
        )
