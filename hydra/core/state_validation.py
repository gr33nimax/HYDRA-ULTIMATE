"""Structural validation for current and legacy serialized state."""

from __future__ import annotations

from hydra.core.hydrabox_keys import validate_optional_hydrabox_jwe_key
from hydra.core.configuration_names import validate_configuration_names
from hydra.core.state_creator_models import validate_raw_headless_creator
from hydra.core.state_devices import validate_device_map
from hydra.core.state_format import STATE_FORMAT_VERSION, UnsupportedStateVersion
from hydra.core.state_kernel_models import validate_raw_kernel_config
from hydra.core.state_managed_nodes import validate_managed_nodes_extensions


LEGACY_SCHEMA_VERSION = 18


def supports_personal_protocol_access(name: str) -> bool:
    """WDTT uses a shared service password, not per-user credentials."""
    return name != "wdtt"


def validate_raw_state(raw: object) -> None:
    if not isinstance(raw, dict):
        raise ValueError("state root must be an object")
    version_key = "format_version" if "format_version" in raw else "version"
    version = raw.get(version_key, 0)
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError(f"state {version_key} must be a non-negative integer")
    revision = raw.get("revision", 0)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("state revision must be a non-negative integer")
    for key in (
        "protocols",
        "install",
        "telegram",
        "network",
        "security",
        "configuration_names",
        "core_extensions",
        "feature_extensions",
    ):
        if key in raw and not isinstance(raw[key], dict):
            raise ValueError(f"state field '{key}' must be an object")
    if "headless_creator" in raw:
        validate_raw_headless_creator(raw["headless_creator"])
    if "configuration_names" in raw:
        validate_configuration_names(raw["configuration_names"], path="configuration_names")
    if "kernel" in raw:
        validate_raw_kernel_config(raw["kernel"])
    validate_managed_nodes_extensions(raw.get("feature_extensions", {}))
    if "users" in raw:
        users = raw["users"]
        if not isinstance(users, list) or any(not isinstance(user, dict) for user in users):
            raise ValueError("state field 'users' must be a list of objects")
        for user in users:
            if not isinstance(user.get("email", ""), str) or not isinstance(user.get("uuid", ""), str):
                raise ValueError("user email and uuid must be strings")
            device_limit = user.get("device_limit", 0)
            if type(device_limit) is not int or device_limit < 0:
                raise ValueError("user device limit must be a non-negative integer")
            validate_optional_hydrabox_jwe_key(user.get("hydrabox_jwe_key", ""))
            if "configuration_name_overrides" in user:
                validate_configuration_names(
                    user["configuration_name_overrides"],
                    path="user.configuration_name_overrides",
                )
            disabled = user.get("disabled_protocols", [])
            if (
                not isinstance(disabled, list)
                or any(
                    not isinstance(name, str) or not name or not supports_personal_protocol_access(name)
                    for name in disabled
                )
                or len(set(disabled)) != len(disabled)
            ):
                raise ValueError("invalid user disabled_protocols")
            validate_device_map(
                user.get("devices", {}),
                legacy="format_version" not in raw and version < 5,
            )
    for name, protocol in raw.get("protocols", {}).items():
        if not isinstance(name, str) or not isinstance(protocol, dict):
            raise ValueError("protocol entries must be named objects")


def validate_supported_version(raw: dict) -> None:
    if "format_version" in raw:
        version = raw["format_version"]
        supported = STATE_FORMAT_VERSION
        label = "state format"
    else:
        version = raw.get("version", 0)
        supported = LEGACY_SCHEMA_VERSION
        label = "legacy state schema"
    if version > supported:
        raise UnsupportedStateVersion(f"{label} {version} is newer than supported {label} {supported}")


__all__ = ["LEGACY_SCHEMA_VERSION", "validate_raw_state", "validate_supported_version"]
