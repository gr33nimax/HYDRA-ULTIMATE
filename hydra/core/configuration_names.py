"""Persistent display-name resolution for client configurations."""
from __future__ import annotations

import unicodedata


MAX_CONFIGURATION_NAME_LENGTH = 128


def validate_configuration_key(key: object) -> str:
    """Accept a stable technical profile or variant identifier."""
    if not isinstance(key, str) or not key or len(key) > 128:
        raise ValueError("configuration key must be a stable non-empty identifier")
    if any(character.isspace() or unicodedata.category(character) == "Cc" for character in key):
        raise ValueError("configuration key must not contain whitespace or control characters")
    return key


def normalize_configuration_name(value: object) -> str:
    """Trim a display name; an empty value means remove the override."""
    if not isinstance(value, str):
        raise ValueError("configuration name must be a string")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError("configuration name must not contain control characters")
    name = value.strip()
    if len(name) > MAX_CONFIGURATION_NAME_LENGTH:
        raise ValueError("configuration name must be at most 128 characters")
    return name


def validate_configuration_names(value: object, *, path: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    for key, name in value.items():
        try:
            validate_configuration_key(key)
            normalized = normalize_configuration_name(name)
        except ValueError as exc:
            raise ValueError(f"{path}: {exc}") from None
        if not normalized:
            raise ValueError(f"{path} must not persist empty names")


def resolve_configuration_name(
    *,
    key: str,
    default: str,
    global_names: dict[str, str],
    user_names: dict[str, str],
) -> str:
    """Resolve user override, then global override, then the built-in default."""
    validate_configuration_key(key)
    return user_names.get(key) or global_names.get(key) or default


__all__ = [
    "MAX_CONFIGURATION_NAME_LENGTH",
    "normalize_configuration_name",
    "resolve_configuration_name",
    "validate_configuration_key",
    "validate_configuration_names",
]
