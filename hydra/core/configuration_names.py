"""Persistent display-name resolution for client configurations."""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Mapping
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


def configuration_name_key(
    plugin_name: str,
    parameters: Mapping[str, object],
) -> str:
    """Return the profile key when a plugin has several client configurations."""
    profile = parameters.get("profile")
    if isinstance(profile, str) and profile.strip():
        return f"{plugin_name}:{profile.strip()}"
    return plugin_name


def apply_json_configuration_name(
    payload: str,
    *,
    key: str,
    global_names: dict[str, str],
    user_names: dict[str, str],
) -> str:
    """Rename a JSON profile's primary outbound when an override exists."""
    name = user_names.get(key) or global_names.get(key)
    if not name:
        return payload
    try:
        document = json.loads(payload)
        if not isinstance(document, dict):
            return payload
        outbounds = document.get("outbounds", [])
        if not isinstance(outbounds, list):
            return payload
        route = document.get("route", {})
        final = route.get("final") if isinstance(route, dict) else None
        primary = next(
            (
                outbound
                for outbound in outbounds
                if isinstance(outbound, dict)
                and outbound.get("tag") == final
                and final != "direct"
            ),
            next(
                (
                    outbound
                    for outbound in outbounds
                    if isinstance(outbound, dict)
                    and outbound.get("tag") != "direct"
                    and isinstance(outbound.get("tag"), str)
                ),
                None,
            ),
        )
        if primary is None:
            return payload
        old = primary.get("tag")
        if not isinstance(old, str) or name == old:
            return payload
        tags = {
            outbound.get("tag")
            for outbound in outbounds
            if isinstance(outbound, dict) and outbound is not primary
        }
        replacement = _unique_configuration_tag(name, tags)
        primary["tag"] = replacement
        _replace_profile_reference(document, old, replacement)
        return json.dumps(document, indent=2)
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return payload


def _unique_configuration_tag(name: str, tags: set[object]) -> str:
    tags = tags | {"select", "direct", "lowest", "lowest-open", "lowest-free", "mixed"}
    if name.startswith("__hydra."):
        name = f"Profile {name}"
    if name not in tags:
        return name
    number = 2
    while f"{name} ({number})" in tags:
        number += 1
    return f"{name} ({number})"


def _replace_profile_reference(value: object, old: str, new: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"detour", "outbound", "endpoint", "final", "default"}:
                if child == old:
                    value[key] = new
            elif key == "outbounds" and isinstance(child, list):
                for index, tag in enumerate(child):
                    if tag == old:
                        child[index] = new
            _replace_profile_reference(child, old, new)
    elif isinstance(value, list):
        for child in value:
            _replace_profile_reference(child, old, new)


def user_with_configuration_names(user, global_names: dict[str, str]):
    """Give a profile generator the resolved names without widening its state API."""
    names = {**global_names, **user.configuration_name_overrides}
    for transport in ("tcp", "quic"):
        key = f"trusttunnel:{transport}"
        for source in (user.configuration_name_overrides, global_names):
            if source.get(key):
                names[key] = source[key]
                break
            if source.get("trusttunnel"):
                names[key] = source["trusttunnel"] + (" QUIC" if transport == "quic" else "")
                break
    return replace(
        user,
        configuration_name_overrides=names,
    )


__all__ = [
    "MAX_CONFIGURATION_NAME_LENGTH",
    "apply_json_configuration_name",
    "configuration_name_key",
    "normalize_configuration_name",
    "resolve_configuration_name",
    "user_with_configuration_names",
    "validate_configuration_key",
    "validate_configuration_names",
]
