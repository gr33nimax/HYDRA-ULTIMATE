"""Stable on-disk envelope for HYDRA state."""
from __future__ import annotations

import copy


STATE_FORMAT_VERSION = 1

_CORE_KEYS = ("install", "users", "telegram", "network")
_FEATURE_KEYS = ("protocols", "headless_creator", "kernel")
_DEFAULTS = {
    "install": {},
    "users": [],
    "telegram": {},
    "network": {},
    "protocols": {},
    "headless_creator": {},
    "kernel": {},
}


class UnsupportedStateVersion(RuntimeError):
    """Persisted state was produced by a newer HYDRA format."""


def is_state_document(raw: object) -> bool:
    return isinstance(raw, dict) and "format_version" in raw


def validate_state_document(raw: object) -> None:
    if not isinstance(raw, dict):
        raise ValueError("state root must be an object")
    version = raw.get("format_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("state format_version must be a positive integer")
    if version != STATE_FORMAT_VERSION:
        raise UnsupportedStateVersion(
            f"state format {version} is newer than supported format "
            f"{STATE_FORMAT_VERSION}"
        )
    revision = raw.get("revision", 0)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("state revision must be a non-negative integer")
    for key in ("core", "features"):
        if not isinstance(raw.get(key, {}), dict):
            raise ValueError(f"state field '{key}' must be an object")


def unpack_state_document(raw: dict) -> dict:
    """Flatten the stable envelope into the existing runtime aggregate."""
    validate_state_document(raw)
    core = copy.deepcopy(raw.get("core", {}))
    features = copy.deepcopy(raw.get("features", {}))
    return {
        "format_version": raw["format_version"],
        "revision": raw.get("revision", 0),
        **{key: core.pop(key, copy.deepcopy(_DEFAULTS[key])) for key in _CORE_KEYS},
        **{
            key: features.pop(key, copy.deepcopy(_DEFAULTS[key]))
            for key in _FEATURE_KEYS
        },
        "core_extensions": core,
        "feature_extensions": features,
    }


def pack_state_document(payload: dict) -> dict:
    """Pack the runtime aggregate while preserving unknown namespaces."""
    data = copy.deepcopy(payload)
    version = data.pop("format_version", STATE_FORMAT_VERSION)
    revision = data.pop("revision", 0)
    core = data.pop("core_extensions", {})
    features = data.pop("feature_extensions", {})
    core.update({key: data.pop(key) for key in _CORE_KEYS})
    features.update({key: data.pop(key) for key in _FEATURE_KEYS})
    features.update(data)
    document = {
        "format_version": version,
        "revision": revision,
        "core": core,
        "features": features,
    }
    validate_state_document(document)
    return document


__all__ = [
    "STATE_FORMAT_VERSION",
    "UnsupportedStateVersion",
    "is_state_document",
    "pack_state_document",
    "unpack_state_document",
    "validate_state_document",
]
