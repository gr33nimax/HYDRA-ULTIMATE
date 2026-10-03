"""Shared pure validation and canonical-document helpers for managed-node DTOs."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_OPERATION_STATES = {"pending", "running", "succeeded", "failed", "recovery_required"}
_OUTCOMES = {"ok", "error", "unknown", "not_applicable"}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SSH_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_SECRET_KEY = re.compile(r"(?i)(password|token|secret|private[_-]?key|authorization|askpass|cookie)")


def _text(value: object, path: str, *, maximum: int = 253, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError(f"{path} must be non-empty text of at most {maximum} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{path} contains a control character")
    return value


def _identifier(value: object, path: str) -> str:
    text = _text(value, path, maximum=64)
    if not _ID.fullmatch(text):
        raise ValueError(f"{path} has an invalid identifier")
    return text


def _reference(value: object, path: str) -> str:
    text = _text(value, path, maximum=192)
    if text.startswith("/") or "\\" in text or any(part in {"", ".", ".."} for part in text.split("/")):
        raise ValueError(f"{path} must be a scoped relative reference")
    if any(not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", part) for part in text.split("/")):
        raise ValueError(f"{path} has an invalid scoped reference")
    return text


def _digest(value: object, path: str, *, empty: bool = False) -> str:
    text = _text(value, path, maximum=64, empty=empty)
    if text and not _SHA256.fullmatch(text):
        raise ValueError(f"{path} must be a lowercase SHA-256 digest")
    return text


def _integer(value: object, path: str, minimum: int = 0, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        bound = f"{minimum}..{maximum}" if maximum is not None else f">= {minimum}"
        raise ValueError(f"{path} must be an integer {bound}")
    return value


def _mapping(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{path} must be an object with string keys")
    return value


def _reject_secret_fields(value: object, path: str = "document") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and _SECRET_KEY.search(key):
                raise ValueError(f"{path}.{key} contains a forbidden secret field")
            _reject_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_fields(child, f"{path}[{index}]")


def canonical_digest(value: object) -> str:
    """Hash an explicit JSON document with stable key and collection order."""
    serializer = getattr(value, "to_document", None)
    document = serializer() if callable(serializer) else value
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _unique(values: list[str], path: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{path} contains duplicate identifiers")


__all__ = ["canonical_digest"]
