"""Rollback-only snapshots encoded with the stable state envelope."""

from __future__ import annotations

import hashlib
import json

from hydra.core.state_format import (
    UnsupportedStateVersion,
    is_state_document,
    pack_state_document,
    validate_state_document,
)
from hydra.core.state_models import AppState, validate_state
from hydra.core.state_serialization import (
    decode_serialized_state,
    from_state_dict,
    to_state_dict,
)


def serialize_state_snapshot(state: AppState) -> bytes:
    """Encode a checksummed rollback-only copy using the stable state envelope."""
    validate_state(state)
    document = pack_state_document(to_state_dict(state))
    state_payload = _encode_document(document)
    snapshot = {
        "snapshot_format_version": 1,
        "sha256": hashlib.sha256(state_payload).hexdigest(),
        "state": document,
    }
    return _encode_document(snapshot)


def deserialize_state_snapshot(payload: bytes) -> AppState:
    """Decode without backup fallback or future-version downgrade."""
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("state snapshot is not valid JSON") from exc
    if not isinstance(raw, dict) or "snapshot_format_version" not in raw:
        raise ValueError("state snapshot checksum envelope is missing")
    raw = _unwrap_checksummed_snapshot(raw)
    if not is_state_document(raw):
        raise ValueError("state snapshot does not use the stable state envelope")
    validate_state_document(raw)
    state = from_state_dict(AppState, decode_serialized_state(raw))
    validate_state(state)
    return state


def _unwrap_checksummed_snapshot(raw: dict) -> dict:
    version = raw["snapshot_format_version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("state snapshot format version must be a positive integer")
    if version != 1:
        raise UnsupportedStateVersion(f"state snapshot format {version} is newer than supported format 1")
    if set(raw) != {"snapshot_format_version", "sha256", "state"}:
        raise ValueError("state snapshot fields are invalid")
    document = raw["state"]
    digest = raw["sha256"]
    if not isinstance(document, dict) or not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("state snapshot checksum metadata is invalid")
    if hashlib.sha256(_encode_document(document)).hexdigest() != digest:
        raise ValueError("state snapshot checksum does not match its content")
    return document


def _encode_document(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


__all__ = ["deserialize_state_snapshot", "serialize_state_snapshot"]
