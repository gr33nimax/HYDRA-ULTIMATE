"""Private per-user key material for HydraBox subscription encryption."""
from __future__ import annotations

import base64
import hashlib
import secrets


HYDRABOX_JWE_KEY_BYTES = 32


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_hydrabox_jwe_key(value: str) -> bytes:
    """Decode and validate one unpadded 256-bit HydraBox content key."""
    if not isinstance(value, str) or len(value) != 43:
        raise ValueError("HydraBox JWE key must be 32-byte base64url")
    try:
        decoded = base64.b64decode(
            value + "=",
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("HydraBox JWE key must be 32-byte base64url") from exc
    if len(decoded) != HYDRABOX_JWE_KEY_BYTES or _b64url(decoded) != value:
        raise ValueError("HydraBox JWE key must be 32-byte base64url")
    return decoded


def generate_hydrabox_jwe_key() -> str:
    """Generate a cryptographically random per-user A256GCM direct key."""
    return _b64url(secrets.token_bytes(HYDRABOX_JWE_KEY_BYTES))


def hydrabox_jwe_kid(value: str) -> str:
    """Return a non-secret stable identifier for a validated content key."""
    digest = hashlib.sha256(decode_hydrabox_jwe_key(value)).hexdigest()
    return f"hbx-{digest[:16]}"


def validate_optional_hydrabox_jwe_key(
    value: object,
    *,
    owner: str = "",
) -> None:
    """Validate an optional persisted key without ever returning its value."""
    if not isinstance(value, str):
        raise ValueError("user HydraBox JWE key must be a string")
    if not value:
        return
    try:
        decode_hydrabox_jwe_key(value)
    except ValueError as exc:
        if owner:
            raise ValueError(
                f"HydraBox JWE key is invalid for {owner}: {exc}",
            ) from None
        raise


__all__ = [
    "decode_hydrabox_jwe_key",
    "generate_hydrabox_jwe_key",
    "hydrabox_jwe_kid",
    "validate_optional_hydrabox_jwe_key",
]
