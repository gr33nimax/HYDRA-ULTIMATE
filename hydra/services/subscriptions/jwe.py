"""Strict flattened JWE for HydraBox SubscriptionData documents."""
from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hydra.core.hydrabox_keys import (
    decode_hydrabox_jwe_key,
    hydrabox_jwe_kid,
)
from hydra.services.subscriptions.hydrabox import (
    HYDRABOX_MEDIA_TYPE,
    serialize_hydrabox_subscription,
)


JWE_MEDIA_TYPE = "application/jose+json"
JWE_TYPE = "hbx+jwe"
HYDRABOX_MAX_PLAINTEXT_BYTES = 12 * 1024 * 1024
HYDRABOX_MAX_JWE_BYTES = 16 * 1024 * 1024
_OUTER_FIELDS = frozenset({"protected", "iv", "ciphertext", "tag"})
_HEADER_FIELDS = frozenset({"alg", "enc", "typ", "cty", "kid"})


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: object, field: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(f"invalid JWE {field}")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid JWE {field}") from exc


def _protected_header(key: str) -> dict[str, str]:
    return {
        "alg": "dir",
        "enc": "A256GCM",
        "typ": JWE_TYPE,
        "cty": HYDRABOX_MEDIA_TYPE,
        "kid": hydrabox_jwe_kid(key),
    }


def encrypt_hydrabox_subscription(
    subscription: dict[str, Any],
    key: str,
    *,
    iv: bytes | None = None,
) -> str:
    """Encrypt a document as bounded flattened ``dir``/``A256GCM`` JWE."""
    plaintext = serialize_hydrabox_subscription(subscription).encode("utf-8")
    if len(plaintext) > HYDRABOX_MAX_PLAINTEXT_BYTES:
        raise ValueError("HydraBox plaintext exceeds 12 MiB")
    nonce = iv if iv is not None else secrets.token_bytes(12)
    if len(nonce) != 12:
        raise ValueError("HydraBox JWE IV must contain 12 bytes")
    protected = _b64url(json.dumps(
        _protected_header(key),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii"))
    encrypted = AESGCM(decode_hydrabox_jwe_key(key)).encrypt(
        nonce,
        plaintext,
        protected.encode("ascii"),
    )
    outer = {
        "protected": protected,
        "iv": _b64url(nonce),
        "ciphertext": _b64url(encrypted[:-16]),
        "tag": _b64url(encrypted[-16:]),
    }
    result = json.dumps(outer, ensure_ascii=True, separators=(",", ":"))
    if len(result.encode("utf-8")) > HYDRABOX_MAX_JWE_BYTES:
        raise ValueError("HydraBox JWE exceeds 16 MiB")
    return result


def decrypt_hydrabox_subscription(
    payload: str,
    key: str,
    *,
    expected_kid: str | None = None,
) -> dict[str, Any]:
    """Decrypt a strict flattened JWE; primarily an interoperability seam."""
    if len(payload.encode("utf-8")) > HYDRABOX_MAX_JWE_BYTES:
        raise ValueError("HydraBox JWE exceeds 16 MiB")
    try:
        outer = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid HydraBox JWE JSON") from exc
    if not isinstance(outer, dict) or set(outer) != _OUTER_FIELDS:
        raise ValueError("invalid flattened HydraBox JWE fields")
    protected_value = outer["protected"]
    protected_bytes = _decode(protected_value, "protected")
    try:
        header = json.loads(protected_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid HydraBox JWE protected header") from exc
    expected = _protected_header(key)
    if not isinstance(header, dict) or set(header) != _HEADER_FIELDS:
        raise ValueError("invalid HydraBox JWE protected header")
    if any(
        header.get(name) != value
        for name, value in expected.items()
        if name != "kid"
    ):
        raise ValueError("unsupported HydraBox JWE protected header")
    wanted_kid = expected_kid or expected["kid"]
    if header.get("kid") != wanted_kid:
        raise ValueError("HydraBox JWE kid mismatch")
    nonce = _decode(outer["iv"], "iv")
    tag = _decode(outer["tag"], "tag")
    if len(nonce) != 12 or len(tag) != 16:
        raise ValueError("invalid HydraBox JWE IV or tag length")
    plaintext = AESGCM(decode_hydrabox_jwe_key(key)).decrypt(
        nonce,
        _decode(outer["ciphertext"], "ciphertext") + tag,
        str(protected_value).encode("ascii"),
    )
    if len(plaintext) > HYDRABOX_MAX_PLAINTEXT_BYTES:
        raise ValueError("HydraBox plaintext exceeds 12 MiB")
    document = json.loads(plaintext)
    if not isinstance(document, dict):
        raise ValueError("HydraBox plaintext must be an object")
    return document


__all__ = [
    "HYDRABOX_MAX_JWE_BYTES",
    "HYDRABOX_MAX_PLAINTEXT_BYTES",
    "JWE_MEDIA_TYPE",
    "decrypt_hydrabox_subscription",
    "encrypt_hydrabox_subscription",
]
