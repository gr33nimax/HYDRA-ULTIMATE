"""Deterministic mtproto.zig credentials isolated from Telemt."""

from __future__ import annotations

import base64
import hashlib
import hmac

from hydra.utils.crypto import derive_key


def derive_username(uuid: str) -> str:
    return "u" + derive_key("mtproto-zig-user", uuid)[:8]


def derive_secret(uuid: str) -> str:
    return hashlib.sha256(f"mtproto-zig-secret|{uuid}".encode()).hexdigest()[:32]


def make_tls_secret(secret: str, domain: str) -> str:
    return f"ee{secret}{domain.encode().hex()}"


# Telegram Desktop's WEB-proxy bridge context, exactly as upstream derives it.
BRIDGE_CONTEXT_PREFIX = b"tdesktop-web-proxy-bridge-v1\n"


def bridge_capability(secret_hex: str, host: str) -> str:
    """Derive one user's bridge capability for a canonical WEB host.

    The WEB link carries ``dd<secret>``; decoded, that is the 0xDD marker byte
    followed by the 16 secret bytes, and the capability is an unpadded URL-safe
    HMAC-SHA256 over the context prefix and the host. The relay recomputes the
    same value, so this is what makes the readiness probe an authenticated check
    rather than a plain fetch.
    """
    key = bytes.fromhex("dd" + str(secret_hex).strip())
    digest = hmac.new(key, BRIDGE_CONTEXT_PREFIX + host.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")
