"""Deterministic mtproto.zig credentials isolated from Telemt."""

from __future__ import annotations

import hashlib

from hydra.utils.crypto import derive_key


def derive_username(uuid: str) -> str:
    return "u" + derive_key("mtproto-zig-user", uuid)[:8]


def derive_secret(uuid: str) -> str:
    return hashlib.sha256(f"mtproto-zig-secret|{uuid}".encode()).hexdigest()[:32]


def make_tls_secret(secret: str, domain: str) -> str:
    return f"ee{secret}{domain.encode().hex()}"
