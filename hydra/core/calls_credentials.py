"""Credential derivation for native Calls projections."""
from __future__ import annotations

from typing import Protocol

from hydra.utils.crypto import derive_hex_key


class CallsCredentialUser(Protocol):
    uuid: str


def user_password(user: CallsCredentialUser) -> str:
    return derive_hex_key("calls-vk-user", user.uuid)


__all__ = ["CallsCredentialUser", "user_password"]
