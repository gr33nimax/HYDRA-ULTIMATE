"""Dependency-neutral contracts for native call transports."""
from __future__ import annotations

from typing import Protocol


class CallConfigSource(Protocol):
    """Read protected call runtime inputs without exposing filesystem details."""

    def load_native_join_links(self) -> list[str]: ...

    def vk_parasite_supported(self) -> bool: ...

    def singbox_running(self) -> bool: ...


class UnavailableCallConfigSource:
    """Safe default used outside the production composition root."""

    def load_native_join_links(self) -> list[str]:
        return []

    def vk_parasite_supported(self) -> bool:
        return False

    def singbox_running(self) -> bool:
        return False


__all__ = ["CallConfigSource", "UnavailableCallConfigSource"]
