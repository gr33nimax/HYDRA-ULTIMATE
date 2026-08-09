"""Dependency-neutral contracts for native call transports."""
from __future__ import annotations

from typing import Protocol


class CallConfigSource(Protocol):
    """Read protected call runtime inputs without exposing filesystem details."""

    def load_vk_cookies(self) -> list[dict[str, str]]: ...

    def load_native_join_link(self) -> str: ...

    def load_native_join_links(self) -> list[str]: ...

    def feature_supported(self) -> bool: ...

    def multi_user_supported(self) -> bool: ...

    def singbox_running(self) -> bool: ...


class UnavailableCallConfigSource:
    """Safe default used outside the production composition root."""

    def load_vk_cookies(self) -> list[dict[str, str]]:
        return []

    def load_native_join_link(self) -> str:
        return ""

    def load_native_join_links(self) -> list[str]:
        return []

    def feature_supported(self) -> bool:
        return False

    def multi_user_supported(self) -> bool:
        return False

    def singbox_running(self) -> bool:
        return False


__all__ = ["CallConfigSource", "UnavailableCallConfigSource"]
