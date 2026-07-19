"""Application service boundary for protocol and plugin management."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from hydra.core.state import AppState
from hydra.plugins.base import BasePlugin, PluginCategory


class ProtocolOperations(Protocol):
    def install_plugin(self, state: AppState, name: str) -> bool: ...
    def reinstall_plugin(self, state: AppState, name: str) -> bool: ...
    def uninstall_plugin(self, state: AppState, name: str) -> bool: ...
    def enable(self, state: AppState, name: str) -> bool: ...
    def disable(self, state: AppState, name: str) -> bool: ...


class ProtocolCatalog(Protocol):
    def get(self, name: str) -> BasePlugin | None: ...
    def transports(self) -> list[BasePlugin]: ...
    def enhancements(self) -> list[BasePlugin]: ...
    def security(self) -> list[BasePlugin]: ...
    def status_all(self) -> dict[str, dict[str, Any]]: ...


@dataclass(frozen=True)
class ProtocolService:
    """Stable facade shared by CLI and future remote management transports."""

    operations: ProtocolOperations
    catalog: ProtocolCatalog

    def list(self, category: PluginCategory | None = None) -> list[BasePlugin]:
        if category == PluginCategory.TRANSPORT:
            return self.catalog.transports()
        if category == PluginCategory.ENHANCEMENT:
            return self.catalog.enhancements()
        if category == PluginCategory.SECURITY:
            return self.catalog.security()
        return [
            *self.catalog.transports(),
            *self.catalog.enhancements(),
            *self.catalog.security(),
        ]

    def get(self, name: str) -> BasePlugin | None:
        return self.catalog.get(name)

    def statuses(self) -> dict[str, dict[str, Any]]:
        return self.catalog.status_all()

    def install(self, state: AppState, name: str) -> bool:
        return self.operations.install_plugin(state, name)

    def reinstall(self, state: AppState, name: str) -> bool:
        return self.operations.reinstall_plugin(state, name)

    def uninstall(self, state: AppState, name: str) -> bool:
        return self.operations.uninstall_plugin(state, name)

    def enable(self, state: AppState, name: str) -> bool:
        return self.operations.enable(state, name)

    def disable(self, state: AppState, name: str) -> bool:
        return self.operations.disable(state, name)
