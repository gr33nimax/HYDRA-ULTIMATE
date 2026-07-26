"""Allowlisted runtime actions owned by individual plugins."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from hydra.plugins.base import BasePlugin
from hydra.plugins.invoker import PluginInvoker


class PluginActions(Protocol):
    def execute(
        self,
        plugin_name: str,
        action: str,
        **parameters: object,
    ) -> Any: ...


@dataclass(frozen=True)
class UnavailablePluginActions:
    def execute(
        self,
        plugin_name: str,
        action: str,
        **parameters: object,
    ) -> Any:
        raise RuntimeError("plugin action service is unavailable")


@dataclass(frozen=True)
class PluginActionService:
    """Invoke a public runtime action without exposing a plugin instance."""

    get_plugin: Callable[[str], BasePlugin | None]
    invoker: PluginInvoker = field(default_factory=PluginInvoker)
    actions: Mapping[str, frozenset[str]] | None = None

    def execute(
        self,
        plugin_name: str,
        action: str,
        **parameters: object,
    ) -> Any:
        if action.startswith("_"):
            raise ValueError(
                f"unsupported plugin action: {plugin_name}.{action}",
            )
        plugin = self.get_plugin(plugin_name)
        if plugin is None:
            raise ValueError(f"unknown plugin: {plugin_name}")
        allowed = (
            self.actions.get(plugin_name, frozenset())
            if self.actions is not None
            else frozenset(plugin.meta.capabilities.actions)
        )
        if action not in allowed:
            raise ValueError(
                f"unsupported plugin action: {plugin_name}.{action}",
            )
        return self.invoker.action(plugin, action, **parameters)


__all__ = [
    "PluginActionService",
    "PluginActions",
    "UnavailablePluginActions",
]
