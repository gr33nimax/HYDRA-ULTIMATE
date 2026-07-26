"""Allowlisted read-only queries for plugin-specific application views."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from hydra.plugins.base import BasePlugin
from hydra.plugins.invoker import PluginInvoker


class PluginQueries(Protocol):
    def execute(
        self,
        plugin_name: str,
        query: str,
        **parameters: object,
    ) -> Any: ...


@dataclass(frozen=True)
class UnavailablePluginQueries:
    def execute(
        self,
        plugin_name: str,
        query: str,
        **parameters: object,
    ) -> Any:
        raise RuntimeError("plugin query service is unavailable")


@dataclass(frozen=True)
class PluginQueryService:
    """Expose narrow plugin-owned projections without leaking plugin objects."""

    get_plugin: Callable[[str], BasePlugin | None]
    invoker: PluginInvoker = field(default_factory=PluginInvoker)
    queries: Mapping[str, frozenset[str]] | None = None

    def execute(
        self,
        plugin_name: str,
        query: str,
        **parameters: object,
    ) -> Any:
        if query.startswith("_"):
            raise ValueError(
                f"unsupported plugin query: {plugin_name}.{query}",
            )
        plugin = self.get_plugin(plugin_name)
        if plugin is None:
            raise ValueError(f"unknown plugin: {plugin_name}")
        allowed = (
            self.queries.get(plugin_name, frozenset())
            if self.queries is not None
            else frozenset(plugin.meta.capabilities.queries)
        )
        if query not in allowed:
            raise ValueError(
                f"unsupported plugin query: {plugin_name}.{query}",
            )
        return self.invoker.query(plugin, query, **parameters)


__all__ = [
    "PluginQueries",
    "PluginQueryService",
    "UnavailablePluginQueries",
]
