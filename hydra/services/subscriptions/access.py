"""Explicit plugin boundary used by subscription generation."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from hydra.core.state_models import AppState, User
from hydra.plugins.base import BasePlugin, PluginCategory, PluginStatus
from hydra.plugins.invoker import PluginInvoker


class SubscriptionPluginAccess(Protocol):
    """Narrow read-only plugin capabilities needed by subscriptions."""

    def enabled_transports(self, state: AppState) -> Sequence[BasePlugin]: ...

    def get(self, name: str) -> BasePlugin | None: ...

    def status(
        self,
        plugin: BasePlugin,
        state: AppState,
    ) -> PluginStatus: ...

    def client_link(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> str: ...

    def client_links(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> list[str]: ...

    def client_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> str: ...

    def singbox_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
    ) -> str: ...

    def profiles(
        self,
        plugin: BasePlugin,
        state: AppState,
    ) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class SubscriptionPluginService:
    """Adapt an application-owned protocol catalog to subscription reads."""

    enabled_plugins: Callable[
        [AppState, PluginCategory | None],
        Sequence[BasePlugin],
    ]
    get_plugin: Callable[[str], BasePlugin | None]
    invoker: PluginInvoker = field(default_factory=PluginInvoker)

    def enabled_transports(self, state: AppState) -> Sequence[BasePlugin]:
        return self.enabled_plugins(state, PluginCategory.TRANSPORT)

    def get(self, name: str) -> BasePlugin | None:
        return self.get_plugin(name)

    def status(
        self,
        plugin: BasePlugin,
        state: AppState,
    ) -> PluginStatus:
        return self.invoker.status(plugin, state)

    def client_link(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> str:
        return self.invoker.client_link(plugin, user, state, **parameters)

    def client_links(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> list[str]:
        return self.invoker.client_links(plugin, user, state, **parameters)

    def client_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> str:
        return self.invoker.generate_client_config(
            plugin,
            user,
            state,
            **parameters,
        )

    def singbox_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
    ) -> str:
        return self.invoker.generate_singbox_config(plugin, user, state)

    def profiles(
        self,
        plugin: BasePlugin,
        state: AppState,
    ) -> list[dict[str, Any]]:
        query = plugin.meta.capabilities.subscription_profile_query
        if not query:
            return []
        profiles = self.invoker.query(plugin, query, state=state)
        return list(profiles or [])
