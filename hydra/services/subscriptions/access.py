"""Explicit plugin boundary used by subscription generation."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from hydra.core.configuration_names import (
    apply_json_configuration_name,
    configuration_name_key,
    user_with_configuration_names,
)
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

    def singbox_client_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        *,
        apply_name: bool = True,
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
        named_user = user_with_configuration_names(
            user,
            state.configuration_names,
        )
        return self.invoker.client_link(
            plugin,
            named_user if plugin.meta.name == "trusttunnel" else user,
            state,
            **parameters,
        )

    def client_links(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> list[str]:
        named_user = user_with_configuration_names(
            user,
            state.configuration_names,
        )
        return self.invoker.client_links(
            plugin,
            named_user if plugin.meta.name == "trusttunnel" else user,
            state,
            **parameters,
        )

    def client_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        **parameters: Any,
    ) -> str:
        named_user = user_with_configuration_names(
            user,
            state.configuration_names,
        )
        payload = self.invoker.generate_client_config(
            plugin,
            named_user if plugin.meta.name == "trusttunnel" else user,
            state,
            **parameters,
        )
        return apply_json_configuration_name(
            payload,
            key=configuration_name_key(plugin.meta.name, parameters),
            global_names=state.configuration_names,
            user_names=user.configuration_name_overrides,
        ) if plugin.meta.name != "trusttunnel" else payload

    def singbox_client_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        *,
        apply_name: bool = True,
    ) -> str:
        named_user = user_with_configuration_names(
            user,
            state.configuration_names,
        )
        payload = self.invoker.generate_singbox_client_config(
            plugin,
            named_user if apply_name and plugin.meta.name == "trusttunnel" else user,
            state,
        )
        return apply_json_configuration_name(
            payload,
            key=plugin.meta.name,
            global_names=state.configuration_names,
            user_names=user.configuration_name_overrides,
        ) if apply_name and plugin.meta.name != "trusttunnel" else payload

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
