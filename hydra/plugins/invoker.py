"""Single invocation boundary for the versioned plugin contract."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hydra.contracts import ConfigFragment
from hydra.plugins.base import (
    BasePlugin,
    HealthResult,
    LifecycleResult,
    PluginStatus,
    lifecycle_result,
)
from hydra.plugins.context import PluginStateAccess
from hydra.core.state_models import User


@dataclass(frozen=True)
class PluginInvoker:
    """Dispatch plugin hooks without leaking call mechanics to services."""

    supported_contract_version: int = 1

    def status(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        self._validate_version(plugin)
        return plugin.status(state)

    def configure(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess,
    ) -> ConfigFragment:
        self._validate_version(plugin)
        return plugin.configure(state)

    def snapshot(self, plugin: BasePlugin, state: PluginStateAccess) -> Any:
        self._validate_version(plugin)
        callback = getattr(plugin, "snapshot", None)
        return callback(state) if callable(callback) else None

    def apply(self, plugin: BasePlugin, state: PluginStateAccess) -> bool:
        self._validate_version(plugin)
        return bool(plugin.apply(state))

    def rollback(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess,
        snapshot: Any,
    ) -> bool:
        self._validate_version(plugin)
        callback = getattr(plugin, "rollback", None)
        return bool(callback(state, snapshot)) if callable(callback) else True

    def health(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess | None = None,
    ) -> HealthResult:
        self._validate_version(plugin)
        health_result = getattr(plugin, "health_result", None)
        if callable(health_result):
            return health_result(state)
        result = plugin.healthcheck()
        if isinstance(result, tuple):
            healthy, detail = result
            return HealthResult(
                bool(healthy),
                str(detail or ""),
                "ok" if healthy else "error",
            )
        return result

    def traffic(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess,
    ) -> dict[str, int]:
        self._validate_version(plugin)
        return plugin.traffic(state)

    def traffic_snapshot(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess,
    ) -> dict[str, int] | None:
        self._validate_version(plugin)
        return plugin.traffic_snapshot(state)

    def aggregate_traffic_snapshot(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess,
    ) -> int | None:
        self._validate_version(plugin)
        return plugin.aggregate_traffic_snapshot(state)

    def ingest_traffic(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess,
        cursors: dict,
    ) -> None:
        self._validate_version(plugin)
        plugin.ingest_traffic(state, cursors)

    def connected_clients(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess | None = None,
    ) -> list[dict]:
        self._validate_version(plugin)
        return plugin.connected_clients(state)

    def generate_client_config(
        self,
        plugin: BasePlugin,
        user: User,
        state: PluginStateAccess,
        **kwargs: Any,
    ) -> str:
        self._validate_version(plugin)
        return plugin.generate_client_config(user, state, **kwargs)

    def client_link(
        self,
        plugin: BasePlugin,
        user: User,
        state: PluginStateAccess,
        **kwargs: Any,
    ) -> str:
        self._validate_version(plugin)
        return plugin.client_link(user, state, **kwargs)

    def client_links(
        self,
        plugin: BasePlugin,
        user: User,
        state: PluginStateAccess,
        **kwargs: Any,
    ) -> list[str]:
        self._validate_version(plugin)
        return plugin.client_links(user, state, **kwargs)

    def lifecycle(
        self,
        plugin: BasePlugin,
        operation: str,
        state: PluginStateAccess | None = None,
    ) -> LifecycleResult:
        self._validate_version(plugin)
        return lifecycle_result(plugin, operation, state)

    def user_add(
        self,
        plugin: BasePlugin,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        self._validate_version(plugin)
        plugin.on_user_add(user, state)

    def user_remove(
        self,
        plugin: BasePlugin,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        self._validate_version(plugin)
        plugin.on_user_remove(user, state)

    def user_block(
        self,
        plugin: BasePlugin,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        self._validate_version(plugin)
        plugin.on_user_block(user, state)

    def command(
        self,
        plugin: BasePlugin,
        state: PluginStateAccess,
        command: str,
        **parameters: Any,
    ) -> bool:
        """Invoke one application-authorized desired-state mutation."""
        self._validate_version(plugin)
        handler = getattr(plugin, command, None)
        if not callable(handler):
            raise ValueError(
                f"plugin {plugin.meta.name} does not implement command {command}",
            )
        return bool(handler(state=state, **parameters))

    def query(
        self,
        plugin: BasePlugin,
        query: str,
        **parameters: Any,
    ) -> Any:
        """Invoke one application-authorized public plugin projection."""
        self._validate_version(plugin)
        if query.startswith("_"):
            raise ValueError(f"private plugin query is forbidden: {query}")
        handler = getattr(plugin, query, None)
        if not callable(handler):
            raise ValueError(
                f"plugin {plugin.meta.name} does not implement query {query}",
            )
        return handler(**parameters)

    def action(
        self,
        plugin: BasePlugin,
        action: str,
        **parameters: Any,
    ) -> Any:
        """Invoke one application-authorized public runtime action."""
        self._validate_version(plugin)
        if action.startswith("_"):
            raise ValueError(f"private plugin action is forbidden: {action}")
        handler = getattr(plugin, action, None)
        if not callable(handler):
            raise ValueError(
                f"plugin {plugin.meta.name} does not implement action {action}",
            )
        return handler(**parameters)

    def _validate_version(self, plugin: BasePlugin) -> None:
        meta = getattr(plugin, "meta", None)
        version = getattr(meta, "contract_version", 1)
        if not isinstance(version, int):
            # Legacy/custom plugins and loose test doubles predate this field.
            version = 1
        if version != self.supported_contract_version:
            name = getattr(meta, "name", plugin.__class__.__name__)
            raise ValueError(
                f"unsupported plugin contract v{version}: {name}",
            )
