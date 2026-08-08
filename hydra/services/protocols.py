"""Application service boundary for protocol and plugin management."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from hydra.core.state_models import AppState, User
from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.plugins.base import BasePlugin, PluginCategory
from hydra.plugins.invoker import PluginInvoker
from hydra.services.reconciliation import ReconciliationService


class ProtocolOperations(Protocol):
    def install_plugin(self, state: AppState, name: str) -> bool: ...
    def reinstall_plugin(self, state: AppState, name: str) -> bool: ...
    def uninstall_plugin(self, state: AppState, name: str) -> bool: ...
    def activate_plugin(
        self,
        state: AppState,
        name: str,
        *,
        domain: str | None = None,
    ) -> bool: ...
    def enable(self, state: AppState, name: str) -> bool: ...
    def disable(self, state: AppState, name: str) -> bool: ...


class ProtocolCatalog(Protocol):
    def get(self, name: str) -> BasePlugin | None: ...
    def transports(self) -> list[BasePlugin]: ...
    def enhancements(self) -> list[BasePlugin]: ...
    def security(self) -> list[BasePlugin]: ...
    def status_all(self, state: AppState | None = None) -> dict[str, dict[str, Any]]: ...


@dataclass(frozen=True)
class MaintenanceJob:
    """Adapter-neutral projection of one plugin-declared scheduled task."""

    plugin_name: str
    action: str
    title: str
    description: str
    due_query: str
    enabled_flag: str
    apply_on_success: bool


@dataclass(frozen=True)
class ManualClientArtifact:
    """Admin-only client artifact declared by a plugin query."""

    plugin_name: str
    display_name: str
    profile_name: str
    profile_label: str
    config: str
    links: tuple[str, ...]


def _manual_client_artifact(
    plugin: BasePlugin,
    value: object,
) -> ManualClientArtifact | None:
    if not isinstance(value, dict):
        return None
    raw_links = value.get("links", ())
    if isinstance(raw_links, str):
        raw_links = (raw_links,)
    if not isinstance(raw_links, (list, tuple)):
        return None
    links = tuple(
        dict.fromkeys(
            link.strip()
            for link in raw_links
            if isinstance(link, str) and link.strip()
        ),
    )
    config = str(value.get("config", "") or "")
    if not config and not links:
        return None
    return ManualClientArtifact(
        plugin_name=plugin.meta.name,
        display_name=plugin.meta.display_name or plugin.meta.name,
        profile_name=str(value.get("profile_name", "") or ""),
        profile_label=str(value.get("profile_label", "") or ""),
        config=config,
        links=links,
    )


@dataclass(frozen=True)
class ProtocolService:
    """Stable facade shared by CLI and future remote management transports."""

    operations: ProtocolOperations
    catalog: ProtocolCatalog
    invoker: PluginInvoker = field(default_factory=PluginInvoker)
    state_reader: Callable[[], AppState] | None = None

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

    def require(self, name: str) -> BasePlugin:
        plugin = self.get(name)
        if plugin is None:
            raise ValueError(f"unknown plugin: {name}")
        return plugin

    def display_name(self, name: str) -> str:
        plugin = self.get(name)
        if plugin is None:
            return name
        return plugin.meta.display_name or plugin.meta.name

    def status(self, name: str, state: AppState | None = None):
        """Read one plugin's runtime status through the contract boundary."""
        if state is None and self.state_reader is not None:
            state = self.state_reader()
        return self.invoker.status(self.require(name), state)

    def health(self, state: AppState, name: str):
        """Read one plugin's state-aware health through the contract boundary."""
        return self.invoker.health(self.require(name), state)

    def apply_runtime(self, state: AppState, name: str) -> bool:
        """Apply plugin-owned runtime artifacts without bypassing its contract."""
        return self.invoker.apply(self.require(name), state)

    def traffic(self, state: AppState, name: str) -> dict[str, int]:
        return self.invoker.traffic(self.require(name), state)

    def traffic_snapshot(
        self,
        state: AppState,
        name: str,
    ) -> dict[str, int] | None:
        return self.invoker.traffic_snapshot(
            self.require(name),
            state,
        )

    def aggregate_traffic_snapshot(
        self,
        state: AppState,
        name: str,
    ) -> int | None:
        return self.invoker.aggregate_traffic_snapshot(
            self.require(name),
            state,
        )

    def ingest_traffic(
        self,
        state: AppState,
        name: str,
        cursors: dict,
    ) -> None:
        self.invoker.ingest_traffic(
            self.require(name),
            state,
            cursors,
        )

    def connected_clients(
        self,
        state: AppState,
        name: str,
    ) -> list[dict]:
        return self.invoker.connected_clients(self.require(name), state)

    def connection_activity(
        self,
        state: AppState,
        name: str,
    ) -> list[dict]:
        """Read the plugin-declared active/recent connection projection."""
        plugin = self.require(name)
        source = plugin.meta.capabilities.connection_source
        if source in {"tracked", "none"}:
            return []
        if source == "plugin":
            return self.invoker.connected_clients(plugin, state)
        return list(self.invoker.query(plugin, source, state=state) or [])

    def client_config(
        self,
        state: AppState,
        name: str,
        user: User,
        **parameters: object,
    ) -> str:
        return self.invoker.generate_client_config(
            self.require(name),
            user,
            state,
            **parameters,
        )

    def client_link(
        self,
        state: AppState,
        name: str,
        user: User,
        **parameters: object,
    ) -> str:
        return self.invoker.client_link(
            self.require(name),
            user,
            state,
            **parameters,
        )

    def client_links(
        self,
        state: AppState,
        name: str,
        user: User,
        **parameters: object,
    ) -> list[str]:
        return self.invoker.client_links(
            self.require(name),
            user,
            state,
            **parameters,
        )

    def client_profiles(
        self,
        state: AppState,
        name: str,
    ) -> list[dict[str, Any]]:
        """Return optional named client profiles without leaking plugin objects."""
        plugin = self.require(name)
        query = plugin.meta.capabilities.subscription_profile_query
        if not query:
            return []
        return list(self.invoker.query(plugin, query, state=state) or [])

    def enabled(
        self,
        state: AppState,
        category: PluginCategory | None = None,
    ) -> list[BasePlugin]:
        return [
            plugin
            for plugin in self.list(category)
            if state.protocols.get(plugin.meta.name)
            and state.protocols[plugin.meta.name].enabled
        ]

    def enabled_names(
        self,
        state: AppState,
        category: PluginCategory | None = None,
    ) -> set[str]:
        """Return desired enabled plugin names without exposing the catalog."""
        return {plugin.meta.name for plugin in self.enabled(state, category)}

    def enabled_subscription_names(
        self,
        state: AppState,
        category: PluginCategory | None = PluginCategory.TRANSPORT,
    ) -> set[str]:
        """Return enabled plugins that expose per-user client artifacts."""
        return {
            plugin.meta.name
            for plugin in self.enabled(state, category)
            if plugin.meta.capabilities.subscription_enabled
        }

    def manual_client_artifacts(
        self,
        state: AppState,
        category: PluginCategory | None = PluginCategory.TRANSPORT,
    ) -> list[ManualClientArtifact]:
        """Return admin-only artifacts independently from subscriptions."""
        artifacts: list[ManualClientArtifact] = []
        for plugin in self.enabled(state, category):
            query = plugin.meta.capabilities.manual_artifacts_query
            if not query:
                continue
            try:
                values = self.invoker.query(plugin, query, state=state) or []
            except Exception:
                continue
            for value in values if isinstance(values, (list, tuple)) else ():
                artifact = _manual_client_artifact(plugin, value)
                if artifact is not None:
                    artifacts.append(artifact)
        return artifacts

    def maintenance_jobs(self) -> list[MaintenanceJob]:
        """Expose scheduled plugin work without leaking plugin instances."""
        return [
            MaintenanceJob(
                plugin_name=plugin.meta.name,
                action=task.action,
                title=task.title,
                description=task.description,
                due_query=task.due_query,
                enabled_flag=task.enabled_flag,
                apply_on_success=task.apply_on_success,
            )
            for plugin in self.list()
            for task in plugin.meta.capabilities.maintenance_tasks
        ]

    def aggregate_traffic(self, state: AppState, name: str) -> int | None:
        """Read an optional protocol-wide counter through the plugin boundary."""
        plugin = self.require(name)
        reader = getattr(plugin, "total_traffic", None)
        if not callable(reader):
            return None
        value = self.invoker.query(plugin, "total_traffic", state=state)
        return None if value is None else max(0, int(value))

    def notify_user_block(self, state: AppState, user) -> list[str]:
        failures: list[str] = []
        for plugin in self.enabled(state):
            try:
                self.invoker.user_block(plugin, user, state)
            except Exception as exc:
                failures.append(
                    f"{plugin.meta.name}: {str(exc) or exc.__class__.__name__}",
                )
        return failures

    def statuses(self, state: AppState | None = None) -> dict[str, dict[str, Any]]:
        if state is None and self.state_reader is not None:
            state = self.state_reader()
        return (
            self.catalog.status_all(state)
            if state is not None
            else self.catalog.status_all()
        )

    def inventory(
        self,
        state: AppState,
        *,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return a JSON-safe plugin catalog projection for management adapters."""
        selected: PluginCategory | None = None
        if category is not None:
            try:
                selected = PluginCategory(category)
            except ValueError as exc:
                raise ValueError(f"unknown plugin category: {category}") from exc
        statuses = self.statuses(state)
        inventory: list[dict[str, Any]] = []
        for plugin in self.list(selected):
            meta = plugin.meta
            inventory.append(
                {
                    "name": meta.name,
                    "display_name": meta.display_name or meta.name,
                    "description": meta.description,
                    "category": meta.category.value,
                    "version": meta.version,
                    "contract_version": meta.contract_version,
                    "capabilities": meta.capabilities.as_dict(),
                    "status": statuses.get(meta.name, {}),
                },
            )
        return inventory

    def install(self, state: AppState, name: str) -> bool:
        return self.operations.install_plugin(state, name)

    def lifecycle_result(self, state: AppState, operation: str, name: str) -> ServiceResult:
        """Normalize legacy bool lifecycle operations for all adapters."""
        try:
            callback = getattr(self, operation)
            ok = bool(callback(state, name))
            if ok:
                return ServiceResult(True, value={"operation": operation, "name": name})
            return failed_result(
                RuntimeError(f"{operation} failed for {name}"),
                fallback=ErrorCode.OPERATION_FAILED,
            )
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.PLUGIN)

    def reinstall(self, state: AppState, name: str) -> bool:
        return self.operations.reinstall_plugin(state, name)

    def uninstall(self, state: AppState, name: str) -> bool:
        return self.operations.uninstall_plugin(state, name)

    def activate(
        self,
        state: AppState,
        name: str,
        *,
        domain: str | None = None,
    ) -> bool:
        """Install and enable a protocol with staged activation input."""
        return self.operations.activate_plugin(
            state,
            name,
            domain=domain,
        )

    def enable(self, state: AppState, name: str) -> bool:
        return self.operations.enable(state, name)

    def disable(self, state: AppState, name: str) -> bool:
        return self.operations.disable(state, name)

    def reconciliation(self) -> ReconciliationService:
        return ReconciliationService(self)
