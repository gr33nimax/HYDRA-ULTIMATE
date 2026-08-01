"""Plugin discovery and read-only catalog queries."""
from __future__ import annotations

from dataclasses import dataclass, field
from dataclasses import replace
from typing import Any

from hydra.contracts import BackupResource
from hydra.core.state_models import AppState
from hydra.plugins.base import BasePlugin, PluginCategory, PluginStatus
from hydra.plugins.invoker import PluginInvoker
from hydra.plugins.runtime import assess


@dataclass(frozen=True)
class PluginCatalog:
    """Stable plugin instances plus filtering and status queries."""

    plugins: list[BasePlugin]
    invoker: PluginInvoker = field(default_factory=PluginInvoker)

    def all(self) -> list[BasePlugin]:
        return self.plugins

    def get(self, name: str) -> BasePlugin | None:
        return next(
            (plugin for plugin in self.plugins if plugin.meta.name == name),
            None,
        )

    def category(self, category: PluginCategory) -> list[BasePlugin]:
        return [
            plugin
            for plugin in self.plugins
            if plugin.meta.category == category
        ]

    def enabled(
        self,
        state: AppState,
        category: PluginCategory | None = None,
    ) -> list[BasePlugin]:
        pool = (
            self.plugins
            if category is None
            else self.category(category)
        )
        return [
            plugin
            for plugin in pool
            if state.protocols.get(plugin.meta.name)
            and state.protocols[plugin.meta.name].enabled
        ]

    def contract_errors(self, plugin: BasePlugin) -> list[str]:
        errors: list[str] = []
        meta = getattr(plugin, "meta", None)
        if meta is None:
            return ["missing meta"]
        if not isinstance(meta.name, str) or not meta.name.strip():
            errors.append("meta.name must be a non-empty string")
        if not isinstance(meta.description, str):
            errors.append("meta.description must be a string")
        if not isinstance(meta.display_name, str):
            errors.append("meta.display_name must be a string")
        if not isinstance(meta.version, str) or not meta.version.strip():
            errors.append("meta.version must be a non-empty string")
        if not isinstance(meta.contract_version, int) or meta.contract_version < 1:
            errors.append("meta.contract_version must be a positive integer")
        capabilities = meta.capabilities
        for field_name in (
            "required_commands",
            "required_services",
            "conflicts_with",
            "commands",
            "persist_only_commands",
            "queries",
            "actions",
        ):
            values = getattr(capabilities, field_name)
            if any(
                not isinstance(value, str) or not value.strip()
                for value in values
            ):
                errors.append(
                    f"meta.{field_name} must contain non-empty strings",
                )
            if len(values) != len(set(values)):
                errors.append(f"meta.{field_name} contains duplicates")
            if field_name in {"commands", "queries", "actions"}:
                for value in values:
                    if value.startswith("_"):
                        errors.append(
                            f"meta.{field_name} cannot expose "
                            f"private method {value}",
                        )
                    elif not callable(getattr(plugin, value, None)):
                        errors.append(
                            f"meta.{field_name} declares "
                            f"missing method {value}()",
                        )
        if any(
            command not in capabilities.commands
            for command in capabilities.persist_only_commands
        ):
            errors.append(
                "meta.persist_only_commands must be declared in commands",
            )
        if capabilities.tls_domain_source not in {
            "",
            "network",
            "protocol",
        }:
            errors.append(
                "meta.tls_domain_source must be '', 'network' or 'protocol'",
            )
        default_names = [
            key
            for key, _value in capabilities.config_defaults
            if isinstance(key, str)
        ]
        if (
            len(default_names) != len(capabilities.config_defaults)
            or len(default_names) != len(set(default_names))
        ):
            errors.append(
                "meta.config_defaults must have unique string keys",
            )
        profile_query = capabilities.subscription_profile_query
        if (
            profile_query
            and profile_query not in capabilities.queries
        ):
            errors.append(
                "meta.subscription_profile_query must be a declared query",
            )
        manual_query = capabilities.manual_artifacts_query
        if manual_query and manual_query not in capabilities.queries:
            errors.append(
                "meta.manual_artifacts_query must be a declared query",
            )
        connection_source = capabilities.connection_source
        if connection_source not in {"plugin", "tracked", "none"} and (
            connection_source not in capabilities.queries
        ):
            errors.append(
                "meta.connection_source must be 'plugin', 'tracked', "
                "'none' or a declared query",
            )
        maintenance_actions: list[str] = []
        for task in capabilities.maintenance_tasks:
            if not isinstance(task.action, str) or not task.action.strip():
                errors.append(
                    "meta.maintenance_tasks actions must be non-empty strings",
                )
                continue
            maintenance_actions.append(task.action)
            if task.action not in capabilities.actions:
                errors.append(
                    "meta.maintenance_tasks action must be declared in actions",
                )
            if task.due_query and task.due_query not in capabilities.queries:
                errors.append(
                    "meta.maintenance_tasks due_query must be declared in queries",
                )
            if not task.title.strip():
                errors.append(
                    "meta.maintenance_tasks title must be a non-empty string",
                )
            if not task.enabled_flag.strip():
                errors.append(
                    "meta.maintenance_tasks enabled_flag must be a non-empty string",
                )
        if len(maintenance_actions) != len(set(maintenance_actions)):
            errors.append("meta.maintenance_tasks contains duplicate actions")
        backup_paths: list[str] = []
        for resource in capabilities.backup_resources:
            path = str(resource.path).replace("\\", "/")
            if (
                not path
                or not (path.startswith("/") or ":/" in path)
                or path.rstrip("/") in {"", "/etc", "/var", "/usr", "/home", "/root"}
            ):
                errors.append(
                    "meta.backup_resources paths must be absolute and scoped",
                )
            if resource.kind not in {"file", "tree"}:
                errors.append(
                    "meta.backup_resources kind must be 'file' or 'tree'",
                )
            backup_paths.append(path.rstrip("/"))
        if len(backup_paths) != len(set(backup_paths)):
            errors.append("meta.backup_resources contains duplicate paths")
        for method_name in (
            "install",
            "uninstall",
            "install_result",
            "uninstall_result",
            "enable_result",
            "disable_result",
            "status",
            "configure",
            "health_result",
            "snapshot",
            "rollback",
        ):
            if not callable(getattr(plugin, method_name, None)):
                errors.append(f"missing {method_name}()")
        return errors

    def backup_resources(self) -> tuple[BackupResource, ...]:
        """Return plugin-owned resources labeled by their trusted owner."""
        return tuple(
            replace(
                resource,
                owner=resource.owner or plugin.meta.name,
            )
            for plugin in self.plugins
            for resource in plugin.meta.capabilities.backup_resources
        )

    def validate_contracts(self) -> None:
        violations = {
            plugin.meta.name: errors
            for plugin in self.plugins
            if (errors := self.contract_errors(plugin))
        }
        if violations:
            raise ValueError(f"plugin contract violations: {violations}")

    def status_all(self, state: AppState | None = None) -> dict[str, dict]:
        result: dict[str, dict] = {}
        for plugin in self.plugins:
            try:
                status = self.invoker.status(plugin, state)
                desired_enabled = self._desired_enabled(
                    state,
                    plugin.meta.name,
                    status.enabled,
                )
                result[plugin.meta.name] = {
                    "running": status.running,
                    "installed": status.installed,
                    "port": status.port,
                    "enabled": status.enabled,
                    "error": "",
                    **assess(status, desired_enabled).as_dict(),
                }
            except Exception as exc:
                detail = str(exc) or exc.__class__.__name__
                desired_enabled = self._desired_enabled(
                    state,
                    plugin.meta.name,
                    False,
                )
                result[plugin.meta.name] = {
                    "running": False,
                    "installed": False,
                    "port": 0,
                    "enabled": False,
                    "error": detail,
                    **assess(
                        PluginStatus(False, False, False),
                        desired_enabled,
                        detail,
                    ).as_dict(),
                }
        return result

    def requirements(
        self,
        state: AppState,
        *,
        host: Any,
    ) -> dict[str, dict[str, list[str]]]:
        active = self.enabled(state)
        active_names = {plugin.meta.name for plugin in active}
        result: dict[str, dict[str, list[str]]] = {}
        for plugin in active:
            missing = sorted(
                command
                for command in plugin.meta.required_commands
                if host.which(command) is None
            )
            conflicts = sorted(
                name
                for name in plugin.meta.conflicts_with
                if name in active_names
            )
            if missing or conflicts:
                result[plugin.meta.name] = {
                    "missing_commands": missing,
                    "conflicts": conflicts,
                }
        return result

    @staticmethod
    def _desired_enabled(
        state: AppState | None,
        name: str,
        default: bool,
    ) -> bool:
        if state is None:
            return default
        protocol = state.protocols.get(name)
        return protocol.enabled if protocol else default
