"""Composition-owned plugin collection.

Production code receives this object explicitly.  The legacy ``registry``
module remains a compatibility facade, but no application use-case needs a
process-global plugin list.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from hydra.contracts import BackupResource, ConfigFragment
from hydra.core.state_models import AppState
from hydra.plugins.base import BasePlugin, PluginCategory
from hydra.plugins.catalog import PluginCatalog
from hydra.plugins.executor import PluginExecutor


def _ignore_error(_message: str) -> None:
    return None


@dataclass(frozen=True)
class PluginContainer:
    """Validated catalog and executor sharing the same plugin instances."""

    plugins: Sequence[BasePlugin]
    host: Any
    log_error: Callable[[str], None] = _ignore_error
    catalog: PluginCatalog = field(init=False)
    executor: PluginExecutor = field(init=False)

    def __post_init__(self) -> None:
        stable_plugins = list(self.plugins)
        names = [plugin.meta.name for plugin in stable_plugins]
        duplicates = sorted(
            name
            for name in set(names)
            if names.count(name) > 1
        )
        if duplicates:
            raise ValueError(
                f"duplicate plugin names: {', '.join(duplicates)}",
            )
        catalog = PluginCatalog(stable_plugins)
        catalog.validate_contracts()
        object.__setattr__(self, "plugins", tuple(stable_plugins))
        object.__setattr__(self, "catalog", catalog)
        object.__setattr__(self, "executor", PluginExecutor(catalog))

    def all_plugins(self) -> list[BasePlugin]:
        return list(self.plugins)

    def get(self, name: str) -> BasePlugin | None:
        return self.catalog.get(name)

    def transports(self) -> list[BasePlugin]:
        return self.catalog.category(PluginCategory.TRANSPORT)

    def enhancements(self) -> list[BasePlugin]:
        return self.catalog.category(PluginCategory.ENHANCEMENT)

    def security(self) -> list[BasePlugin]:
        return self.catalog.category(PluginCategory.SECURITY)

    def enabled(
        self,
        state: AppState,
        category: PluginCategory | None = None,
    ) -> list[BasePlugin]:
        return self.catalog.enabled(state, category)

    def status_all(
        self,
        state: AppState | None = None,
    ) -> dict[str, dict]:
        return self.catalog.status_all(state)

    def collect_fragments(
        self,
        state: AppState,
    ) -> dict[str, ConfigFragment]:
        return self.executor.collect_fragments(
            state,
            log_error=self.log_error,
        )

    def apply_enabled(
        self,
        state: AppState,
    ) -> list[tuple[BasePlugin, object]]:
        return self.executor.apply_enabled(
            state,
            log_error=self.log_error,
        )

    def rollback(
        self,
        plugin: BasePlugin,
        state: AppState,
        snapshot: object,
    ) -> bool:
        return self.executor.rollback(plugin, state, snapshot)

    def health_all(self, state: AppState) -> dict[str, str]:
        return self.executor.health_all(state)

    def requirements(
        self,
        state: AppState,
    ) -> dict[str, dict[str, list[str]]]:
        return self.catalog.requirements(state, host=self.host)

    def backup_resources(self) -> tuple[BackupResource, ...]:
        return self.catalog.backup_resources()


__all__ = ["PluginContainer"]
