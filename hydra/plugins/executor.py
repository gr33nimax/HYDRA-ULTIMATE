"""Configuration, apply and health execution for catalogued plugins."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from hydra.contracts import ConfigFragment, validate_fragment
from hydra.core.apply_transaction import ApplyTransaction
from hydra.core.errors import PluginError
from hydra.core.state_models import AppState
from hydra.plugins.base import BasePlugin
from hydra.plugins.catalog import PluginCatalog
from hydra.plugins.invoker import PluginInvoker


class PluginConfigurationError(PluginError):
    """An enabled plugin could not produce a valid configuration."""

    def __init__(self, plugin_name: str, cause: Exception):
        super().__init__(f"Plugin {plugin_name} configuration failed: {cause}")
        self.plugin_name = plugin_name
        self.__cause__ = cause


@dataclass(frozen=True)
class PluginExecutor:
    """Execute plugin hooks through one version-aware invocation boundary."""

    catalog: PluginCatalog
    invoker: PluginInvoker = field(default_factory=PluginInvoker)

    def collect_fragments(
        self,
        state: AppState,
        *,
        log_error: Callable[[str], None],
    ) -> dict[str, ConfigFragment]:
        fragments: dict[str, ConfigFragment] = {}
        for plugin in self.catalog.enabled(state):
            try:
                fragment = self.invoker.configure(plugin, state)
                validate_fragment(fragment)
                if not fragment.is_empty():
                    fragments[plugin.meta.name] = fragment
            except Exception as exc:
                log_error(
                    f"Error configuring plugin {plugin.meta.name}: {exc}",
                )
                raise PluginConfigurationError(plugin.meta.name, exc) from exc
        return fragments

    def apply_enabled(
        self,
        state: AppState,
        *,
        log_error: Callable[[str], None],
    ) -> list[tuple[BasePlugin, object]]:
        applied: list[tuple[BasePlugin, object]] = []
        transaction = ApplyTransaction()
        transaction.advance("snapshot")

        for plugin in self.catalog.enabled(state):
            if not uses_central_apply(plugin):
                continue
            try:
                snapshot = self.invoker.snapshot(plugin, state)
            except Exception as exc:
                transaction.rollback(log_error)
                raise RuntimeError(
                    f"Plugin {plugin.meta.name} apply failed: {exc}",
                ) from exc

            transaction.add_rollback(
                f"plugin {plugin.meta.name}",
                lambda plugin=plugin, snapshot=snapshot: self.invoker.rollback(
                    plugin,
                    state,
                    snapshot,
                ),
                priority=-(len(applied) + 1),
            )
            transaction.advance("apply")
            try:
                applied_ok = self.invoker.apply(plugin, state)
            except Exception as exc:
                transaction.rollback(log_error)
                raise RuntimeError(
                    f"Plugin {plugin.meta.name} apply failed: {exc}",
                ) from exc
            if not applied_ok:
                transaction.rollback(log_error)
                raise RuntimeError(
                    f"Plugin {plugin.meta.name} apply returned false",
                )
            applied.append((plugin, snapshot))
        transaction.commit()
        return applied

    def rollback(
        self,
        plugin: BasePlugin,
        state: AppState,
        snapshot: object,
    ) -> bool:
        return self.invoker.rollback(plugin, state, snapshot)

    def health_all(self, state: AppState) -> dict[str, str]:
        failures: dict[str, str] = {}
        for plugin in self.catalog.enabled(state):
            if not uses_central_apply(plugin):
                continue
            try:
                health = self.invoker.health(plugin, state)
                healthy, detail = health.healthy, health.detail
            except Exception as exc:
                healthy, detail = False, str(exc) or exc.__class__.__name__
            if not healthy:
                if detail == "service is not active":
                    detail = (
                        "service is not active while enabled in configuration; "
                        f"disable {plugin.meta.name} in the TUI protocol menu"
                    )
                failures[plugin.meta.name] = detail or "проверка не пройдена"
        return failures


def uses_central_apply(plugin: BasePlugin) -> bool:
    """Read the capability while preserving legacy custom plugins."""
    value = getattr(plugin.meta, "central_apply", None)
    return plugin.meta.name != "wdtt" if value is None else value
