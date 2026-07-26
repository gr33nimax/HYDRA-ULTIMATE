"""Application orchestration for complete HYDRA removal."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from hydra.core.state_models import AppState
from hydra.core.uninstall import (
    uninstall_hydra as remove_host_installation,
    uninstall_plan,
)
from hydra.plugins.invoker import PluginInvoker


class UninstallOperations(Protocol):
    """Application port used by management adapters."""

    def plan(self, state: AppState, *, keep_data: bool = False) -> dict: ...

    def uninstall(
        self,
        state: AppState,
        *,
        confirmed: bool,
        dry_run: bool = False,
        keep_data: bool = False,
    ) -> dict: ...


@dataclass(frozen=True)
class UnavailableUninstallOperations:
    """Default for applications assembled without destructive host access."""

    def plan(self, state: AppState, *, keep_data: bool = False) -> dict:
        del state, keep_data
        raise RuntimeError("uninstall service is unavailable")

    def uninstall(
        self,
        state: AppState,
        *,
        confirmed: bool,
        dry_run: bool = False,
        keep_data: bool = False,
    ) -> dict:
        del state, confirmed, dry_run, keep_data
        raise RuntimeError("uninstall service is unavailable")


@dataclass(frozen=True)
class CleanupStep:
    """One composition-owned cleanup outside the plugin lifecycle contract."""

    name: str
    callback: Callable[[], object]


@dataclass(frozen=True)
class UninstallService:
    """Remove auxiliary rules, plugins, and finally shared host resources."""

    plugin_inventory: Callable[[], Iterable[Any]]
    cleanup_steps: tuple[CleanupStep, ...] = ()
    invoker: PluginInvoker = field(default_factory=PluginInvoker)
    remove_installation: Callable[..., dict] = remove_host_installation

    def plan(self, state: AppState, *, keep_data: bool = False) -> dict:
        plugins = tuple(self.plugin_inventory())
        return uninstall_plan(
            state,
            keep_data=keep_data,
            plugin_names=self._ordered_plugin_names(plugins),
        )

    def uninstall(
        self,
        state: AppState,
        *,
        confirmed: bool,
        dry_run: bool = False,
        keep_data: bool = False,
    ) -> dict:
        plugins = tuple(self.plugin_inventory())
        plugin_names = self._ordered_plugin_names(plugins)
        plan = uninstall_plan(
            state,
            keep_data=keep_data,
            plugin_names=plugin_names,
        )
        if dry_run:
            return {"ok": True, "dry_run": True, **plan}
        if not confirmed:
            raise ValueError(
                "uninstall requires --yes; use --dry-run to inspect the plan",
            )

        failures: list[str] = []
        for cleanup in self.cleanup_steps:
            try:
                cleanup.callback()
            except Exception as exc:
                failures.append(f"{cleanup.name}: {exc}")

        for plugin in reversed(plugins):
            name = self._plugin_name(plugin)
            try:
                if not self.invoker.lifecycle(plugin, "uninstall"):
                    failures.append(f"plugin {name}: returned false")
            except Exception as exc:
                failures.append(f"plugin {name}: {exc}")

        return self.remove_installation(
            state,
            confirmed=True,
            dry_run=False,
            keep_data=keep_data,
            plugin_names=plugin_names,
            initial_failures=failures,
        )

    @classmethod
    def _ordered_plugin_names(cls, plugins: tuple[Any, ...]) -> list[str]:
        return [cls._plugin_name(plugin) for plugin in reversed(plugins)]

    @staticmethod
    def _plugin_name(plugin: Any) -> str:
        meta = getattr(plugin, "meta", None)
        return str(getattr(meta, "name", plugin.__class__.__name__))


__all__ = [
    "CleanupStep",
    "UnavailableUninstallOperations",
    "UninstallOperations",
    "UninstallService",
]
