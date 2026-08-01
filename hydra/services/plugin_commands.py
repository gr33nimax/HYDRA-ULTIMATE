"""Transactional application boundary for plugin-specific settings."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol

from hydra.core.state_models import AppState
from hydra.plugins.base import BasePlugin
from hydra.plugins.invoker import PluginInvoker
from hydra.services.configuration import restore_state_in_place


class PluginCommands(Protocol):
    def execute(
        self,
        state: AppState,
        plugin_name: str,
        command: str,
        **parameters: object,
    ) -> bool: ...


@dataclass(frozen=True)
class UnavailablePluginCommands:
    """Safe default for manually assembled application facades."""

    def execute(
        self,
        state: AppState,
        plugin_name: str,
        command: str,
        **parameters: object,
    ) -> bool:
        raise RuntimeError("plugin command service is unavailable")


@dataclass(frozen=True)
class PluginCommandService:
    """Mutate desired plugin state, then persist or apply it atomically."""

    get_plugin: Callable[[str], BasePlugin | None]
    apply_config: Callable[[AppState], bool]
    save_state: Callable[[AppState], None]
    # A rollback must land even when a background writer moved the revision;
    # facades without the dedicated restore fall back to a plain save.
    restore_state: Callable[[AppState], object] | None = None
    invoker: PluginInvoker = field(default_factory=PluginInvoker)
    prepare_apply: Callable[[AppState, str], None] = lambda state, name: None
    commands: Mapping[str, frozenset[str]] | None = None

    def _persist_rollback(self, state: AppState) -> None:
        """Persist a restored snapshot without failing on a stale revision."""
        if self.restore_state is None:
            self.save_state(state)
            return
        restored = self.restore_state(state)
        if isinstance(restored, AppState):
            state.revision = restored.revision

    def execute(
        self,
        state: AppState,
        plugin_name: str,
        command: str,
        **parameters: object,
    ) -> bool:
        plugin = self.get_plugin(plugin_name)
        if plugin is None:
            raise ValueError(f"unknown plugin: {plugin_name}")
        allowed = (
            self.commands.get(plugin_name, frozenset())
            if self.commands is not None
            else frozenset(plugin.meta.capabilities.commands)
        )
        if command not in allowed:
            raise ValueError(
                f"unsupported plugin command: {plugin_name}.{command}",
            )

        snapshot = copy.deepcopy(state)
        plugin_snapshot = self.invoker.snapshot(plugin, state)
        rolled_back = False

        def rollback() -> None:
            nonlocal rolled_back
            if rolled_back:
                return
            rolled_back = True
            restore_state_in_place(state, snapshot)
            try:
                plugin_rolled_back = self.invoker.rollback(
                    plugin,
                    state,
                    plugin_snapshot,
                )
            finally:
                self._persist_rollback(state)
            if not plugin_rolled_back:
                raise RuntimeError(
                    f"plugin command rollback failed: {plugin_name}.{command}",
                )

        try:
            changed = self.invoker.command(
                plugin,
                state,
                command,
                **parameters,
            )
            if not changed:
                restore_state_in_place(state, snapshot)
                return False

            protocol = state.protocols.get(plugin_name)
            persist_only = frozenset(
                getattr(
                    plugin.meta.capabilities,
                    "persist_only_commands",
                    (),
                ),
            )
            if (
                protocol is not None
                and protocol.enabled
                and command not in persist_only
            ):
                self.prepare_apply(state, plugin_name)
                capabilities = getattr(plugin.meta, "capabilities", None)
                central_apply = getattr(
                    capabilities,
                    "central_apply",
                    getattr(plugin.meta, "central_apply", None) is not False,
                )
                applied = (
                    self.apply_config(state)
                    if central_apply
                    else self.invoker.apply(plugin, state)
                )
                if applied:
                    if not central_apply:
                        self.save_state(state)
                    return True
                rollback()
                return False

            self.save_state(state)
            return True
        except Exception:
            rollback()
            raise


__all__ = [
    "PluginCommandService",
    "PluginCommands",
    "UnavailablePluginCommands",
]
