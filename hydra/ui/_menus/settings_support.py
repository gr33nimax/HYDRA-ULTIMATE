"""Shared helpers for plugin settings adapters.

Each settings module reports through its own ``success``/``error`` imports so the
existing per-module seams stay patchable; only the wording and the desired-state
read are shared here.
"""

from __future__ import annotations

from hydra.core.state_models import AppState, PluginState

FAILURE_TEXT = "Не удалось применить настройки; предыдущая конфигурация восстановлена"


def desired_state(state: AppState, name: str) -> PluginState:
    """Read one protocol's desired state, tolerating an unset protocol."""
    return state.protocols.get(name) or PluginState()


__all__ = ["FAILURE_TEXT", "desired_state"]
