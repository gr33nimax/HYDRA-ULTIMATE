"""Shared helpers for plugin settings adapters.

Each settings module reports through its own ``success``/``error`` imports so the
existing per-module seams stay patchable; only the wording, the desired-state
read and the failure reason are shared here.
"""

from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService

FAILURE_TEXT = "Не удалось применить настройки; предыдущая конфигурация восстановлена"


def desired_state(state: AppState, name: str) -> PluginState:
    """Read one protocol's desired state, tolerating an unset protocol."""
    return state.protocols.get(name) or PluginState()


def report_change(
    app: ApplicationService,
    changed: bool,
    success_text: str,
    *,
    report_success: Callable[[str], object],
    report_error: Callable[[str], object],
) -> None:
    """Report a command result, preferring the recorded apply reason.

    A failed apply records its cause in ``app.apply_error()``; replacing that
    with the generic text hides the reason the operator needs. The generic text
    stays as the fallback for a failure whose cause was never recorded.
    """
    if changed:
        report_success(success_text)
        return
    report_error(app.apply_error() or FAILURE_TEXT)


__all__ = ["FAILURE_TEXT", "desired_state", "report_change"]
