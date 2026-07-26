"""Shared application and client-status helpers for extended protocol menus."""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService


def _application(app: ApplicationService | None = None) -> ApplicationService:
    if app is None:
        raise RuntimeError("extended protocol controller requires an application")
    return app


def _apply_error_text(
    default: str = "Ошибка применения конфигурации",
    app: ApplicationService | None = None,
) -> str:
    return _application(app).apply_error() or default


def _desired_state(state: AppState, name: str) -> PluginState:
    return state.protocols.get(name) or PluginState()


def _show_plugin_clients(
    state: AppState,
    p,
    app: ApplicationService,
):
    from hydra.ui._menus.client_status import show_plugin_clients

    show_plugin_clients(state, p, app)
