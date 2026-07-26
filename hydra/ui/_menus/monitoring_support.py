"""Shared dependency-clean helpers for monitoring menu controllers."""
from __future__ import annotations

from hydra.services.application import ApplicationService
from hydra.ui.tui import enter_pressed


def _application(
    app: ApplicationService | None = None,
) -> ApplicationService:
    if app is None:
        raise ValueError("ApplicationService must be injected by the UI facade")
    return app


def _apply_error_text(
    default: str = "Ошибка применения конфигурации",
    app: ApplicationService | None = None,
) -> str:
    return _application(app).apply_error() or default


def _unit_active(unit: str, app: ApplicationService) -> bool:
    """Query a unit through the injected administration port."""
    return app.admin.unit_active(unit)


def _unit_known(unit: str, app: ApplicationService) -> bool:
    return app.admin.unit_known(unit)


def _is_enter_pressed() -> bool:
    return enter_pressed()
