"""Shared dependency validation for user menu controllers."""
from __future__ import annotations

from hydra.services.application import ApplicationService


def _application(app: ApplicationService | None = None) -> ApplicationService:
    if app is None:
        raise ValueError("ApplicationService must be injected by the UI facade")
    return app
