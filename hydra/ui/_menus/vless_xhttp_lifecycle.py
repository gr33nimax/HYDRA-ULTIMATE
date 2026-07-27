"""Lifecycle UI helpers for the VLESS/XHTTP transport."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService


def reinstall(
    state: AppState,
    plugin: object,
    app: ApplicationService,
    *,
    ask: Callable[..., bool],
    report_error: Callable[[str], None],
    report_success: Callable[[str], None],
    pause: Callable[[str], str],
) -> None:
    """Reinstall VLESS while keeping lifecycle failures inside the TUI."""
    if not ask("Переустановить VLESS + XHTTP?", default=False):
        return
    try:
        reinstalled = app.protocols.reinstall(state, plugin.meta.name)
    except Exception as exc:
        report_error(f"Ошибка переустановки VLESS: {exc}")
    else:
        if reinstalled:
            report_success("Переустановлено!")
        else:
            report_error(app.apply_error() or "Ошибка переустановки")
    pause("Нажмите Enter")
