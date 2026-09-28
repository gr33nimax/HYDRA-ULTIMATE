"""Shared dependency-clean helpers for monitoring menu controllers."""
from __future__ import annotations

from typing import Any

from hydra.services.application import ApplicationService
from hydra.ui.protocol_ui import protocol_state
from hydra.ui.tui import (
    CYAN,
    DIM,
    NC,
    _strip,
    enter_pressed,
    visible_width,
)

# The single source of truth for the "По протоколам" table: cell widths and
# separators, so header, divider and rows cannot drift apart (16+1+12+2+23+1+
# 13+1+8 = 77).
PROTOCOL_WIDTH = 16
TRAFFIC_WIDTH = 12
SHARE_WIDTH = 23
ACCOUNTING_WIDTH = 13
STATUS_WIDTH = 8
SHARE_BAR_WIDTH = 16
TABLE_WIDTH = (
    PROTOCOL_WIDTH + 1 + TRAFFIC_WIDTH + 2 + SHARE_WIDTH
    + 1 + ACCOUNTING_WIDTH + 1 + STATUS_WIDTH
)


def _as_int(value: Any) -> int:
    """Coerce a stored counter for display; a malformed value reads as zero."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _cell(text: str, width: int, align: str = "<") -> str:
    """Pad to an exact visible width; longer text is cut with an ellipsis."""
    if visible_width(text) > width:
        text = _strip(text)[: max(0, width - 1)] + "…"
    padding = " " * max(0, width - visible_width(text))
    return f"{padding}{text}" if align == ">" else f"{text}{padding}"


def _status_text(installed: bool, enabled: bool, running: bool) -> str:
    """Compact verdict derived from the canonical protocol_state helper."""
    plain = _strip(protocol_state(installed, enabled, running))
    return plain[2:] if plain.startswith("● ") else plain


def _share_bar(value: int, total: int) -> str:
    """Draw the 16-block share bar; a nonzero share always shows one block."""
    ratio = min(1.0, value / total) if total > 0 else 0.0
    filled = min(SHARE_BAR_WIDTH, max(1, round(ratio * SHARE_BAR_WIDTH))) if value > 0 else 0
    return (
        f"{CYAN}{'█' * filled}{DIM}{'░' * (SHARE_BAR_WIDTH - filled)}{NC} "
        f"{ratio * 100:5.1f}%"
    )


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
