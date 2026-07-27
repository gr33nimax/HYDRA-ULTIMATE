"""Russian-language formatting primitives shared by every adapter.

These helpers carry no domain knowledge, so the plugin, service, and UI layers
can all depend on them without crossing an architectural boundary.
"""
from __future__ import annotations


def format_count(value: object) -> str:
    """Group large counters so totals stay readable at a glance."""
    try:
        return f"{int(float(value or 0)):,}".replace(",", " ")
    except (TypeError, ValueError):
        return "0"


def plural(count: object, forms: tuple[str, str, str]) -> str:
    """Return ``count`` with the correct Russian plural form of a noun."""
    try:
        value = abs(int(count))
    except (TypeError, ValueError):
        return f"0 {forms[2]}"
    tail, hundred = value % 10, value % 100
    if tail == 1 and hundred != 11:
        return f"{value} {forms[0]}"
    if 2 <= tail <= 4 and not 12 <= hundred <= 14:
        return f"{value} {forms[1]}"
    return f"{value} {forms[2]}"


def format_duration(seconds: object) -> str:
    """Render a coarse two-unit duration such as ``1ч 5м``."""
    try:
        total = max(0, int(float(seconds)))
    except (TypeError, ValueError):
        return "—"
    if total < 60:
        return f"{total}с"
    if total < 3600:
        minutes, rest = divmod(total, 60)
        return f"{minutes}м {rest}с" if rest else f"{minutes}м"
    if total < 86400:
        hours, rest = divmod(total, 3600)
        minutes = rest // 60
        return f"{hours}ч {minutes}м" if minutes else f"{hours}ч"
    days, rest = divmod(total, 86400)
    hours = rest // 3600
    return f"{days}д {hours}ч" if hours else f"{days}д"


def format_age(timestamp: object, *, now: object) -> str:
    """Render how long ago an absolute timestamp was observed."""
    try:
        moment = float(timestamp or 0)
        reference = float(now or 0)
    except (TypeError, ValueError):
        return "—"
    if moment <= 0 or reference <= 0:
        return "—"
    elapsed = reference - moment
    if elapsed < 5:
        return "только что"
    return f"{format_duration(elapsed)} назад"


def progress_bar(value: object, *, maximum: object, width: int = 10) -> str:
    """Render a monospace progress bar that both HTML and TTY views can use."""
    cells = max(1, int(width))
    try:
        current = max(0.0, float(value))
        limit = float(maximum)
    except (TypeError, ValueError):
        return "░" * cells
    if limit <= 0:
        return "█" * cells
    filled = min(cells, int(round(cells * min(1.0, current / limit))))
    return "█" * filled + "░" * (cells - filled)


__all__ = [
    "format_age",
    "format_count",
    "format_duration",
    "plural",
    "progress_bar",
]
