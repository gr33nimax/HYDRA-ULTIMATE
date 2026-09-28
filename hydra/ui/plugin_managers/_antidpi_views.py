"""Read-only Anti-DPI panels for the TUI controller."""

from __future__ import annotations

from datetime import datetime

from hydra.plugins.antidpi.labels import (
    health_label,
    signal_summary,
    source_label,
)
from hydra.utils.format_ru import (
    format_age,
    format_count,
    plural,
    progress_bar,
)
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    RED,
    WHITE,
    YELLOW,
    kv,
)

TABLE_WIDTH = 74
ADDRESS_WIDTH = 26


def _as_float(value: object, default: float = 0.0) -> float:
    """Return a float from untrusted persisted state, or ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return float(value.strip())
        except (TypeError, ValueError):
            return default
    return default


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from untrusted persisted state, or ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return int(value.strip())
        except (TypeError, ValueError):
            return default
    return default


def _is_false(value: object) -> bool:
    """Return True only for the JSON boolean ``false``."""
    return isinstance(value, bool) and not value


def timestamp(value: object) -> str:
    """Render an absolute event time, tolerating corrupt persisted values."""
    try:
        return datetime.fromtimestamp(_as_float(value)).strftime("%d.%m %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return "—"


def address_cell(value: object, *, color: str = CYAN) -> str:
    """Pad an address without breaking alignment for long IPv6 literals."""
    text = str(value or "—")
    if len(text) > ADDRESS_WIDTH:
        return f"{color}{text}{NC}"
    return f"{color}{text}{NC}{' ' * (ADDRESS_WIDTH - len(text))}"


def rule(width: int = TABLE_WIDTH) -> str:
    return f"  {DIM}{'─' * width}{NC}"


def wrapped(label: str, text: str, *, width: int = 56) -> list[str]:
    """Wrap one long detail line under a fixed-width label column."""
    prefix = f"     {DIM}{label}"
    indent = " " * (5 + len(label))
    lines: list[str] = []
    current = ""
    for word in str(text).split():
        candidate = f"{current} {word}".strip()
        if current and len(candidate) > width:
            lines.append(current)
            current = word
        else:
            current = candidate
    lines.append(current or "—")
    return [f"{prefix if index == 0 else indent}{value}{NC}" for index, value in enumerate(lines)]


def status_lines(*, running: bool, health, data: dict) -> list[str]:
    """Render the compact AntiDPI summary."""
    now = data.get("now", 0)
    bans = rows(data, "ban_rows")
    whitelist = data.get("whitelist", [])
    whitelist = whitelist if isinstance(whitelist, list) else []
    healthy = bool(getattr(health, "healthy", False))
    service = f"{GREEN}● работает{NC}" if running else f"{RED}○ остановлен{NC}"
    condition = f"{GREEN}✓ исправен{NC}" if healthy else f"{RED}✗ требует внимания{NC}"
    lines = [
        kv("Статус", f"{service} {DIM}·{NC} {condition}"),
        kv(
            "Защита",
            f"{RED if bans else GREEN}{len(bans)} банов{NC} {DIM}· whitelist {len(whitelist)}{NC}",
        ),
        kv(
            "События",
            f"{WHITE}{format_count(data.get('events'))}{NC} "
            f"{DIM}· последнее {format_age(data.get('last_event_at'), now=now)}"
            f" ({source_label(data.get('last_event_source'))}){NC}",
        ),
    ]
    reconciliation = data.get("reconciliation", {})
    reconciliation_failed = isinstance(reconciliation, dict) and _is_false(reconciliation.get("ok"))
    failed = [
        health_label(name)
        for name, value in (getattr(health, "checks", {}) or {}).items()
        if not value and not (name == "reconciliation" and reconciliation_failed)
    ]
    if data.get("degraded"):
        failed.append("state повреждён; автоблокировки остановлены")
    if reconciliation_failed:
        steps = reconciliation.get("failed", [])
        detail = ", ".join(str(value) for value in steps) or "ошибка синхронизации"
        failed.append("firewall: " + detail)
    if failed:
        lines.extend(wrapped("Проблема:  ", ", ".join(dict.fromkeys(failed))))
    lines.extend(_failure_lines(data, now=now))
    error = str(data.get("last_error") or "").strip()
    if error:
        lines.append(kv("Ошибка", f"{RED}{error[:52]}{NC}"))
    return lines


def _failure_lines(data: dict, *, now: float) -> list[str]:
    failures = data.get("ban_failures", {})
    failures = failures if isinstance(failures, dict) else {}
    count = _as_int(failures.get("count", 0))
    try:
        last_at = float(failures.get("last_at", 0) or 0)
        recent = last_at > 0 and float(now) - last_at <= 86400
    except (TypeError, ValueError):
        recent = False
    if count <= 0 or not recent:
        return []
    return [
        kv(
            "Firewall",
            f"{RED}не применено банов: {count}{NC} {DIM}· "
            f"{failures.get('last_ip', '—')} "
            f"{format_age(failures.get('last_at'), now=now)}{NC}",
        ),
    ]


def rows(data: dict, key: str) -> list[dict]:
    """Return one projection row list, tolerating a legacy snapshot shape."""
    values = data.get(key, []) if isinstance(data, dict) else []
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def ban_table(
    data: dict,
    *,
    limit: int = 20,
    offset: int = 0,
) -> list[str]:
    """Render one page of active bans with their remaining time and evidence.

    Row numbers always refer to the rendered page, so an operator can never
    type the number of a row that is not on screen.
    """
    ordered = rows(data, "ban_rows")
    if not ordered:
        return [f"  {DIM}Активных блокировок нет{NC}"]
    start = max(0, _as_int(offset))
    window = ordered[start : start + max(0, _as_int(limit, 20))]
    lines = [
        f"  {BOLD}{'#':<4}{'IP':<{ADDRESS_WIDTH}}Осталось{NC}",
        rule(),
    ]
    for index, view in enumerate(window, 1):
        lines.extend(_ban_rows(index, str(view.get("ip", "—")), view))
        lines.extend(wrapped("Причина:   ", str(view.get("reason", "—"))))
        lines.extend(
            wrapped(
                "Источник:  ",
                f"{view.get('source', '—')} · {view.get('protocol', '—')} · "
                f"срок {view.get('ttl', '—')} · "
                f"нарушение #{_as_int(view.get('offense', 1), default=1)} · "
                f"{timestamp(view.get('at'))}",
            ),
        )
        lines.append("")
    hidden = len(ordered) - (start + len(window))
    if hidden > 0:
        lines.append(
            f"  {DIM}…и ещё {plural(hidden, ('адрес', 'адреса', 'адресов'))}{NC}",
        )
    return lines


def _ban_rows(index: int, address: str, view: dict) -> list[str]:
    """Keep long IPv6 literals readable instead of truncating the row."""
    metrics = f"{view['icon']} {view['remaining_label']}"
    if len(address) > ADDRESS_WIDTH:
        return [
            f"  {CYAN}{index:<4}{NC}{RED}{address}{NC}",
            f"  {' ' * 4}{' ' * ADDRESS_WIDTH}{metrics}",
        ]
    return [
        f"  {CYAN}{index:<4}{NC}{address_cell(address, color=RED)}{metrics}",
    ]


def history_table(data: dict, *, limit: int = 12) -> list[str]:
    """Render closed ban records that no longer have an active block."""
    records = data.get("history", []) if isinstance(data, dict) else []
    records = records if isinstance(records, list) else []
    active = {str(row.get("ip")) for row in rows(data, "ban_rows")}
    closed = [item for item in reversed(records) if isinstance(item, dict) and str(item.get("ip")) not in active][
        :limit
    ]
    if not closed:
        return [f"  {DIM}Завершённых записей нет{NC}"]
    lines = [
        f"  {BOLD}{'IP':<{ADDRESS_WIDTH}}{'Статус':<12}Время{NC}",
        rule(),
    ]
    states = {
        "active": (RED, "активен"),
        "expired": (DIM, "истёк"),
        "unbanned": (GREEN, "снят"),
    }
    for item in closed:
        color, text = states.get(str(item.get("status", "")), (DIM, "—"))
        lines.append(
            f"  {address_cell(item.get('ip'))}{color}{text:<12}{NC}{DIM}{timestamp(item.get('at'))}{NC}",
        )
        lines.append(
            f"     {DIM}{signal_summary(item.get('signals'), limit=4)}{NC}",
        )
    return lines


def counter_lines(data: dict) -> list[str]:
    """Render the aggregate signal and source counters of the projection."""
    counters = data.get("counters", {}) if isinstance(data, dict) else {}
    counters = counters if isinstance(counters, dict) else {}
    return [
        f"  {BOLD}Сигналы{NC}",
        *_counter_rows(counters.get("signals")),
        "",
        f"  {BOLD}Источники{NC}",
        *_counter_rows(counters.get("sources")),
    ]


def _counter_rows(values: object) -> list[str]:
    items = [row for row in values if isinstance(row, dict)] if isinstance(values, (list, tuple)) else []
    if not items:
        return [f"  {DIM}нет данных{NC}"]
    return [
        f"    {str(row.get('label', '—')):<34}"
        f"{CYAN}"
        f"{progress_bar(_as_float(row.get('count')), maximum=row.get('maximum'), width=12)}"
        f"{NC} {WHITE}{_as_int(row.get('count'))}{NC}"
        for row in items
    ]


__all__ = [
    "address_cell",
    "ban_table",
    "counter_lines",
    "history_table",
    "rule",
    "status_lines",
    "timestamp",
    "wrapped",
]
