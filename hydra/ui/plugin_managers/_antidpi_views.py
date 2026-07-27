"""Read-only Anti-DPI panels for the TUI controller."""
from __future__ import annotations

from datetime import datetime

from hydra.plugins.antidpi.labels import (
    block_reason_label,
    health_label,
    signal_label,
    signal_summary,
    source_label,
)
from hydra.plugins.antidpi.model import BAN_THRESHOLD
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


def timestamp(value: object) -> str:
    """Render an absolute event time, tolerating corrupt persisted values."""
    try:
        return datetime.fromtimestamp(float(value)).strftime("%d.%m %H:%M:%S")
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
    return [
        f"{prefix if index == 0 else indent}{value}{NC}"
        for index, value in enumerate(lines)
    ]


def status_lines(*, running: bool, health, data: dict) -> list[str]:
    """Render the header panel of the Anti-DPI controller."""
    now = data.get("now", 0)
    bans = rows(data, "ban_rows")
    watch = rows(data, "watchlist")
    whitelist = data.get("whitelist", [])
    whitelist = whitelist if isinstance(whitelist, list) else []
    permanent = sum(1 for row in bans if row.get("permanent") is True)
    lines = [
        kv(
            "Служба",
            f"{GREEN}● активна{NC}" if running else f"{RED}○ остановлена{NC}",
        ),
        *_health_lines(health),
        kv(
            "События",
            f"{WHITE}{format_count(data.get('events'))}{NC} "
            f"{DIM}· последнее {format_age(data.get('last_event_at'), now=now)}"
            f" ({source_label(data.get('last_event_source'))}){NC}",
        ),
        kv(
            "Блокировки",
            f"{RED if bans else GREEN}"
            f"{plural(len(bans), ('активная', 'активные', 'активных'))}{NC} "
            f"{DIM}· бессрочных {permanent}{NC}",
        ),
        kv(
            "Наблюдение",
            f"{YELLOW if watch else DIM}"
            f"{plural(len(watch), ('адрес', 'адреса', 'адресов'))}{NC} "
            f"{DIM}· всего под учётом "
            f"{format_count(data.get('tracked_addresses'))}{NC}",
        ),
        kv(
            "Whitelist",
            plural(len(whitelist), ("запись", "записи", "записей")),
        ),
        *_notification_lines(data),
        *_failure_lines(data, now=now),
    ]
    error = str(data.get("last_error") or "").strip()
    if error:
        lines.append(kv("Ошибка", f"{RED}{error[:52]}{NC}"))
    return lines


def _health_lines(health) -> list[str]:
    healthy = bool(getattr(health, "healthy", False))
    checks = getattr(health, "checks", {}) or {}
    if healthy:
        return [kv("Состояние", f"{GREEN}✓ исправна{NC}")]
    failed = [
        health_label(name)
        for name, value in checks.items()
        if not value
    ]
    lines = [kv("Состояние", f"{RED}✗ требует внимания{NC}")]
    if failed:
        lines.extend(wrapped("Проблемы:  ", ", ".join(failed)))
    return lines


def _notification_lines(data: dict) -> list[str]:
    stats = data.get("notification_stats", {})
    stats = stats if isinstance(stats, dict) else {}
    delivered = int(stats.get("delivered", 0) or 0)
    failed = int(stats.get("failed", 0) or 0)
    grouped = int(data.get("suppressed_ban_notifications", 0) or 0)
    return [
        kv(
            "Telegram",
            f"{GREEN}доставлено {delivered}{NC} {DIM}·{NC} "
            f"{RED if failed else DIM}ошибок {failed}{NC} {DIM}· "
            f"сгруппировано {grouped}{NC}",
        ),
    ]


def _failure_lines(data: dict, *, now: float) -> list[str]:
    failures = data.get("ban_failures", {})
    failures = failures if isinstance(failures, dict) else {}
    count = int(failures.get("count", 0) or 0)
    if count <= 0:
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


def ban_table(data: dict, *, limit: int = 20) -> list[str]:
    """Render active bans with their remaining time and evidence."""
    ordered = rows(data, "ban_rows")
    if not ordered:
        return [f"  {DIM}Активных блокировок нет{NC}"]
    lines = [
        f"  {BOLD}{'#':<4}{'IP':<{ADDRESS_WIDTH}}{'Баллы':<9}Осталось{NC}",
        rule(),
    ]
    for index, view in enumerate(ordered[:limit], 1):
        lines.extend(_ban_rows(index, str(view.get("ip", "—")), view))
        lines.extend(wrapped("Причина:   ", str(view.get("reason", "—"))))
        lines.extend(
            wrapped(
                "Источник:  ",
                f"{view.get('source', '—')} · {view.get('protocol', '—')} · "
                f"срок {view.get('ttl', '—')} · "
                f"нарушение #{int(view.get('offense', 1) or 1)} · "
                f"{timestamp(view.get('at'))}",
            ),
        )
        lines.append("")
    if len(ordered) > limit:
        hidden = len(ordered) - limit
        lines.append(
            f"  {DIM}…и ещё {plural(hidden, ('адрес', 'адреса', 'адресов'))}"
            f"{NC}",
        )
    return lines


def _ban_rows(index: int, address: str, view: dict) -> list[str]:
    """Keep long IPv6 literals readable instead of truncating the row."""
    metrics = (
        f"{YELLOW}{view['score']:<9.1f}{NC}"
        f"{view['icon']} {view['remaining_label']}"
    )
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
    closed = [
        item
        for item in reversed(records)
        if isinstance(item, dict) and str(item.get("ip")) not in active
    ][:limit]
    if not closed:
        return [f"  {DIM}Завершённых записей нет{NC}"]
    lines = [
        f"  {BOLD}{'IP':<{ADDRESS_WIDTH}}{'Баллы':<9}{'Статус':<12}"
        f"Время{NC}",
        rule(),
    ]
    states = {
        "active": (RED, "активен"),
        "expired": (DIM, "истёк"),
        "unbanned": (GREEN, "снят"),
    }
    for item in closed:
        color, text = states.get(str(item.get("status", "")), (DIM, "—"))
        try:
            score = float(item.get("score", 0) or 0)
        except (TypeError, ValueError):
            score = 0.0
        lines.append(
            f"  {address_cell(item.get('ip'))}"
            f"{DIM}{score:<9.1f}{NC}{color}{text:<12}{NC}"
            f"{DIM}{timestamp(item.get('at'))}{NC}",
        )
        lines.append(
            f"     {DIM}{signal_summary(item.get('signals'), limit=4)}{NC}",
        )
    return lines


def watchlist_table(data: dict) -> list[str]:
    """Render sub-threshold evidence so operators see attacks in progress."""
    items = rows(data, "watchlist")
    now = data.get("now", 0) if isinstance(data, dict) else 0
    if not items:
        return [
            f"  {DIM}Под наблюдением никого нет.{NC}",
            f"  {DIM}Здесь появляются адреса с накопленными баллами "
            f"ниже порога бана ({BAN_THRESHOLD}).{NC}",
        ]
    lines = [
        f"  {BOLD}{'#':<4}{'IP':<{ADDRESS_WIDTH}}{'Баллы':<20}"
        f"Последнее событие{NC}",
        rule(),
    ]
    for index, row in enumerate(items, 1):
        score = float(row.get("score", 0) or 0)
        verified = float(row.get("verified_score", 0) or 0)
        threshold = float(row.get("threshold", BAN_THRESHOLD) or BAN_THRESHOLD)
        color = RED if score >= threshold * 0.75 else YELLOW
        bar = f"{color}{progress_bar(score, maximum=threshold)}{NC}"
        lines.append(
            f"  {CYAN}{index:<4}{NC}{address_cell(row.get('ip'))}"
            f"{bar} {color}{score:>4.1f}{NC}{DIM}/{threshold:.0f}{NC}  "
            f"{DIM}{format_age(row.get('updated'), now=now)}{NC}",
        )
        detail = ", ".join(
            signal_label(value) for value in row.get("signals", [])
        )
        lines.extend(wrapped("Сигналы:   ", detail or "—"))
        evidence = str(row.get("evidence", "") or "").strip()
        if evidence and evidence != "—":
            lines.extend(wrapped("Улики:     ", evidence))
        if verified < score:
            lines.append(
                f"     {DIM}Подтверждено: {verified:.1f} "
                f"(остальное — alert-only телеметрия){NC}",
            )
        blocked = str(
            row.get("block_label")
            or block_reason_label(row.get("block_reason")),
        ).strip()
        if blocked:
            lines.extend(wrapped("До бана:   ", blocked))
        lines.append("")
    return lines


def coordinated_table(data: dict) -> list[str]:
    """Render subnets that are probing from several addresses at once."""
    items = rows(data, "coordinated")
    if not items:
        return [
            f"  {DIM}Скоординированной активности не зафиксировано.{NC}",
            f"  {DIM}Сюда попадают подсети, из которых улики приходят "
            f"сразу с нескольких адресов.{NC}",
        ]
    lines = [
        f"  {BOLD}{'Подсеть':<24}{'Адресов':<10}Последняя активность{NC}",
        rule(),
    ]
    now = data.get("now", 0) if isinstance(data, dict) else 0
    for row in items:
        lines.append(
            f"  {YELLOW}{str(row.get('prefix', '—')):<24}{NC}"
            f"{RED}{int(row.get('members', 0) or 0):<10}{NC}"
            f"{DIM}{format_age(row.get('updated'), now=now)}{NC}",
        )
        lines.extend(
            wrapped("Адреса:    ", ", ".join(row.get("addresses", []) or ["—"])),
        )
        lines.append("")
    lines.append(
        f"  {DIM}Агрегат не банит сам по себе: каждый адрес блокируется "
        f"только по собственным уликам.{NC}",
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
    items = [row for row in (values or []) if isinstance(row, dict)]
    if not items:
        return [f"  {DIM}нет данных{NC}"]
    return [
        f"    {str(row.get('label', '—')):<34}"
        f"{CYAN}"
        f"{progress_bar(row.get('count'), maximum=row.get('maximum'), width=12)}"
        f"{NC} {WHITE}{int(row.get('count', 0) or 0)}{NC}"
        for row in items
    ]


__all__ = [
    "address_cell",
    "ban_table",
    "coordinated_table",
    "counter_lines",
    "history_table",
    "rule",
    "status_lines",
    "timestamp",
    "watchlist_table",
    "wrapped",
]
