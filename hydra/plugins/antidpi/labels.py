"""Human-readable AntiDPI vocabulary owned by the plugin that produces it.

Adapters must never disagree about what a signal means or how long a ban still
lasts, and the service layer is not allowed to import plugin internals.  The
plugin therefore owns the vocabulary and ships rendered labels inside its
management projection; generic number and date formatting lives in
:mod:`hydra.utils.format_ru`.
"""

from __future__ import annotations

from collections.abc import Iterable

from hydra.plugins.antidpi.model import ban_duration
from hydra.utils.format_ru import format_duration

# Only the evidence AntiScan can actually produce is translated; anything
# else stays visible under its raw key instead of inventing a meaning.
SIGNAL_LABELS: dict[str, str] = {
    "snell:record_auth_failed": "Snell: неверный ключ клиента",
    "https:scanner_path": "поиск уязвимых путей на decoy-сайте",
    "manual_ban": "блокировка администратором",
}

SOURCE_LABELS: dict[str, str] = {
    "journal": "журнал протокола",
    "caddy-decoy": "decoy-сайт",
    "caddy-source-relay": "source-relay Caddy",
    "manual": "администратор",
    "legacy/unknown": "источник не сохранён",
    "unknown": "источник неизвестен",
}

HEALTH_LABELS: dict[str, str] = {
    "service": "служба детектора",
    "ipsets": "ipset-наборы блокировок",
    "firewall": "правила DROP в INPUT",
    "obsolete_telemetry_removed": "устаревшая телеметрия удалена",
    "collector_heartbeat": "живость сборщика событий",
    "state": "состояние детектора",
    "reconciliation": "сверка правил и банов",
}


def signal_label(value: object) -> str:
    """Translate one signal key, keeping unknown keys visible as-is."""
    key = str(value or "").strip()
    return SIGNAL_LABELS.get(key, key or "—")


def signal_summary(values: object, *, limit: int = 3) -> str:
    """Render up to ``limit`` translated signals plus an overflow marker."""
    items = signal_list(values)
    if not items:
        return "аномальное поведение"
    visible = [signal_label(item) for item in items[: max(1, int(limit))]]
    hidden = len(items) - len(visible)
    if hidden > 0:
        visible.append(f"+{hidden}")
    return ", ".join(visible)


def source_label(value: object) -> str:
    """Translate an evidence source, falling back to its raw identifier."""
    key = str(value or "").strip()
    return SOURCE_LABELS.get(key, key or "—")


def health_label(value: object) -> str:
    """Translate one healthcheck key from the firewall adapter."""
    key = str(value or "").strip()
    return HEALTH_LABELS.get(key, key or "—")


def signal_list(values: object) -> list[str]:
    """Normalize persisted signals that may be a list or a legacy string."""
    if isinstance(values, str):
        return [item.strip() for item in values.split(",") if item.strip()]
    if isinstance(values, Iterable) and not isinstance(values, (bytes, dict)):
        return [str(item) for item in values if str(item).strip()]
    return []


def ban_view(address: object, metadata: object, *, now: float) -> dict:
    """Project one ban record into the fields every adapter renders."""
    record = metadata if isinstance(metadata, dict) else {}
    duration = ban_duration(record)
    permanent = _is_true(record.get("permanent"))
    started_at = _number(record.get("at"))
    remaining = 0.0 if permanent else max(0.0, duration - (_number(now) - started_at))
    expired = not permanent and remaining <= 0
    if permanent:
        icon, ttl, left = "🔴", "бессрочно", "бессрочно"
    elif expired:
        icon, ttl, left = "🟡", format_duration(duration), "истёк"
    else:
        icon = "🔴" if remaining > 300 else "🟠"
        ttl, left = format_duration(duration), format_duration(remaining)
    return {
        "ip": str(address),
        "at": started_at,
        "duration": duration,
        "permanent": permanent,
        "expired": expired,
        "remaining": remaining,
        "icon": icon,
        "ttl": ttl,
        "remaining_label": left,
        "offense": _positive_int(record.get("offense_count"), default=1),
        "signals": signal_list(record.get("signals")),
        "reason": signal_summary(record.get("signals")),
        "source": source_label(record.get("source", "legacy/unknown")),
        "protocol": str(record.get("protocol", "unknown"))[:40],
        "kind": str(record.get("kind", ""))[:80],
    }


def counter_rows(counter: object, translate, *, limit: int = 6) -> list[dict]:
    """Rank one persisted counter and attach its translated labels."""
    values = counter if isinstance(counter, dict) else {}
    rows = []
    for name, value in values.items():
        count = _positive_int(value)
        rows.append({"key": str(name), "count": count})
    rows.sort(key=lambda row: row["count"], reverse=True)
    top = max((row["count"] for row in rows), default=0)
    return [
        {**row, "label": translate(row["key"]), "maximum": top}
        for row in rows[: max(0, _positive_int(limit, default=6))]
    ]


def _is_true(value: object) -> bool:
    """Return True only for the JSON boolean ``true``."""
    return isinstance(value, bool) and value


def _number(value: object) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except (TypeError, ValueError, OverflowError):
            return 0.0
    if isinstance(value, str):
        try:
            return float(value.strip())
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _positive_int(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return max(0, int(value))
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return max(0, int(value.strip()))
        except (TypeError, ValueError):
            return default
    return default


__all__ = [
    "HEALTH_LABELS",
    "SIGNAL_LABELS",
    "SOURCE_LABELS",
    "ban_view",
    "counter_rows",
    "health_label",
    "signal_label",
    "signal_list",
    "signal_summary",
    "source_label",
]
