"""AntiDPI dashboard renderers.

Every human-readable label (signals, sources, remaining ban time) is produced
by the plugin's own management projection, so this adapter only arranges
already-translated evidence and never imports plugin internals.
"""

from __future__ import annotations

import html

from hydra.services.application import ApplicationService
from hydra.services.telegram.dashboard_common import _mapping_projection
from hydra.utils.format_ru import (
    format_age,
    format_count,
)

COUNTER_ROWS = 3


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from untrusted projection data, or ``default``."""
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


def _snapshot(app: ApplicationService) -> dict:
    try:
        return _mapping_projection(
            app.plugin_query("antidpi", "management_snapshot"),
        )
    except Exception:
        return {}


def _rows(data: dict, key: str, limit: int | None = None) -> list[dict]:
    values = data.get(key, [])
    if not isinstance(values, list):
        return []
    rows = [item for item in values if isinstance(item, dict)]
    return rows if limit is None else rows[:limit]


def _text(row: dict, key: str, default: str = "—") -> str:
    return html.escape(str(row.get(key, default) or default))


def _service_label(app: ApplicationService) -> str:
    status = app.protocols.status("antidpi")
    if status.running:
        return "🟢 работает"
    return "⚠️ установлен, остановлен" if status.installed else "🔴 не установлен"


def _headline(app: ApplicationService, data: dict) -> list[str]:
    now = data.get("now", 0)
    bans = _rows(data, "ban_rows")
    lines = [
        _service_label(app),
        f"<b>{len(bans)}</b> блокировок",
        f"{format_count(data.get('events'))} событий · {html.escape(format_age(data.get('last_event_at'), now=now))}",
    ]
    if data.get("degraded"):
        lines.append(
            "⚠️ <b>State повреждён:</b> автоматические блокировки приостановлены",
        )
    reconciliation = _mapping_projection(data.get("reconciliation"))
    if _is_false(reconciliation.get("ok")):
        failed = ", ".join(str(value) for value in reconciliation.get("failed", []))
        lines.append(
            "⚠️ <b>Firewall:</b> не синхронизирован · " + html.escape(failed or "ошибка"),
        )
    failures = _mapping_projection(data.get("ban_failures"))
    count = _as_int(failures.get("count", 0))
    try:
        last_at = float(failures.get("last_at", 0) or 0)
        recent = last_at > 0 and float(now) - last_at <= 86400
    except (TypeError, ValueError):
        recent = False
    if count and recent:
        lines.append(
            f"⚠️ Firewall: {count} ошибок · {html.escape(format_age(failures.get('last_at'), now=now))}",
        )
    return lines


def _counter_lines(data: dict, key: str) -> list[str]:
    rows = _rows(_mapping_projection(data.get("counters")), key, COUNTER_ROWS)
    if not rows:
        return ["<i>нет данных</i>"]
    return [f"• {_text(row, 'label')} — {_as_int(row.get('count', 0))}" for row in rows]


def get_antidpi_dashboard_text(
    app: ApplicationService,
) -> str:
    """Render the compact AntiDPI dashboard."""
    data = _snapshot(app)
    return "<b>🛡 AntiDPI</b>\n\n" + "\n".join(_headline(app, data))


def get_antidpi_status_text(app: ApplicationService) -> str:
    """Render the detailed AntiDPI status view."""
    data = _snapshot(app)
    whitelist = data.get("whitelist", [])
    whitelist = whitelist if isinstance(whitelist, list) else []
    blocks = [
        "<b>🛡 AntiDPI · подробно</b>",
        "\n".join(
            [
                *_headline(app, data),
                f"whitelist {len(whitelist)}",
            ],
        ),
        "<b>Сигналы</b>\n" + "\n".join(_counter_lines(data, "signals")),
        "<b>Источники</b>\n" + "\n".join(_counter_lines(data, "sources")),
    ]
    return "\n\n".join(blocks)
