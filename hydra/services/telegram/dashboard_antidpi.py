"""AntiDPI dashboard renderers.

Every human-readable label (signals, sources, remaining ban time) is produced
by the plugin's own management projection, so this adapter only arranges
already-translated evidence and never imports plugin internals.
"""
from __future__ import annotations

import html

from hydra.services.application import ApplicationService
from hydra.services.telegram.dashboard_common import (
    _mapping_projection,
    _network_label,
)
from hydra.utils.format_ru import (
    format_age,
    format_count,
    plural,
    progress_bar,
)

BAN_ROWS = 5
WATCH_ROWS = 3
DETAIL_BAN_ROWS = 12
DETAIL_WATCH_ROWS = 8


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


def _score(row: dict, key: str = "score") -> float:
    try:
        return float(row.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def _service_label(app: ApplicationService) -> str:
    status = app.protocols.status("antidpi")
    if status.running:
        return "🟢 работает"
    return "⚠️ установлен, остановлен" if status.installed else "🔴 не установлен"


def _headline(app: ApplicationService, data: dict) -> list[str]:
    now = data.get("now", 0)
    bans = _rows(data, "ban_rows")
    permanent = sum(1 for row in bans if row.get("permanent") is True)
    watching = _rows(data, "watchlist")
    source = str(data.get("last_event_source_label", "") or "").strip()
    lines = [
        _service_label(app),
        f"<b>Блокировки:</b> "
        f"{plural(len(bans), ('активная', 'активные', 'активных'))}"
        + (f" · бессрочных {permanent}" if permanent else ""),
        f"<b>Под наблюдением:</b> "
        f"{plural(len(watching), ('адрес', 'адреса', 'адресов'))}",
        f"<b>События:</b> {format_count(data.get('events'))} · последнее "
        f"{html.escape(format_age(data.get('last_event_at'), now=now))}"
        + (f" ({html.escape(source)})" if source else ""),
    ]
    lines.extend(_delivery_lines(data))
    return lines


def _delivery_lines(data: dict) -> list[str]:
    stats = _mapping_projection(data.get("notification_stats"))
    grouped = int(data.get("suppressed_ban_notifications", 0) or 0)
    lines = [
        f"<b>Уведомления:</b> доставлено "
        f"{int(stats.get('delivered', 0) or 0)}, ошибок "
        f"{int(stats.get('failed', 0) or 0)}, сгруппировано {grouped}",
    ]
    failures = _mapping_projection(data.get("ban_failures"))
    count = int(failures.get("count", 0) or 0)
    if count:
        lines.append(
            f"⚠️ <b>Firewall отклонил блокировок:</b> {count} · последняя "
            f"<code>{html.escape(str(failures.get('last_ip', '—')))}</code> "
            f"{html.escape(format_age(failures.get('last_at'), now=data.get('now', 0)))}",
        )
    return lines


def _ban_block(row: dict, *, intel: dict) -> str:
    address = str(row.get("ip", "—"))
    details = intel.get(address, {})
    flag = html.escape(str(details.get("flag", "🌐")))
    owner = _network_label(details) if details else ""
    suffix = f" · {html.escape(owner)}" if owner else ""
    return (
        f"{_text(row, 'icon', '🔴')} {flag} "
        f"<code>{html.escape(address)}</code> · "
        f"<b>{_score(row):.1f}</b> · {_text(row, 'remaining_label')}\n"
        f"  {_text(row, 'reason')}\n"
        f"  {_text(row, 'source')} · {_text(row, 'protocol')} · "
        f"нарушение #{int(row.get('offense', 1) or 1)}{suffix}"
    )


def _ban_line(row: dict) -> str:
    return (
        f"{_text(row, 'icon', '🔴')} "
        f"<code>{html.escape(str(row.get('ip', '—')))}</code> · "
        f"{_score(row):.1f} балла · {_text(row, 'remaining_label')} · "
        f"{_text(row, 'reason')}"
    )


def _watch_line(row: dict, *, now: object) -> str:
    score = _score(row)
    threshold = _score(row, "threshold") or 8.0
    blocked = str(row.get("block_label", "") or "").strip()
    return (
        f"👁 <code>{html.escape(str(row.get('ip', '—')))}</code> · "
        f"<code>{progress_bar(score, maximum=threshold, width=8)}</code> "
        f"{score:.1f}/{threshold:.0f} · "
        f"{html.escape(format_age(row.get('updated'), now=now))}\n"
        f"  {_text(row, 'reason', 'накопление улик')}"
        + (f"\n  <i>{html.escape(blocked)}</i>" if blocked else "")
    )


def _coordinated_lines(data: dict) -> list[str]:
    rows = _rows(data, "coordinated", 3)
    if not rows:
        return []
    lines = [
        f"🌐 <code>{_text(row, 'prefix')}</code> · "
        f"{plural(int(row.get('members', 0) or 0), ('адрес', 'адреса', 'адресов'))}"
        for row in rows
    ]
    lines.append(
        "<i>Агрегат не банит: каждый адрес блокируется только по "
        "собственным уликам.</i>",
    )
    return lines


def _counter_lines(data: dict, key: str) -> list[str]:
    rows = _rows(_mapping_projection(data.get("counters")), key, 6)
    if not rows:
        return ["<i>нет данных</i>"]
    return [
        f"<code>"
        f"{progress_bar(row.get('count'), maximum=row.get('maximum'), width=8)}"
        f"</code> {_text(row, 'label')} — {int(row.get('count', 0) or 0)}"
        for row in rows
    ]


def get_antidpi_dashboard_text(
    app: ApplicationService,
    *,
    lookup_intel=None,
) -> str:
    """Render the operational AntiDPI dashboard."""
    data = _snapshot(app)
    bans = _rows(data, "ban_rows")
    visible = bans[:BAN_ROWS]
    intel = (
        lookup_intel([str(row.get("ip", "")) for row in visible])
        if lookup_intel and visible
        else {}
    )
    rows = [_ban_block(row, intel=intel) for row in visible]
    if len(bans) > BAN_ROWS:
        rows.append(
            f"<i>…и ещё {len(bans) - BAN_ROWS} в списке блокировок</i>",
        )
    watch = [
        _watch_line(row, now=data.get("now", 0))
        for row in _rows(data, "watchlist", WATCH_ROWS)
    ]
    blocks = [
        "<b>🛡 AntiDPI — защита всей VPS</b>",
        "\n".join(_headline(app, data)),
        "<b>Активные блокировки</b>\n"
        + ("\n\n".join(rows) if rows else "<i>Блокировок нет</i>"),
    ]
    if watch:
        blocks.append("<b>Под наблюдением</b>\n" + "\n".join(watch))
    coordinated = _coordinated_lines(data)
    if coordinated:
        blocks.append(
            "<b>Скоординированная активность</b>\n" + "\n".join(coordinated),
        )
    return "\n\n".join(blocks)


def get_antidpi_status_text(app: ApplicationService) -> str:
    """Render the detailed AntiDPI status view."""
    data = _snapshot(app)
    bans = _rows(data, "ban_rows")
    rows = [_ban_line(row) for row in bans[:DETAIL_BAN_ROWS]]
    if len(bans) > DETAIL_BAN_ROWS:
        rows.append(f"<i>…и ещё {len(bans) - DETAIL_BAN_ROWS} IP</i>")
    watch = [
        _watch_line(row, now=data.get("now", 0))
        for row in _rows(data, "watchlist", DETAIL_WATCH_ROWS)
    ]
    whitelist = data.get("whitelist", [])
    whitelist = whitelist if isinstance(whitelist, list) else []
    blocks = [
        "<b>🛡️ AntiDPI Status</b>",
        "\n".join(
            [
                *_headline(app, data),
                f"<b>Whitelist:</b> "
                f"{plural(len(whitelist), ('запись', 'записи', 'записей'))}",
                f"<b>Адресов под учётом:</b> "
                f"{format_count(data.get('tracked_addresses'))}",
            ],
        ),
        "<b>Сигналы</b>\n" + "\n".join(_counter_lines(data, "signals")),
        "<b>Источники</b>\n" + "\n".join(_counter_lines(data, "sources")),
        f"<b>Заблокировано IP:</b> {len(bans)}\n"
        + ("\n".join(rows) if rows else "<i>Нет заблокированных IP</i>"),
    ]
    if watch:
        blocks.append("<b>Под наблюдением</b>\n" + "\n".join(watch))
    return "\n\n".join(blocks)
