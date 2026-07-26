"""Paged list screens and the address card of the admin bot.

Dashboards answer "what is happening"; these screens answer "show me all of it,
and tell me everything you know about this one address". Lists are paged rather
than silently truncated, and every row can be opened as a card.
"""
from __future__ import annotations

import html
import ipaddress
from dataclasses import dataclass, field

from hydra.services.application import ApplicationService
from hydra.services.telegram import navigation
from hydra.services.telegram.dashboard_common import (
    _mapping_projection,
    _network_label,
)
from hydra.utils.format_ru import format_age, plural, progress_bar


@dataclass(frozen=True)
class PagedView:
    """One rendered page plus the addresses its rows can open."""

    text: str
    addresses: tuple[str, ...] = ()
    page: int = 1
    pages: int = 1
    empty: bool = False
    extra: dict = field(default_factory=dict)


def _snapshot(app: ApplicationService, plugin: str) -> dict:
    try:
        return _mapping_projection(
            app.plugin_query(plugin, "management_snapshot"),
        )
    except Exception:
        return {}


def _rows(data: dict, key: str) -> list[dict]:
    values = data.get(key, [])
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def _header(name: str, total: int, noun: tuple[str, str, str]) -> str:
    return (
        f"<b>{html.escape(navigation.breadcrumb(name))}</b>\n"
        f"Всего: {plural(total, noun)}"
    )


def antidpi_bans_view(app: ApplicationService, page: int = 1) -> PagedView:
    """Render every active AntiDPI ban, one page at a time."""
    data = _snapshot(app, "antidpi")
    bans = _rows(data, "ban_rows")
    rows, current, pages = navigation.page_slice(bans, page)
    if not bans:
        return PagedView(
            text=_header("antidpi_bans", 0, ("блокировка", "блокировки", "блокировок"))
            + "\n\n<i>Активных блокировок нет</i>",
            empty=True,
        )
    lines = [
        f"{str(row.get('icon', '🔴'))} "
        f"<code>{html.escape(str(row.get('ip', '—')))}</code> · "
        f"<b>{float(row.get('score', 0) or 0):.1f}</b> · "
        f"{html.escape(str(row.get('remaining_label', '—')))}\n"
        f"  {html.escape(str(row.get('reason', '—')))}\n"
        f"  {html.escape(str(row.get('source', '—')))} · "
        f"нарушение #{int(row.get('offense', 1) or 1)}"
        for row in rows
    ]
    return PagedView(
        text=_header(
            "antidpi_bans",
            len(bans),
            ("блокировка", "блокировки", "блокировок"),
        )
        + "\n\n"
        + "\n\n".join(lines),
        addresses=tuple(str(row.get("ip", "")) for row in rows),
        page=current,
        pages=pages,
    )


def antidpi_watch_view(app: ApplicationService, page: int = 1) -> PagedView:
    """Render addresses whose evidence has not reached the ban bar."""
    data = _snapshot(app, "antidpi")
    watch = _rows(data, "watchlist")
    rows, current, pages = navigation.page_slice(watch, page)
    header = _header("antidpi_watch", len(watch), ("адрес", "адреса", "адресов"))
    if not watch:
        return PagedView(
            text=header
            + "\n\n<i>Под наблюдением никого нет. Сюда попадают адреса с "
            "уликами ниже порога блокировки.</i>",
            empty=True,
        )
    now = data.get("now", 0)
    lines = []
    for row in rows:
        score = float(row.get("score", 0) or 0)
        threshold = float(row.get("threshold", 8) or 8)
        blocked = str(row.get("block_label", "") or "").strip()
        lines.append(
            f"👁 <code>{html.escape(str(row.get('ip', '—')))}</code> · "
            f"<code>{progress_bar(score, maximum=threshold, width=8)}</code> "
            f"{score:.1f}/{threshold:.0f} · "
            f"{html.escape(format_age(row.get('updated'), now=now))}\n"
            f"  {html.escape(str(row.get('reason', '—')))}"
            + (f"\n  <i>{html.escape(blocked)}</i>" if blocked else ""),
        )
    return PagedView(
        text=header + "\n\n" + "\n\n".join(lines),
        addresses=tuple(str(row.get("ip", "")) for row in rows),
        page=current,
        pages=pages,
    )


def honeypot_bans_view(app: ApplicationService, page: int = 1) -> PagedView:
    """Render every address the honeypot trap has caught."""
    data = _snapshot(app, "honeypot")
    banned = _mapping_projection(data.get("banned"))
    ordered = sorted(
        banned.items(),
        key=lambda item: str((item[1] or {}).get("banned_at", "")),
        reverse=True,
    )
    rows, current, pages = navigation.page_slice(ordered, page)
    header = _header("honeypot_bans", len(ordered), ("адрес", "адреса", "адресов"))
    if not ordered:
        return PagedView(
            text=header + "\n\n<i>Ловушка ещё никого не поймала</i>",
            empty=True,
        )
    lines = [
        f"🍯 <code>{html.escape(str(address))}</code> · "
        f"{html.escape(str((metadata or {}).get('banned_at', '—'))[:19])} · "
        f"{html.escape(str((metadata or {}).get('backend', 'firewall')))}"
        for address, metadata in rows
    ]
    return PagedView(
        text=header + "\n\n" + "\n".join(lines),
        addresses=tuple(str(address) for address, _metadata in rows),
        page=current,
        pages=pages,
    )


def _ban_record(app: ApplicationService, address: str) -> dict:
    for row in _rows(_snapshot(app, "antidpi"), "ban_rows"):
        if str(row.get("ip", "")) == address:
            return row
    return {}


def _watch_record(app: ApplicationService, address: str) -> dict:
    for row in _rows(_snapshot(app, "antidpi"), "watchlist"):
        if str(row.get("ip", "")) == address:
            return row
    return {}


def address_card_text(
    app: ApplicationService,
    address: str,
    *,
    lookup_intel=None,
) -> str:
    """Render everything the panel knows about one address."""
    try:
        parsed = ipaddress.ip_address(str(address).strip("[]")).compressed
    except ValueError:
        return (
            "<b>Адрес</b>\n\n"
            "<i>Это не похоже на IP-адрес. Пришлите IPv4 или IPv6.</i>"
        )
    intel = lookup_intel([parsed]).get(parsed, {}) if lookup_intel else {}
    lines = [
        f"<b>🔎 {html.escape(parsed)}</b>",
        _intel_line(intel),
        _antidpi_line(app, parsed),
        _honeypot_line(app, parsed),
    ]
    return "\n\n".join(line for line in lines if line)


def _intel_line(intel: dict) -> str:
    if not intel:
        return ""
    owner = _network_label(intel)
    flag = html.escape(str(intel.get("flag", "🌐")))
    country = html.escape(str(intel.get("country", "") or ""))
    parts = [value for value in (f"{flag} {country}".strip(), owner) if value]
    return " · ".join(html.escape(part) if part is owner else part for part in parts)


def _antidpi_line(app: ApplicationService, address: str) -> str:
    ban = _ban_record(app, address)
    if ban:
        return (
            "<b>AntiDPI:</b> 🔴 заблокирован\n"
            f"Осталось: {html.escape(str(ban.get('remaining_label', '—')))} · "
            f"баллы {float(ban.get('score', 0) or 0):.1f} · "
            f"нарушение #{int(ban.get('offense', 1) or 1)}\n"
            f"Причина: {html.escape(str(ban.get('reason', '—')))}"
        )
    watch = _watch_record(app, address)
    if watch:
        score = float(watch.get("score", 0) or 0)
        threshold = float(watch.get("threshold", 8) or 8)
        blocked = str(watch.get("block_label", "") or "").strip()
        return (
            "<b>AntiDPI:</b> 👁 под наблюдением\n"
            f"Баллы: {score:.1f}/{threshold:.0f}\n"
            f"Сигналы: {html.escape(str(watch.get('reason', '—')))}"
            + (f"\n<i>{html.escape(blocked)}</i>" if blocked else "")
        )
    return "<b>AntiDPI:</b> ✅ улик нет"


def _honeypot_line(app: ApplicationService, address: str) -> str:
    banned = _mapping_projection(_snapshot(app, "honeypot").get("banned"))
    record = banned.get(address)
    if not isinstance(record, dict):
        return "<b>Honeypot:</b> ✅ не срабатывал"
    when = str(record.get("banned_at", "—"))[:19].replace("T", " ")
    return (
        "<b>Honeypot:</b> 🔴 пойман\n"
        f"Время: {html.escape(when)} · "
        f"{html.escape(str(record.get('backend', 'firewall')))}"
    )


__all__ = [
    "PagedView",
    "address_card_text",
    "antidpi_bans_view",
    "antidpi_watch_view",
    "honeypot_bans_view",
]
