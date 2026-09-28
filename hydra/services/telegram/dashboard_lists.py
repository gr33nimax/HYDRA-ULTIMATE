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
from hydra.utils.format_ru import plural


@dataclass(frozen=True)
class PagedView:
    """One rendered page plus the addresses its rows can open."""

    text: str
    addresses: tuple[str, ...] = ()
    page: int = 1
    pages: int = 1
    empty: bool = False
    extra: dict = field(default_factory=dict)


def _snapshot(app: ApplicationService, plugin: str) -> dict | None:
    """Return the projection, or ``None`` when the source is unavailable.

    A failed query must never render as an empty, healthy list: "no data"
    and "nothing found" are different operator statements.
    """
    try:
        return _mapping_projection(
            app.plugin_query(plugin, "management_snapshot"),
        )
    except Exception:
        return None


def _unavailable(name: str, total: int, noun: tuple[str, str, str]) -> PagedView:
    return PagedView(
        text=_header(name, total, noun) + "\n\n<i>⚠️ Нет данных: источник недоступен</i>",
        empty=True,
    )


def _rows(data: dict | None, key: str) -> list[dict]:
    values = data.get(key, []) if isinstance(data, dict) else []
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def _header(name: str, total: int, noun: tuple[str, str, str]) -> str:
    return f"<b>{html.escape(navigation.breadcrumb(name))}</b>\nВсего: {plural(total, noun)}"


def antidpi_bans_view(app: ApplicationService, page: int = 1) -> PagedView:
    """Render every active AntiDPI ban, one page at a time."""
    data = _snapshot(app, "antidpi")
    if data is None:
        return _unavailable(
            "antidpi_bans",
            0,
            ("блокировка", "блокировки", "блокировок"),
        )
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
        f"<b>{html.escape(str(row.get('protocol', '—')))}</b> · "
        f"{html.escape(str(row.get('remaining_label', '—')))}\n"
        f"  {html.escape(str(row.get('reason', '—')))}\n"
        f"  {html.escape(str(row.get('source', '—')))} · "
        f"нарушение #{_positive_int(row.get('offense'), default=1)}"
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


def honeypot_bans_view(app: ApplicationService, page: int = 1) -> PagedView:
    """Render every address the honeypot trap has caught."""
    data = _snapshot(app, "honeypot")
    if data is None:
        return _unavailable(
            "honeypot_bans",
            0,
            ("адрес", "адреса", "адресов"),
        )
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


def _ban_record(data: dict | None, address: str) -> dict:
    for row in _rows(data, "ban_rows"):
        if str(row.get("ip", "")) == address:
            return row
    return {}


def _address_details(app: ApplicationService, address: str) -> dict | None:
    """Fetch the exact record for one address, tolerating old deployments.

    The exact query answers regardless of list truncation. When it is
    unavailable (older install), the bounded snapshot lists are the honest
    fallback; when even they fail, ``None`` means "no data", never "safe".
    """
    try:
        details = app.plugin_query(
            "antidpi",
            "address_details",
            address=address,
        )
    except Exception:
        details = None
    if isinstance(details, dict) and details.get("degraded"):
        return None
    if isinstance(details, dict) and _is_not_false(details.get("valid")):
        if "ban_rows" in details:
            # Legacy deployment answered with a management snapshot.
            ban = next(
                (row for row in _rows(details, "ban_rows") if str(row.get("ip", "")) == address),
                {},
            )
            return {"ban": ban or None}
        if "tracked" in details:
            # Exact response of the current plugin, found or not.
            return details
    snapshot = _snapshot(app, "antidpi")
    if snapshot is None or snapshot.get("degraded"):
        return None
    return {"ban": _ban_record(snapshot, address) or None}


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
        return "<b>Адрес</b>\n\n<i>Это не похоже на IP-адрес. Пришлите IPv4 или IPv6.</i>"
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
    details = _address_details(app, address)
    if details is None:
        return "<b>AntiDPI:</b> ⚠️ нет данных (источник недоступен)"
    ban = details.get("ban")
    if isinstance(ban, dict):
        return (
            "<b>AntiScan:</b> 🔴 заблокирован\n"
            f"Осталось: {html.escape(str(ban.get('remaining_label', '—')))} · "
            f"{html.escape(str(ban.get('protocol', '—')))} · "
            f"нарушение #{_positive_int(ban.get('offense'), default=1)}\n"
            f"Причина: {html.escape(str(ban.get('reason', '—')))}"
        )
    return "<b>AntiScan:</b> ✅ улик нет"


def _honeypot_line(app: ApplicationService, address: str) -> str:
    data = _snapshot(app, "honeypot")
    if data is None:
        return "<b>Honeypot:</b> ⚠️ нет данных (источник недоступен)"
    banned = _mapping_projection(data.get("banned"))
    record = banned.get(address)
    if not isinstance(record, dict):
        return "<b>Honeypot:</b> ✅ не срабатывал"
    when = str(record.get("banned_at", "—"))[:19].replace("T", " ")
    return (
        "<b>Honeypot:</b> 🔴 пойман\n"
        f"Время: {html.escape(when)} · "
        f"{html.escape(str(record.get('backend', 'firewall')))}"
    )


def _is_not_false(value: object) -> bool:
    """Return False only for the JSON boolean ``false``."""
    return not (isinstance(value, bool) and not value)


def _positive_int(value: object, *, default: int = 0) -> int:
    """Return a non-negative integer from untrusted state, or ``default``."""
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
    "PagedView",
    "address_card_text",
    "antidpi_bans_view",
    "honeypot_bans_view",
]
