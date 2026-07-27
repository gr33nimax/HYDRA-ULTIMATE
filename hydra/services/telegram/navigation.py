"""Screen graph, breadcrumbs, and pagination for the Telegram admin adapter.

The adapter used to be a flat set of views: every screen rebuilt the same
message, every "back" button led to the main menu, and long lists were silently
truncated. This module owns the missing structure — which screen belongs under
which, how a page is addressed, and how a callback payload is parsed — as pure
data, so keyboards, views, and routing cannot disagree about it.
"""
from __future__ import annotations

from dataclasses import dataclass

PAGE_SIZE = 5
MAX_PAGES = 99
VIEW_PREFIX = "view"
IP_PREFIX = "ip"


@dataclass(frozen=True)
class Screen:
    """One addressable screen of the admin bot."""

    name: str
    title: str
    parent: str = ""
    paged: bool = False


SCREENS: dict[str, Screen] = {
    screen.name: screen
    for screen in (
        Screen("home", "Control Center"),
        Screen("system", "Система", "home"),
        Screen("antidpi", "AntiDPI", "home"),
        Screen("antidpi_details", "Подробно", "antidpi"),
        Screen("antidpi_bans", "Блокировки", "antidpi", paged=True),
        Screen("antidpi_watch", "Под наблюдением", "antidpi", paged=True),
        Screen("honeypot", "Honeypot", "home"),
        Screen("honeypot_bans", "Пойманные адреса", "honeypot", paged=True),
        Screen("fail2ban", "Fail2ban", "home"),
        Screen("notifications", "Уведомления", "home"),
        Screen("quiet", "Тихие часы", "notifications"),
    )
}

HOME = SCREENS["home"]


def screen(name: object) -> Screen:
    """Return one screen, falling back to the root for unknown names."""
    return SCREENS.get(str(name or "").strip(), HOME)


def parent_name(name: object) -> str:
    """Return the parent screen name, or an empty string at the root."""
    return screen(name).parent


def breadcrumb(name: object) -> str:
    """Render the path from the root to this screen."""
    trail = []
    current = screen(name)
    seen: set[str] = set()
    while current.name not in seen:
        seen.add(current.name)
        trail.append(current.title)
        if not current.parent:
            break
        current = screen(current.parent)
    return " › ".join(reversed(trail))


def view_callback(name: object, page: int = 1) -> str:
    """Build the callback payload that addresses one screen page."""
    target = screen(name).name
    if page > 1:
        return f"{VIEW_PREFIX}:{target}:{int(page)}"
    return f"{VIEW_PREFIX}:{target}"


def parse_view(data: object) -> tuple[str, int]:
    """Parse ``view:<screen>[:<page>]`` into a screen name and page number."""
    raw = str(data or "")
    if not raw.startswith(f"{VIEW_PREFIX}:"):
        return "", 1
    parts = raw.split(":")
    name = parts[1] if len(parts) > 1 else ""
    page = 1
    if len(parts) > 2:
        try:
            page = max(1, min(MAX_PAGES, int(parts[2])))
        except (TypeError, ValueError):
            page = 1
    return name, page


ORIGIN_CODES: dict[str, str] = {
    "a": "antidpi",
    "b": "antidpi_bans",
    "w": "antidpi_watch",
    "h": "honeypot_bans",
}
_ORIGIN_BY_SCREEN = {screen: code for code, screen in ORIGIN_CODES.items()}


def address_callback(address: object, origin: str = "antidpi") -> str:
    """Build the payload that opens one address card from a given screen."""
    code = _ORIGIN_BY_SCREEN.get(str(origin), "a")
    return f"{IP_PREFIX}:{code}:{str(address).strip()}"


def parse_address(data: object) -> tuple[str, str]:
    """Parse ``ip:<origin>:<address>`` into ``(address, origin screen)``.

    The address is split off with a bounded split so IPv6 colons survive, and
    payloads without an origin code stay supported.
    """
    raw = str(data or "")
    if not raw.startswith(f"{IP_PREFIX}:"):
        return "", ""
    parts = raw.split(":", 2)
    if len(parts) == 3 and parts[1] in ORIGIN_CODES:
        return parts[2], ORIGIN_CODES[parts[1]]
    return raw[len(IP_PREFIX) + 1:], "antidpi"


def page_count(total: object, size: int = PAGE_SIZE) -> int:
    """Return how many pages a list of ``total`` items needs."""
    try:
        items = max(0, int(total))
    except (TypeError, ValueError):
        items = 0
    span = max(1, int(size))
    return max(1, min(MAX_PAGES, -(-items // span)))


def page_slice(
    items: object,
    page: int = 1,
    size: int = PAGE_SIZE,
) -> tuple[list, int, int]:
    """Return ``(rows, page, pages)`` clamped to the available range."""
    values = list(items or [])
    span = max(1, int(size))
    pages = page_count(len(values), span)
    try:
        current = max(1, min(pages, int(page)))
    except (TypeError, ValueError):
        current = 1
    start = (current - 1) * span
    return values[start:start + span], current, pages


def page_label(page: int, pages: int) -> str:
    """Render the page indicator shown between the paging arrows."""
    return f"стр. {int(page)}/{int(pages)}"


__all__ = [
    "HOME",
    "IP_PREFIX",
    "ORIGIN_CODES",
    "PAGE_SIZE",
    "SCREENS",
    "VIEW_PREFIX",
    "Screen",
    "address_callback",
    "breadcrumb",
    "parse_address",
    "page_count",
    "page_label",
    "page_slice",
    "parent_name",
    "parse_view",
    "screen",
    "view_callback",
]
