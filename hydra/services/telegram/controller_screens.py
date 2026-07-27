"""Screen registry of the admin bot.

Each entry renders one addressable screen into ``(text, keyboard)``. Routing,
authorization, and transport live in the controller; what a screen *is* lives
here, so a new screen never has to be wired into four different files.
"""
from __future__ import annotations

from collections.abc import Callable

from hydra.services.application import ApplicationService
from hydra.services.telegram import (
    dashboard_lists,
    dashboards,
    navigation,
    security_actions,
)

Rendered = tuple[str, object]
Renderer = Callable[[ApplicationService, str, int], Rendered]


def _home(app: ApplicationService, name: str, page: int) -> Rendered:
    del app, name, page
    return (
        "<b>🛡️ HYDRA Control Center</b>\n\n"
        "Управление защитой и мониторингом VPS.\n"
        "Пришлите IP-адрес сообщением, чтобы открыть карточку адреса.",
        security_actions._main_keyboard(),
    )


def _system(app: ApplicationService, name: str, page: int) -> Rendered:
    del name, page
    return (
        dashboards.get_system_info_text(app),
        security_actions._back_keyboard(refresh="system"),
    )


def _antidpi(app: ApplicationService, name: str, page: int) -> Rendered:
    del name, page
    return (
        dashboards.get_antidpi_dashboard_text(app),
        security_actions._antidpi_keyboard(app),
    )


def _antidpi_details(app: ApplicationService, name: str, page: int) -> Rendered:
    del page
    return (
        dashboards.get_antidpi_status_text(app),
        security_actions._back_keyboard(refresh=name),
    )


def _paged(
    view: dashboard_lists.PagedView,
    *,
    name: str,
    app: ApplicationService,
) -> Rendered:
    return (
        view.text,
        security_actions.antidpi_list_keyboard(
            app,
            screen=name,
            page=view.page,
            pages=view.pages,
            addresses=[address for address in view.addresses if address],
        ),
    )


def _antidpi_bans(app: ApplicationService, name: str, page: int) -> Rendered:
    return _paged(
        dashboard_lists.antidpi_bans_view(app, page),
        name=name,
        app=app,
    )


def _antidpi_watch(app: ApplicationService, name: str, page: int) -> Rendered:
    return _paged(
        dashboard_lists.antidpi_watch_view(app, page),
        name=name,
        app=app,
    )


def _honeypot(app: ApplicationService, name: str, page: int) -> Rendered:
    del name, page
    return (
        dashboards.get_honeypot_status_text(app),
        security_actions._honeypot_keyboard(app),
    )


def _honeypot_bans(app: ApplicationService, name: str, page: int) -> Rendered:
    return _paged(
        dashboard_lists.honeypot_bans_view(app, page),
        name=name,
        app=app,
    )


def _fail2ban(app: ApplicationService, name: str, page: int) -> Rendered:
    del name, page
    return (
        dashboards.get_fail2ban_dashboard_text(app),
        security_actions._fail2ban_keyboard(app),
    )


def _notifications(app: ApplicationService, name: str, page: int) -> Rendered:
    del app, name, page
    return (
        security_actions._notification_settings_text(),
        security_actions._notification_keyboard(),
    )


def _quiet(app: ApplicationService, name: str, page: int) -> Rendered:
    del app, page
    return (
        security_actions.quiet_hours_text(),
        security_actions.quiet_hours_keyboard(name),
    )


SCREEN_RENDERERS: dict[str, Renderer] = {
    "home": _home,
    "system": _system,
    "antidpi": _antidpi,
    "antidpi_details": _antidpi_details,
    "antidpi_bans": _antidpi_bans,
    "antidpi_watch": _antidpi_watch,
    "honeypot": _honeypot,
    "honeypot_bans": _honeypot_bans,
    "fail2ban": _fail2ban,
    "notifications": _notifications,
    "quiet": _quiet,
}


def render_address_card(
    app: ApplicationService,
    address: str,
    origin: str = "antidpi",
) -> Rendered:
    """Render one address card with its actions."""
    text = dashboard_lists.address_card_text(
        app,
        address,
        lookup_intel=dashboards._lookup_security_intel,
    )
    return (
        text,
        security_actions.address_keyboard(address, origin=origin),
    )


def screen_names() -> tuple[str, ...]:
    """Return every renderable screen, for routing and tests."""
    return tuple(sorted(SCREEN_RENDERERS))


def is_known(name: object) -> bool:
    return str(name or "") in SCREEN_RENDERERS


__all__ = [
    "SCREEN_RENDERERS",
    "Rendered",
    "is_known",
    "render_address_card",
    "screen_names",
]
