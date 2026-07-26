"""Navigation chrome shared by every admin-bot keyboard.

Paging arrows, the parent-aware back row, list keyboards, and the address card
actions live here so screen keyboards only describe their own content.
"""
from __future__ import annotations

from hydra.services.application import ApplicationService
from hydra.services.telegram import navigation
from hydra.services.telegram.sdk import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)

def _back_keyboard(*, refresh: str = "home", extra: list | None = None):
    rows = list(extra or [])
    rows.extend(navigation_rows(refresh))
    return InlineKeyboardMarkup(rows)

def navigation_rows(
    name: str,
    *,
    page: int = 1,
    pages: int = 1,
) -> list[list]:
    """Build paging and parent navigation for one screen.

    Every screen knows its parent, so ``⬅`` returns one level up instead of
    dropping the operator back at the main menu.
    """
    rows: list[list] = []
    if pages > 1:
        rows.append(_paging_row(name, page=page, pages=pages))
    parent = navigation.parent_name(name)
    controls = [
        InlineKeyboardButton(
            "🔄 Обновить",
            callback_data=navigation.view_callback(name, page),
        ),
    ]
    if parent:
        controls.append(
            InlineKeyboardButton(
                f"⬅️ {navigation.screen(parent).title}",
                callback_data=navigation.view_callback(parent),
            ),
        )
    if parent and parent != navigation.HOME.name:
        controls.append(
            InlineKeyboardButton(
                "🏠 Меню",
                callback_data=navigation.view_callback(navigation.HOME.name),
            ),
        )
    rows.append(controls)
    return rows

def _paging_row(name: str, *, page: int, pages: int) -> list:
    previous = page - 1 if page > 1 else pages
    following = page + 1 if page < pages else 1
    return [
        InlineKeyboardButton(
            "◀️",
            callback_data=navigation.view_callback(name, previous),
        ),
        InlineKeyboardButton(
            navigation.page_label(page, pages),
            callback_data=navigation.view_callback(name, page),
        ),
        InlineKeyboardButton(
            "▶️",
            callback_data=navigation.view_callback(name, following),
        ),
    ]

def address_keyboard(address: str, *, origin: str = "antidpi"):
    """Build the action keyboard of one address card.

    Refresh re-opens the card itself; back returns to the list the operator
    came from rather than to the section root.
    """
    safe = str(address).strip()
    parent = navigation.screen(origin)
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "🚫 Заблокировать",
                    callback_data=f"antidpi-ban:{safe}",
                ),
                InlineKeyboardButton(
                    "🔓 Разблокировать",
                    callback_data=f"ask-unban:{safe}",
                ),
            ],
            [
                InlineKeyboardButton(
                    "🔄 Обновить",
                    callback_data=navigation.address_callback(safe, origin),
                ),
                InlineKeyboardButton(
                    f"⬅️ {parent.title}",
                    callback_data=navigation.view_callback(parent.name),
                ),
                InlineKeyboardButton(
                    "🏠 Меню",
                    callback_data=navigation.view_callback(
                        navigation.HOME.name,
                    ),
                ),
            ],
        ],
    )

def antidpi_list_keyboard(
    app: ApplicationService,
    *,
    screen: str,
    page: int,
    pages: int,
    addresses: list[str],
):
    """Build a paged list keyboard whose rows open one address card."""
    del app
    rows = [
        [
            InlineKeyboardButton(
                f"🔎 {address}"[:56],
                callback_data=navigation.address_callback(address, screen),
            ),
        ]
        for address in addresses
    ]
    rows.extend(navigation_rows(screen, page=page, pages=pages))
    return InlineKeyboardMarkup(rows)

def quiet_hours_keyboard(name: str = "quiet"):
    """Build the quiet-hours editor keyboard."""
    rows = [
        [
            InlineKeyboardButton(
                "🌙 Вкл/выкл",
                callback_data="notify:quiet_hours_enabled",
            ),
            InlineKeyboardButton(
                "🔕 Только блокировки",
                callback_data="notify:notify_only_blocks",
            ),
        ],
        [
            InlineKeyboardButton(
                "Начало −1",
                callback_data="quiet:quiet_hours_start:-1",
            ),
            InlineKeyboardButton(
                "Начало +1",
                callback_data="quiet:quiet_hours_start:1",
            ),
        ],
        [
            InlineKeyboardButton(
                "Конец −1",
                callback_data="quiet:quiet_hours_end:-1",
            ),
            InlineKeyboardButton(
                "Конец +1",
                callback_data="quiet:quiet_hours_end:1",
            ),
        ],
    ]
    rows.extend(navigation_rows(name))
    return InlineKeyboardMarkup(rows)

