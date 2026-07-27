"""Navigation, input, and notification-noise contracts of the admin bot."""
from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hydra.core.state_models import AppState, TelegramConfig
from hydra.plugins.base import PluginStatus
from hydra.services.security_notifications import (
    in_quiet_hours,
    notification_allowed,
)
from hydra.services.telegram import (
    controller_screens,
    navigation,
    security_actions,
    security_monitors,
)
from hydra.services.telegram.controller import AdminBot

ADMIN = "999888"


@pytest.fixture
def application():
    snapshot = {
        "now": 1_800_000_000.0,
        "banned": {},
        "ban_rows": [],
        "watchlist": [],
        "history": [],
        "whitelist": [],
        "events": 0,
        "counters": {"signals": [], "sources": []},
        "port": 9999,
    }
    return SimpleNamespace(
        protocols=SimpleNamespace(
            status=MagicMock(
                return_value=PluginStatus(
                    installed=True,
                    enabled=True,
                    running=True,
                ),
            ),
            statuses=MagicMock(return_value={}),
        ),
        admin=SimpleNamespace(
            load_state=MagicMock(return_value=AppState()),
            system_overview=MagicMock(
                return_value=SimpleNamespace(
                    hostname="hydra",
                    public_ip="203.0.113.1",
                    load_averages=(),
                    memory_total=0,
                    memory_used=0,
                    memory_percent=None,
                    disk_total=0,
                    disk_used=0,
                    disk_percent=None,
                    uptime_seconds=10,
                ),
            ),
            run_command=MagicMock(
                return_value=SimpleNamespace(returncode=1, stdout=""),
            ),
        ),
        plugin_query=MagicMock(return_value=snapshot),
        plugin_action=MagicMock(return_value=False),
    )


def _bot(application):
    bot = AdminBot.__new__(AdminBot)
    bot.admin_chat_id = ADMIN
    bot.application = application
    return bot


def _update(*, data: str = "", text: str = ""):
    query = (
        SimpleNamespace(
            data=data,
            answer=AsyncMock(),
            edit_message_text=AsyncMock(),
            message=SimpleNamespace(text="", text_html=""),
        )
        if data
        else None
    )
    message = SimpleNamespace(text=text, reply_text=AsyncMock())
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=int(ADMIN)),
        effective_chat=SimpleNamespace(id=int(ADMIN)),
        effective_message=query.message if query else message,
        callback_query=query,
    )


def _rendered(update):
    query = update.callback_query
    if query and query.edit_message_text.await_count:
        call = query.edit_message_text.call_args
    else:
        call = update.effective_message.reply_text.call_args
    keyboard = call.kwargs.get("reply_markup")
    callbacks = [
        button.callback_data
        for row in getattr(keyboard, "inline_keyboard", [])
        for button in row
    ]
    return call.args[0], callbacks


def test_every_screen_in_the_graph_has_a_renderer():
    assert set(navigation.SCREENS) == set(controller_screens.screen_names())


def test_breadcrumbs_follow_the_screen_graph():
    assert navigation.breadcrumb("antidpi_bans") == (
        "Control Center › AntiDPI › Блокировки"
    )
    assert navigation.breadcrumb("home") == "Control Center"
    assert navigation.breadcrumb("unknown") == "Control Center"


def test_address_payloads_survive_ipv6_colons_and_carry_their_origin():
    payload = navigation.address_callback("2001:db8::5", "antidpi_bans")
    assert navigation.parse_address(payload) == ("2001:db8::5", "antidpi_bans")
    assert len(payload.encode("utf-8")) <= 64
    # Payloads written before origins existed still open the section root.
    assert navigation.parse_address("ip:203.0.113.9") == (
        "203.0.113.9",
        "antidpi",
    )
    assert navigation.parse_address("view:home") == ("", "")


def test_address_card_returns_to_the_list_it_was_opened_from():
    keyboard = security_actions.address_keyboard(
        "203.0.113.9",
        origin="antidpi_watch",
    )
    labels = {
        button.text: button.callback_data
        for row in keyboard.inline_keyboard
        for button in row
    }
    assert labels["⬅️ Под наблюдением"] == "view:antidpi_watch"
    assert labels["🔄 Обновить"] == "ip:w:203.0.113.9"


def test_view_payloads_round_trip_through_the_parser():
    assert navigation.parse_view("view:antidpi_bans:3") == ("antidpi_bans", 3)
    assert navigation.parse_view("view:antidpi") == ("antidpi", 1)
    assert navigation.parse_view("view:antidpi_bans:абв") == ("antidpi_bans", 1)
    assert navigation.parse_view("ip:1.2.3.4") == ("", 1)
    assert navigation.view_callback("antidpi_bans", 2) == "view:antidpi_bans:2"


def test_pagination_clamps_to_the_available_range():
    rows, page, pages = navigation.page_slice(list(range(12)), page=99, size=5)
    assert (rows, page, pages) == ([10, 11], 3, 3)
    assert navigation.page_slice([], page=1) == ([], 1, 1)


def test_back_button_returns_to_the_parent_not_the_main_menu(application):
    keyboard = security_actions._back_keyboard(refresh="antidpi_details")
    labels = {
        button.text: button.callback_data
        for row in keyboard.inline_keyboard
        for button in row
    }
    assert labels["⬅️ AntiDPI"] == "view:antidpi"
    assert labels["🔄 Обновить"] == "view:antidpi_details"
    assert labels["🏠 Меню"] == "view:home"


def test_paged_callback_routes_to_the_requested_page(application):
    bot = _bot(application)
    update = _update(data="view:antidpi_watch:2")
    renderer = MagicMock(return_value=("ok", None))
    with patch.dict(
        controller_screens.SCREEN_RENDERERS,
        {"antidpi_watch": renderer},
    ):
        asyncio.run(bot.handle_callback(update, MagicMock()))
    renderer.assert_called_once_with(application, "antidpi_watch", 2)


def test_a_bare_ip_message_opens_the_address_card(application):
    bot = _bot(application)
    update = _update(text=" 198.51.100.7 ")
    with patch(
        "hydra.services.telegram.dashboards._lookup_security_intel",
        return_value={},
    ):
        asyncio.run(bot.handle_message(update, MagicMock()))
    text, callbacks = _rendered(update)
    assert "198.51.100.7" in text
    assert "antidpi-ban:198.51.100.7" in callbacks


def test_unknown_command_is_reported_instead_of_showing_the_menu(application):
    bot = _bot(application)
    update = _update(text="/nonsense now")
    asyncio.run(bot.handle_message(update, MagicMock()))
    text, _callbacks = _rendered(update)
    assert "Неизвестная команда" in text
    assert "/nonsense" in text


def test_screen_failures_are_reported_to_the_operator(application):
    bot = _bot(application)
    update = _update(data="view:system")
    broken = MagicMock(side_effect=RuntimeError("systemd недоступен"))
    with patch.dict(
        controller_screens.SCREEN_RENDERERS,
        {"system": broken},
    ):
        asyncio.run(bot.handle_callback(update, MagicMock()))
    text, _callbacks = _rendered(update)
    assert "Не удалось построить экран" in text
    assert "systemd недоступен" in text
    update.callback_query.answer.assert_any_await(
        "Ошибка при обновлении экрана",
        show_alert=True,
    )


def test_quiet_hours_window_wraps_over_midnight():
    state = AppState(
        telegram=TelegramConfig(
            quiet_hours_enabled=True,
            quiet_hours_start=23,
            quiet_hours_end=8,
        ),
    )
    assert in_quiet_hours(state, hour=23) is True
    assert in_quiet_hours(state, hour=3) is True
    assert in_quiet_hours(state, hour=8) is False
    assert in_quiet_hours(state, hour=12) is False


def test_quiet_hours_hold_alerts_but_never_blocks():
    state = AppState(
        telegram=TelegramConfig(
            admin_token="t",
            admin_chat_id=ADMIN,
            quiet_hours_enabled=True,
            quiet_hours_start=23,
            quiet_hours_end=8,
        ),
    )
    assert notification_allowed(state, "antidpi", action="ALERT", hour=2) is False
    assert notification_allowed(state, "antidpi", action="BAN", hour=2) is True
    assert notification_allowed(state, "antidpi", action="ALERT", hour=12) is True


def test_blocks_only_mode_drops_alerts_at_any_hour():
    state = AppState(
        telegram=TelegramConfig(notify_only_blocks=True),
    )
    assert notification_allowed(state, "antidpi", action="ALERT", hour=12) is False
    assert notification_allowed(state, "antidpi", action="BAN", hour=12) is True
    assert notification_allowed(state, "honeypot", action="BAN", hour=3) is True


def test_disabled_category_still_wins_over_blocking_actions():
    state = AppState(telegram=TelegramConfig(notify_antidpi=False))
    assert notification_allowed(state, "antidpi", action="BAN") is False


def test_monitor_backs_off_when_the_host_is_quiet():
    intervals = [
        security_monitors._poll_interval(index) for index in range(0, 20, 5)
    ]
    assert intervals == sorted(intervals)
    assert intervals[0] < intervals[-1]
    assert intervals[-1] >= 15.0


def test_monitor_reacts_immediately_after_a_new_line():
    stop = threading.Event()
    waits: list[float] = []
    lines = [["a"], ["a", "b"], ["a", "b"]]

    def fetch():
        return lines.pop(0) if lines else stop.set() or ["a", "b"]

    def wait(timeout=None):
        waits.append(float(timeout or 0))
        if len(waits) >= 4:
            stop.set()
        return stop.is_set()

    processed: list[str] = []
    with patch.object(stop, "wait", side_effect=wait), \
         patch.object(stop, "is_set", side_effect=[False] * 4 + [True] * 8):
        security_monitors._follow_plugin_log(stop, fetch, processed.append)

    assert processed == ["b"]
    assert security_monitors.BUSY_INTERVAL in waits
