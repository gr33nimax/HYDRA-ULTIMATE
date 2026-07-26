"""Rendering contracts for the AntiDPI TUI panels and Telegram dashboards."""
from __future__ import annotations

import re
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra.plugins.antidpi.projection import management_projection
from hydra.plugins.base import PluginStatus
from hydra.services.telegram import dashboards, security_actions
from hydra.ui.plugin_managers import _antidpi_views as views

NOW = 1_800_000_000.0
IPV6 = "2001:db8:1234:5678:9abc:def0:1234:5678"

STATE = {
    "events": 18432,
    "last_event_at": NOW - 42,
    "last_event_source": "kernel-firewall",
    "whitelist": ["203.0.113.10"],
    "notification_stats": {"delivered": 27, "failed": 2},
    "suppressed_ban_notifications": 5,
    "ban_failures": {"count": 3, "last_at": NOW - 900, "last_ip": "198.51.100.77"},
    "banned": {
        "198.51.100.5": {
            "at": NOW - 1200,
            "duration": 86400,
            "score": 14.0,
            "offense_count": 3,
            "signals": ["active_decoy_probe", "port_sweep"],
            "source": "caddy-decoy",
            "protocol": "https",
        },
        IPV6: {
            "at": NOW - 100,
            "duration": 600,
            "score": 8.5,
            "signals": ["malformed_tls"],
            "source": "journal",
            "protocol": "shadowtls",
        },
    },
    "history": [
        {
            "ip": "198.51.100.30",
            "at": NOW - 90000,
            "score": 8.0,
            "status": "unbanned",
            "signals": ["port_scan"],
        },
    ],
    "scores": {
        "203.0.113.77": {
            "score": 6.0,
            "verified_score": 3.0,
            "updated": NOW,
            "signals": ["unknown_sni", "handshake_failure"],
        },
    },
    "signal_counts": {"unknown_sni": 40, "port_scan": 10},
    "source_counts": {"kernel-firewall": 30},
}


def _snapshot() -> dict:
    return management_projection(STATE, now=NOW)


def _plain(lines: list[str]) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", "\n".join(lines))


def _application(snapshot: dict, *, running: bool = True):
    return SimpleNamespace(
        protocols=SimpleNamespace(
            status=MagicMock(
                return_value=PluginStatus(
                    installed=True,
                    enabled=running,
                    running=running,
                ),
            ),
        ),
        plugin_query=MagicMock(return_value=snapshot),
    )


def test_tui_status_panel_reports_health_delivery_and_enforcement_gaps():
    health = SimpleNamespace(
        healthy=False,
        checks={"service": True, "firewall": False, "scan_telemetry": False},
    )
    text = _plain(
        views.status_lines(running=True, health=health, data=_snapshot()),
    )

    assert "требует внимания" in text
    assert "правила DROP в INPUT, телеметрия сканирования" in text
    assert "18 432" in text
    assert "42с назад (телеметрия ядра)" in text
    assert "2 активные" in text
    assert "1 адрес ·" in text
    assert "1 запись" in text
    assert "не применено банов: 3" in text


def test_tui_status_panel_stays_quiet_when_everything_is_healthy():
    healthy = SimpleNamespace(healthy=True, checks={"service": True})
    data = _snapshot()
    data.pop("ban_failures")
    text = _plain(views.status_lines(running=True, health=healthy, data=data))

    assert "исправна" in text
    assert "Проблемы" not in text
    assert "не применено банов" not in text


def test_tui_ban_table_keeps_long_ipv6_intact_and_translates_evidence():
    lines = views.ban_table(_snapshot())
    text = _plain(lines)

    assert IPV6 in text
    assert all(len(line) <= 78 for line in _plain(lines).splitlines())
    assert "активная проверка decoy, перебор разных портов" in text
    assert "decoy-сайт · https · срок 1д · нарушение #3" in text
    assert "🔴 23ч 40м" in text


def test_tui_ban_table_and_history_report_empty_states():
    assert "Активных блокировок нет" in _plain(views.ban_table({}))
    assert "Завершённых записей нет" in _plain(views.history_table({}))


def test_tui_history_hides_addresses_that_are_still_banned():
    data = _snapshot()
    data["history"] = [
        {"ip": "198.51.100.5", "at": NOW, "status": "active", "signals": []},
        *data["history"],
    ]
    text = _plain(views.history_table(data))

    assert "198.51.100.30" in text
    assert "198.51.100.5" not in text
    assert "снят" in text


def test_tui_watchlist_shows_unverified_evidence_below_the_ban_threshold():
    text = _plain(views.watchlist_table(_snapshot()))

    assert "203.0.113.77" in text
    assert "6.0" in text
    assert "неизвестный SNI, ошибка handshake" in text
    assert "Подтверждено: 3.0" in text


def test_tui_watchlist_explains_the_empty_state():
    assert "Под наблюдением никого нет" in _plain(views.watchlist_table({}))


def test_tui_counter_panel_uses_translated_labels():
    text = _plain(views.counter_lines(_snapshot()))

    assert "неизвестный SNI" in text
    assert "телеметрия ядра" in text
    assert "нет данных" not in text
    assert "нет данных" in _plain(views.counter_lines({}))


def test_telegram_dashboard_renders_labels_geoip_and_watchlist():
    intel = {
        "198.51.100.5": {
            "flag": "🇩🇪",
            "asn": "AS64501",
            "owner": "Test Network",
        },
    }
    with patch.object(
        dashboards,
        "_lookup_security_intel",
        return_value=intel,
    ) as lookup:
        text = dashboards.get_antidpi_dashboard_text(_application(_snapshot()))

    lookup.assert_called_once()
    assert "🟢 работает" in text
    assert "<b>Блокировки:</b> 2 активные" in text
    assert "🇩🇪 <code>198.51.100.5</code>" in text
    assert "AS64501 Test Network" in text
    assert "активная проверка decoy, перебор разных портов" in text
    assert "23ч 40м" in text
    assert "Под наблюдением</b>\n👁 <code>203.0.113.77</code>" in text
    assert "Firewall отклонил блокировок:</b> 3" in text
    assert text.count("<b>") == text.count("</b>")


def test_telegram_detail_view_adds_counters_whitelist_and_full_ban_list():
    text = dashboards.get_antidpi_status_text(_application(_snapshot()))

    assert "AntiDPI Status" in text
    assert "Заблокировано IP:</b> 2" in text
    assert "<b>Сигналы</b>" in text
    assert "неизвестный SNI — 40" in text
    assert "телеметрия ядра — 30" in text
    assert "<b>Whitelist:</b> 1 запись" in text
    assert "Адресов под учётом:</b> 1" in text


def test_telegram_views_survive_a_failing_plugin_query():
    app = SimpleNamespace(
        protocols=SimpleNamespace(
            status=MagicMock(
                return_value=PluginStatus(
                    installed=False,
                    enabled=False,
                    running=False,
                ),
            ),
        ),
        plugin_query=MagicMock(side_effect=RuntimeError("state unavailable")),
    )

    dashboard = dashboards.get_antidpi_dashboard_text(app)
    detail = dashboards.get_antidpi_status_text(app)

    assert "🔴 не установлен" in dashboard
    assert "Блокировок нет" in dashboard
    assert "Нет заблокированных IP" in detail
    assert "нет данных" in detail


@contextmanager
def _tui_patches(manager, **extra):
    """Silence terminal output and script the operator's answers."""
    with ExitStack() as stack:
        mocks = {
            name: stack.enter_context(patch.object(manager, name))
            for name in ("clear", "panel", "info", "success", "warn", "error")
        }
        for name, value in extra.items():
            mocks[name] = stack.enter_context(
                patch.object(manager, name, **value),
            )
        yield SimpleNamespace(**mocks)


def test_tui_unban_accepts_row_numbers_and_literal_addresses():
    from hydra.ui.plugin_managers import antidpi as manager

    assert manager._resolve_targets(
        "2, 203.0.113.1 nonsense 2",
        ["198.51.100.5", IPV6],
    ) == [IPV6, "203.0.113.1"]


def test_tui_ban_view_unbans_every_selected_row():
    from hydra.core.state_models import AppState
    from hydra.ui.plugin_managers import antidpi as manager

    app = _application(_snapshot())
    app.plugin_command = MagicMock(return_value=True)
    state = AppState()
    with _tui_patches(
        manager,
        prompt={"side_effect": ["1 203.0.113.9", "", ""]},
    ) as ui:
        manager._bans(state, app)
        assert ui.success.call_count == 2

    unbanned = [
        call.kwargs["address"] for call in app.plugin_command.call_args_list
    ]
    # Row 1 is the newest ban, which is the IPv6 address.
    assert unbanned == [IPV6, "203.0.113.9"]
    assert app.plugin_command.call_args.args[1:] == (
        "antidpi",
        "unban_address",
    )


def test_tui_manual_ban_reports_a_rejected_address():
    from hydra.ui.plugin_managers import antidpi as manager

    app = _application(_snapshot())
    app.plugin_action = MagicMock(return_value={"ok": False, "error": "whitelisted"})
    with _tui_patches(manager, prompt={"return_value": "203.0.113.10"}) as ui:
        manager._manual_ban(app)
        ui.error.assert_called_once_with("Адрес находится в whitelist")

    app.plugin_action.assert_called_once_with(
        "antidpi",
        "manual_ban",
        raw="203.0.113.10",
        source="tui",
    )


def test_tui_selftest_surfaces_a_host_error_instead_of_crashing():
    from hydra.core.state_models import AppState
    from hydra.ui.plugin_managers import antidpi as manager

    app = _application(_snapshot())
    app.plugin_action = MagicMock(side_effect=RuntimeError("only on Linux"))
    with _tui_patches(
        manager,
        prompt={"return_value": ""},
        confirm={"return_value": True},
    ) as ui:
        manager._selftest(AppState(), app)
        assert "only on Linux" in ui.error.call_args.args[0]


def test_tui_selftest_is_skipped_without_confirmation():
    from hydra.core.state_models import AppState
    from hydra.ui.plugin_managers import antidpi as manager

    app = _application(_snapshot())
    app.plugin_action = MagicMock()
    with _tui_patches(
        manager,
        prompt={"return_value": ""},
        confirm={"return_value": False},
    ):
        manager._selftest(AppState(), app)

    app.plugin_action.assert_not_called()


def test_details_callback_is_routed_to_the_detailed_status_view():
    import asyncio
    from unittest.mock import AsyncMock

    from hydra.services.telegram.controller import AdminBot

    bot = AdminBot.__new__(AdminBot)
    bot.admin_chat_id = "999888"
    bot.application = _application(_snapshot())
    query = SimpleNamespace(
        data="view:antidpi_details",
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
        message=SimpleNamespace(text="AntiDPI"),
    )
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=999888),
        effective_chat=SimpleNamespace(id=999888),
        effective_message=query.message,
        callback_query=query,
    )

    asyncio.run(bot.handle_callback(update, MagicMock()))

    text = query.edit_message_text.call_args.args[0]
    assert "AntiDPI Status" in text
    callbacks = [
        button.callback_data
        for row in query.edit_message_text.call_args.kwargs[
            "reply_markup"
        ].inline_keyboard
        for button in row
    ]
    assert "view:antidpi" in callbacks
    assert "view:antidpi_details" in callbacks


def test_telegram_antidpi_keyboard_offers_drilldown_routes():
    keyboard = security_actions._antidpi_keyboard(_application(_snapshot()))
    callbacks = [
        button.callback_data
        for row in keyboard.inline_keyboard
        for button in row
    ]

    assert {
        "ask:antidpi_toggle",
        "view:antidpi_details",
        "view:antidpi_bans",
        "view:antidpi_watch",
        "view:home",
    } <= set(callbacks)
    assert all(
        len(callback.encode("utf-8")) <= 64
        for callback in callbacks
        if callback
    )


def test_telegram_ban_list_is_paged_and_rows_open_an_address_card():
    from hydra.services.telegram import controller_screens

    snapshot = _snapshot()
    snapshot["ban_rows"] = [
        {
            "ip": f"198.51.100.{index}",
            "score": 9.0,
            "icon": "🔴",
            "remaining_label": "10м",
            "reason": "повреждённый TLS ClientHello",
            "source": "журнал протокола",
            "offense": 1,
        }
        for index in range(1, 13)
    ]
    app = _application(snapshot)

    text, keyboard = controller_screens.SCREEN_RENDERERS["antidpi_bans"](
        app,
        "antidpi_bans",
        2,
    )
    callbacks = [
        button.callback_data
        for row in keyboard.inline_keyboard
        for button in row
    ]

    assert "Всего: 12 блокировок" in text
    assert "стр. 2/3" in [
        button.text
        for row in keyboard.inline_keyboard
        for button in row
    ]
    # Rows carry the list they came from, so the card can return to it.
    assert "ip:b:198.51.100.6" in callbacks
    assert "view:antidpi_bans:3" in callbacks
    assert "view:antidpi" in callbacks


def test_telegram_address_card_reports_every_source():
    from hydra.services.telegram import controller_screens

    snapshot = _snapshot()
    app = _application(snapshot)
    app.plugin_query = MagicMock(
        side_effect=lambda plugin, query, **_: (
            snapshot
            if plugin == "antidpi"
            else {
                "banned": {
                    "198.51.100.5": {
                        "banned_at": "2026-07-26T10:00:00",
                        "backend": "iptables",
                    },
                },
            }
        ),
    )
    with patch(
        "hydra.services.telegram.dashboards._lookup_security_intel",
        return_value={},
    ):
        text, keyboard = controller_screens.render_address_card(
            app,
            "198.51.100.5",
        )
    callbacks = [
        button.callback_data
        for row in keyboard.inline_keyboard
        for button in row
    ]

    assert "198.51.100.5" in text
    assert "AntiDPI:</b> 🔴 заблокирован" in text
    assert "Honeypot:</b> 🔴 пойман" in text
    assert "antidpi-ban:198.51.100.5" in callbacks
    assert "ask-unban:198.51.100.5" in callbacks


def test_telegram_address_card_rejects_non_addresses():
    from hydra.services.telegram import controller_screens

    text, _keyboard = controller_screens.render_address_card(
        _application(_snapshot()),
        "не-адрес",
    )
    assert "не похоже на IP-адрес" in text
