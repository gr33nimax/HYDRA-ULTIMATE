"""
tests/test_telegram_admin_bot.py — Tests for new Telegram Admin Bot & notification integration.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from hydra.core.state import AppState, TelegramConfig, load_state, save_state
from hydra.plugins.base import PluginStatus
from hydra.services.admin import SystemOverview
from hydra.services.telegram import security_actions
from hydra.services.telegram.bot import (
    send_admin_notification,
    get_system_info_text,
    get_antidpi_status_text,
    get_antidpi_dashboard_text,
    get_honeypot_status_text,
    get_fail2ban_dashboard_text,
    get_fail2ban_status_text,
    unban_ip_everywhere,
    _process_fail2ban_log_line,
    _process_honeypot_log_line,
    _parse_fail2ban_jail,
    _parse_fail2ban_ban_lines,
    _main_keyboard,
    _notification_settings_text,
    _toggle_notification,
    notification_allowed,
    AdminBot,
    run_admin_bot,
)
from hydra.plugins.antidpi.plugin import AntiDPIPlugin


@pytest.fixture
def application():
    state = AppState()
    statuses = {
        name: PluginStatus(
            installed=False,
            enabled=False,
            running=False,
        )
        for name in ("antidpi", "honeypot", "fail2ban")
    }
    protocols = SimpleNamespace(
        status=MagicMock(side_effect=lambda name: statuses[name]),
        statuses=MagicMock(return_value={}),
        enable=MagicMock(return_value=True),
        disable=MagicMock(return_value=True),
    )
    admin = SimpleNamespace(
        load_state=MagicMock(return_value=state),
        system_overview=MagicMock(
            return_value=SystemOverview(hostname="hydra-test"),
        ),
        run_command=MagicMock(
            return_value=subprocess.CompletedProcess([], 1, "", ""),
        ),
    )
    snapshots = {
        ("antidpi", "management_snapshot"): {
            "banned": {},
            "events": 0,
        },
        ("honeypot", "management_snapshot"): {
            "port": 9999,
            "banned": {},
            "whitelist": [],
        },
        ("fail2ban", "jail_options"): {},
        ("fail2ban", "recent_logs"): [],
    }
    plugin_query = MagicMock(
        side_effect=lambda plugin, query, **_parameters: snapshots[
            (plugin, query)
        ],
    )
    return SimpleNamespace(
        protocols=protocols,
        admin=admin,
        plugin_query=plugin_query,
        plugin_action=MagicMock(return_value=False),
    )


def test_send_admin_notification_without_token():
    state = AppState(telegram=TelegramConfig(admin_token="", admin_chat_id=""))
    assert send_admin_notification("test", state=state) is False


def test_send_admin_notification_success():
    state = AppState(telegram=TelegramConfig(admin_token="123:TOKEN", admin_chat_id="999888"))
    
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = send_admin_notification("Hello Admin", state=state)
        assert result is True

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert "123:TOKEN" in req.full_url
        data = json.loads(req.data.decode("utf-8"))
        assert data["chat_id"] == "999888"
        assert data["text"] == "Hello Admin"


def test_send_admin_notification_includes_inline_keyboard():
    state = AppState(telegram=TelegramConfig(admin_token="123:TOKEN", admin_chat_id="999888"))
    keyboard = {
        "inline_keyboard": [[{
            "text": "🚫 Заблокировать",
            "callback_data": "antidpi-ban:198.51.100.22",
        }]],
    }
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.status = 200
        assert send_admin_notification("Alert", state=state, reply_markup=keyboard) is True
    request = mock_urlopen.call_args.args[0]
    assert json.loads(request.data.decode("utf-8"))["reply_markup"] == keyboard


def test_notification_categories_can_be_disabled():
    state = AppState(telegram=TelegramConfig(
        admin_token="123:TOKEN", admin_chat_id="999888", notify_antidpi=False,
    ))
    assert notification_allowed(state, "antidpi") is False
    with patch("urllib.request.urlopen") as mock_urlopen:
        assert send_admin_notification("probe", state=state, category="antidpi") is False
    mock_urlopen.assert_not_called()


def test_master_notification_switch_can_be_forced():
    state = AppState(telegram=TelegramConfig(
        admin_token="123:TOKEN", admin_chat_id="999888", notifications_enabled=False,
    ))
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.status = 200
        assert send_admin_notification("test", state=state) is False
        assert send_admin_notification("test", state=state, force=True) is True
    assert mock_urlopen.call_count == 1


def test_send_admin_notification_does_not_log_token(capsys):
    state = AppState(telegram=TelegramConfig(admin_token="123:SECRET", admin_chat_id="999888"))
    error = RuntimeError("https://api.telegram.org/bot123:SECRET/sendMessage")
    with patch("urllib.request.urlopen", side_effect=error):
        assert send_admin_notification("test", state=state) is False
    assert "123:SECRET" not in capsys.readouterr().err


def test_get_system_info_text(application):
    info = get_system_info_text(application)
    assert "HYDRA System Information" in info
    assert "hydra-test" in info
    assert "Load Average" in info
    assert "RAM" in info
    assert "Диск" in info
    assert "Статус сервисов" in info
    application.admin.system_overview.assert_called_once_with(
        application.admin.load_state.return_value,
    )


def test_get_antidpi_status_text(application):
    text = get_antidpi_status_text(application)
    assert "AntiDPI Status" in text
    assert "Заблокировано IP" in text


def test_get_fail2ban_status_text(application):
    text = get_fail2ban_status_text(application)
    assert "Fail2ban Status" in text


def test_run_admin_bot_uses_an_injected_application(application):
    with patch("hydra.services.telegram.bot.AdminBot") as bot_type:
        run_admin_bot(
            "123:TOKEN",
            "999888",
            application=application,
        )

    bot_type.assert_called_once_with("123:TOKEN", "999888", application)
    bot_type.return_value.run.assert_called_once_with()


def test_admin_bot_entrypoint_composes_the_application(application):
    from hydra.services.telegram import admin_bot_entrypoint

    state = SimpleNamespace(
        telegram=SimpleNamespace(
            admin_token="123:TOKEN",
            admin_chat_id="999888",
        ),
    )
    with (
        patch.object(admin_bot_entrypoint, "load_state", return_value=state),
        patch.object(
            admin_bot_entrypoint,
            "production_application",
            return_value=application,
        ) as compose,
        patch.object(admin_bot_entrypoint, "run_admin_bot") as run,
    ):
        admin_bot_entrypoint.main()

    compose.assert_called_once_with()
    run.assert_called_once_with(
        "123:TOKEN",
        "999888",
        application=application,
    )


def test_fail2ban_log_processor():
    with patch("hydra.services.telegram.bot.send_admin_notification") as mock_notify:
        _process_fail2ban_log_line("2026-07-20 12:00:00 fail2ban.actions [1234]: NOTICE [hydra-sshd] Ban 192.168.1.50")
        mock_notify.assert_called_once()
        msg = mock_notify.call_args[0][0]
        assert mock_notify.call_args.kwargs["category"] == "fail2ban"
        assert "Fail2ban · BAN" in msg
        assert "hydra-sshd" in msg
        assert "192.168.1.50" in msg


def test_security_event_formatter_escapes_all_dynamic_fields():
    from hydra.services.telegram.bot import format_security_event

    message = format_security_event("Anti<DPI", "alert", [("Source", "a&b")])
    assert message == "<b>Anti&lt;DPI · ALERT</b>\n<b>Source:</b> <code>a&amp;b</code>"


def test_antidpi_observe_event_notification(tmp_path):
    mock_notify = MagicMock(return_value=True)
    plugin = AntiDPIPlugin(notifier=mock_notify)
    event = {"kind": "malformed_tls", "protocol": "tls", "handshake_ok": False}
    state_file = tmp_path / "antidpi.json"

    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file):
        with patch.object(plugin, "_load_state", return_value={"scores": {}, "banned": {}, "whitelist": []}):
            with patch.object(plugin, "_save_state"):
                plugin.observe_event("198.51.100.22", event)
                mock_notify.assert_called()
                component, action, fields = mock_notify.call_args.args[:3]
                assert mock_notify.call_args.kwargs["category"] == "antidpi"
                assert component == "AntiDPI"
                assert action == "ALERT"
                assert ("IP", "198.51.100.22") in fields
                markup = mock_notify.call_args.kwargs["reply_markup"]
                button = markup["inline_keyboard"][0][0]
                assert button["callback_data"] == "antidpi-ban:198.51.100.22"
                assert len(button["callback_data"].encode("utf-8")) <= 64


def test_antidpi_alert_ban_callback_updates_original_message(application):
    bot = AdminBot.__new__(AdminBot)
    bot.admin_chat_id = "999888"
    bot.application = application
    query = SimpleNamespace(
        data="antidpi-ban:198.51.100.22",
        message=SimpleNamespace(text_html="<b>AntiDPI · ALERT</b>", text="AntiDPI · ALERT"),
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
    )
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id="999888"),
        effective_message=query.message,
        callback_query=query,
    )
    result = {
        "ok": True,
        "already_active": False,
        "duration": 0,
        "permanent": True,
        "offense_count": 1,
    }
    with patch(
        "hydra.services.telegram.security_actions.ban_ip_antidpi",
        return_value=result,
    ):
        asyncio.run(bot.handle_callback(update, MagicMock()))

    edited = query.edit_message_text.call_args.args[0]
    assert "AntiDPI · ALERT" in edited
    assert "manual_ban" in edited
    assert "бессрочно" in edited
    assert query.edit_message_text.call_args.kwargs["reply_markup"] is None
    query.answer.assert_awaited_once_with("IP заблокирован")


def test_configured_group_admin_can_use_antidpi_ban_callback(application):
    bot = AdminBot.__new__(AdminBot)
    bot.admin_chat_id = "-1001234567890"
    bot.application = application
    telegram_bot = SimpleNamespace(get_chat_member=AsyncMock(
        return_value=SimpleNamespace(status="administrator"),
    ))
    query = SimpleNamespace(
        data="antidpi-ban:198.51.100.23",
        message=SimpleNamespace(text_html="<b>AntiDPI · ALERT</b>", text="AntiDPI · ALERT"),
        answer=AsyncMock(),
        edit_message_text=AsyncMock(),
    )
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=777),
        effective_chat=SimpleNamespace(id=-1001234567890),
        effective_message=query.message,
        callback_query=query,
        get_bot=MagicMock(return_value=telegram_bot),
    )
    result = {
        "ok": True,
        "already_active": False,
        "duration": 600,
        "offense_count": 1,
    }
    with patch(
        "hydra.services.telegram.security_actions.ban_ip_antidpi",
        return_value=result,
    ):
        asyncio.run(bot.handle_callback(update, MagicMock()))

    telegram_bot.get_chat_member.assert_awaited_once_with(
        chat_id=-1001234567890,
        user_id=777,
    )
    assert "manual_ban" in query.edit_message_text.call_args.args[0]
    query.answer.assert_awaited_once_with("IP заблокирован")


def test_configured_group_regular_member_is_denied_admin_actions():
    bot = AdminBot.__new__(AdminBot)
    bot.admin_chat_id = "-1001234567890"
    telegram_bot = SimpleNamespace(get_chat_member=AsyncMock(
        return_value=SimpleNamespace(status="member"),
    ))
    query = SimpleNamespace(answer=AsyncMock())
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=778),
        effective_chat=SimpleNamespace(id=-1001234567890),
        callback_query=query,
        effective_message=None,
        get_bot=MagicMock(return_value=telegram_bot),
    )

    assert asyncio.run(bot._check_admin(update)) is False
    query.answer.assert_awaited_once_with("Доступ запрещён", show_alert=True)


def test_single_native_auth_failure_sends_alert_without_banning(tmp_path):
    notify = MagicMock(return_value=True)
    plugin = AntiDPIPlugin(notifier=notify)
    state_file = tmp_path / "antidpi-auth.json"
    result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=result):
        banned = plugin.observe_event(
            "198.51.100.44",
            {"kind": "auth_failure", "protocol": "naive", "source": "caddy-naive"},
            now=1000,
        )
    assert banned is False
    notify.assert_called_once()
    component, action, fields = notify.call_args.args[:3]
    assert (component, action) == ("AntiDPI", "ALERT")
    assert ("Event", "auth_failure") in fields


def test_unban_ip_everywhere(application):
    application.plugin_action.side_effect = [True, True]
    application.admin.run_command.return_value = subprocess.CompletedProcess(
        [],
        0,
        "1.1.1.1 unbanned",
        "",
    )

    res = unban_ip_everywhere("1.1.1.1", application)

    assert "Результат разблокировки IP <code>1.1.1.1</code>" in res
    assert "AntiDPI: ✅ Разблокирован" in res
    assert "Honeypot: ✅ Разблокирован" in res
    assert "Fail2ban: ✅ Разблокирован" in res
    assert application.plugin_action.call_args_list == [
        call("antidpi", "unban", raw="1.1.1.1"),
        call("honeypot", "unban", raw="1.1.1.1"),
    ]
    application.admin.run_command.assert_called_once_with(
        ["fail2ban-client", "unban", "1.1.1.1"],
        timeout=10,
        text=True,
    )


def test_unban_rejects_invalid_input_before_host_command(application):
    res = unban_ip_everywhere("--help", application)

    assert "Некорректный IP" in res
    application.plugin_action.assert_not_called()
    application.admin.run_command.assert_not_called()


def test_manual_antidpi_ban_uses_action_boundary(application):
    expected = {
        "ok": True,
        "already_active": False,
        "permanent": True,
    }
    application.plugin_action.return_value = expected

    assert (
        security_actions.ban_ip_antidpi("198.51.100.9", application)
        == expected
    )
    application.plugin_action.assert_called_once_with(
        "antidpi",
        "manual_ban",
        raw="198.51.100.9",
        source="telegram-admin",
    )


def test_controller_honeypot_unban_uses_action_boundary(application):
    application.plugin_action.return_value = True
    bot = AdminBot.__new__(AdminBot)
    bot.application = application
    bot._show = AsyncMock()
    update = SimpleNamespace()

    asyncio.run(
        bot._unban_honeypot(
            update,
            "ask-hp-unban:198.51.100.10",
        ),
    )

    application.plugin_action.assert_called_once_with(
        "honeypot",
        "unban",
        raw="198.51.100.10",
    )
    assert "разблокирован" in bot._show.await_args.args[1]


def test_projected_log_follower_processes_only_new_lines():
    class StopAfterTwoPolls:
        def __init__(self):
            self.polls = 0

        def is_set(self):
            return self.polls >= 2

        def wait(self, _timeout):
            self.polls += 1
            return self.is_set()

    fetch = MagicMock(
        side_effect=[
            ["old record"],
            ["old record", "new record"],
        ],
    )
    process = MagicMock()

    security_actions._follow_plugin_log(
        StopAfterTwoPolls(),
        fetch,
        process,
    )

    process.assert_called_once_with("new record")


def test_notification_toggle_persists_in_state():
    state = AppState()
    save_state(state)
    assert _toggle_notification("notify_antidpi") is False
    assert load_state().telegram.notify_antidpi is False
    assert "AntiDPI: ❌" in _notification_settings_text()


def test_main_keyboard_callback_payloads_fit_telegram_limit():
    keyboard = _main_keyboard()
    callbacks = [
        button.callback_data
        for row in keyboard.inline_keyboard
        for button in row
        if button.callback_data
    ]
    assert {"view:system", "view:antidpi", "view:honeypot", "view:fail2ban", "view:notifications"} <= set(callbacks)
    assert all(len(value.encode("utf-8")) <= 64 for value in callbacks)


def test_honeypot_notification_is_separate_category(application):
    with patch("hydra.services.telegram.bot.send_admin_notification") as notify:
        _process_honeypot_log_line(
            "[2026-07-21T10:00:00] CONNECT 198.51.100.55:45678",
            application,
        )
        _process_honeypot_log_line(
            "[2026-07-21T10:00:00] BAN 198.51.100.55 "
            "backend=iptables result=FAIL",
            application,
        )
        _process_honeypot_log_line(
            "[2026-07-21T10:00:00] BAN 198.51.100.55 "
            "backend=iptables result=OK",
            application,
        )
    notify.assert_called_once()
    assert notify.call_args.kwargs["category"] == "honeypot"
    message = notify.call_args.args[0]
    assert "Honeypot · BAN" in message
    assert "198.51.100.55" in message
    assert "поймал подключение" not in message
    application.plugin_query.assert_called_with(
        "honeypot",
        "management_snapshot",
    )


def test_fail2ban_jail_parser_extracts_full_status():
    parsed = _parse_fail2ban_jail(
        "Currently failed: 2\nTotal failed: 14\nCurrently banned: 1\n"
        "Total banned: 5\nBanned IP list: 198.51.100.9\n"
    )
    assert parsed == {
        "currently_failed": 2,
        "total_failed": 14,
        "currently_banned": 1,
        "total_banned": 5,
        "ips": ["198.51.100.9"],
    }


def test_compact_fail2ban_dashboard_includes_policy_and_latest_geoip(
    application,
):
    overall = MagicMock(returncode=0, stdout="Jail list: hydra-sshd")
    detail = MagicMock(
        returncode=0,
        stdout=(
            "Currently failed: 2\nTotal failed: 14\nCurrently banned: 1\n"
            "Total banned: 5\nBanned IP list: 198.51.100.9\n"
        ),
    )
    application.protocols.status.side_effect = None
    application.protocols.status.return_value = PluginStatus(
        installed=True,
        enabled=True,
        running=True,
    )
    application.admin.run_command.side_effect = [overall, detail]
    application.plugin_query.side_effect = None
    application.plugin_query.return_value = {
        "hydra-sshd": {
            "maxretry": "5",
            "findtime": "600",
            "bantime": "3600",
        },
    }
    with patch(
        "hydra.services.telegram.dashboards._recent_fail2ban_bans",
        return_value=[{
            "ip": "198.51.100.9",
            "jail": "hydra-sshd",
            "when": "2026-07-21 11:42:03",
        }],
    ), patch(
        "hydra.services.telegram.dashboards._lookup_security_intel",
        return_value={
            "198.51.100.9": {
                "flag": "🇷🇺",
                "asn": "AS64500",
                "owner": "Example Net",
            },
        },
    ):
        text = get_fail2ban_dashboard_text(application)
    assert "1</b> активных банов" in text
    assert "hydra-sshd</code> · 1 IP · 5/10м → 1ч" in text
    assert "198.51.100.9" in text
    assert "🇷🇺" in text
    assert "21.07.2026 11:42" in text
    assert "AS64500 Example Net" in text
    assert "Всего ошибок" not in text
    assert "Всего банов" not in text
    application.plugin_query.assert_called_once_with(
        "fail2ban",
        "jail_options",
        state=application.admin.load_state.return_value,
    )


def test_recent_fail2ban_parser_returns_five_unique_latest_bans():
    lines = [
        f"2026-07-21 10:0{index}:00 fail2ban.actions [1]: NOTICE [hydra-sshd] Ban 198.51.100.{index}"
        for index in range(1, 7)
    ]
    lines.append(
        "2026-07-21 10:07:00 fail2ban.actions [1]: NOTICE [hydra-recidive] Ban 198.51.100.6"
    )
    parsed = _parse_fail2ban_ban_lines(lines, 5)
    assert len(parsed) == 5
    assert parsed[0] == {
        "ip": "198.51.100.6", "jail": "hydra-recidive", "when": "2026-07-21 10:07:00",
    }
    assert parsed[-1]["ip"] == "198.51.100.2"


def test_compact_honeypot_dashboard_limits_rows_and_adds_geoip(application):
    banned = {
        f"198.51.100.{index}": {
            "banned_at": f"2026-07-21T10:0{index}:00", "backend": "iptables",
        }
        for index in range(1, 7)
    }
    intel = {
        f"198.51.100.{index}": {"flag": "🇩🇪", "asn": "AS64501", "owner": "Test Network"}
        for index in range(2, 7)
    }
    application.protocols.status.side_effect = None
    application.protocols.status.return_value = PluginStatus(
        installed=True,
        enabled=True,
        running=True,
        port=9999,
    )
    application.plugin_query.side_effect = None
    application.plugin_query.return_value = {
        "port": 9999,
        "banned": banned,
        "whitelist": [],
    }
    with patch(
        "hydra.services.telegram.dashboards._lookup_security_intel",
        return_value=intel,
    ):
        text = get_honeypot_status_text(application)
    assert "<b>🍯 Honeypot</b>" in text
    assert "Активных блокировок:</b> 6" in text
    assert text.count("<code>198.51.100.") == 5
    assert "198.51.100.1" not in text
    assert "🇩🇪" in text
    assert "21.07.2026 10:06" in text
    assert "AS64501 Test Network" in text
    assert "…и ещё" not in text
    application.plugin_query.assert_called_once_with(
        "honeypot",
        "management_snapshot",
    )


def test_admin_bot_installer_starts_and_verifies_service():
    from hydra.ui import menus

    state = AppState(telegram=TelegramConfig(
        admin_token="123:TOKEN", admin_chat_id="999888",
    ))
    install = MagicMock(return_value=SimpleNamespace(ok=True, code=""))
    app = SimpleNamespace(admin=SimpleNamespace(install_admin_bot=install))
    with patch.object(menus, "success") as success_message, \
         patch.object(menus, "prompt"):
        menus._install_admin_bot(state, app)

    install.assert_called_once_with(state)
    success_message.assert_called_once_with(
        "Admin-бот запущен (hydra-tg-admin)",
    )
