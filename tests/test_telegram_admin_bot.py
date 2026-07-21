"""
tests/test_telegram_admin_bot.py — Tests for new Telegram Admin Bot & notification integration.
"""
from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.state import AppState, TelegramConfig, load_state, save_state
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
    _main_keyboard,
    _notification_settings_text,
    _toggle_notification,
    notification_allowed,
)
from hydra.plugins.antidpi.plugin import AntiDPIPlugin


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


def test_get_system_info_text():
    info = get_system_info_text()
    assert "HYDRA System Information" in info
    assert "Load Average" in info
    assert "RAM" in info
    assert "Диск" in info
    assert "Статус сервисов" in info


def test_get_antidpi_status_text():
    text = get_antidpi_status_text()
    assert "AntiDPI Status" in text
    assert "Заблокировано IP" in text


def test_get_fail2ban_status_text():
    text = get_fail2ban_status_text()
    assert "Fail2ban Status" in text


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
    plugin = AntiDPIPlugin()
    event = {"kind": "malformed_tls", "protocol": "tls", "handshake_ok": False}
    state_file = tmp_path / "antidpi.json"

    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.services.telegram.bot.send_admin_notification") as mock_notify:
        with patch.object(plugin, "_load_state", return_value={"scores": {}, "banned": {}, "whitelist": []}):
            with patch.object(plugin, "_save_state"):
                plugin.observe_event("198.51.100.22", event)
                mock_notify.assert_called()
                msg = mock_notify.call_args[0][0]
                assert mock_notify.call_args.kwargs["category"] == "antidpi"
                assert "AntiDPI · ALERT" in msg
                assert "198.51.100.22" in msg
                assert "Действие" not in msg


def test_single_native_auth_failure_sends_alert_without_banning(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi-auth.json"
    result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=result), \
         patch("hydra.services.telegram.bot.send_admin_notification") as notify:
        banned = plugin.observe_event(
            "198.51.100.44",
            {"kind": "auth_failure", "protocol": "naive", "source": "caddy-naive"},
            now=1000,
        )
    assert banned is False
    notify.assert_called_once()
    assert "auth_failure" in notify.call_args.args[0]


def test_unban_ip_everywhere():
    with patch("hydra.plugins.antidpi.plugin.AntiDPIPlugin.unban", return_value=True), \
         patch("hydra.plugins.honeypot.plugin.HoneypotPlugin.unban", return_value=True):
        with patch("hydra.core.host.HOST.run") as mock_run:
            mock_res = MagicMock()
            mock_res.returncode = 0
            mock_res.stdout = "1.1.1.1 unbanned"
            mock_run.return_value = mock_res
            
            res = unban_ip_everywhere("1.1.1.1")
            assert "Результат разблокировки IP <code>1.1.1.1</code>" in res
            assert "AntiDPI: ✅ Разблокирован" in res
            assert "Honeypot: ✅ Разблокирован" in res
            assert "Fail2ban: ✅ Разблокирован" in res


def test_unban_rejects_invalid_input_before_host_command():
    with patch("hydra.core.host.HOST.run") as mock_run:
        res = unban_ip_everywhere("--help")
    assert "Некорректный IP" in res
    mock_run.assert_not_called()


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


def test_honeypot_notification_is_separate_category():
    with patch("hydra.services.telegram.bot.send_admin_notification") as notify, \
         patch("hydra.plugins.honeypot.plugin.HoneypotPlugin._load_state", return_value={"port": 9999}):
        _process_honeypot_log_line("[2026-07-21T10:00:00] CONNECT 198.51.100.55:45678")
        _process_honeypot_log_line("[2026-07-21T10:00:00] BAN 198.51.100.55 backend=iptables result=FAIL")
        _process_honeypot_log_line("[2026-07-21T10:00:00] BAN 198.51.100.55 backend=iptables result=OK")
    notify.assert_called_once()
    assert notify.call_args.kwargs["category"] == "honeypot"
    message = notify.call_args.args[0]
    assert "Honeypot · BAN" in message
    assert "198.51.100.55" in message
    assert "поймал подключение" not in message


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


def test_expanded_fail2ban_dashboard_includes_policy_and_totals():
    overall = MagicMock(returncode=0, stdout="Jail list: hydra-sshd")
    detail = MagicMock(
        returncode=0,
        stdout=(
            "Currently failed: 2\nTotal failed: 14\nCurrently banned: 1\n"
            "Total banned: 5\nBanned IP list: 198.51.100.9\n"
        ),
    )
    with patch("hydra.plugins.fail2ban.plugin.Fail2banPlugin.status", return_value=MagicMock(running=True)), \
         patch("hydra.plugins.fail2ban.plugin.Fail2banPlugin.jail_options", return_value={
             "hydra-sshd": {"maxretry": "5", "findtime": "600", "bantime": "3600"},
         }), \
         patch("hydra.services.telegram.bot.HOST.run", side_effect=[overall, detail]):
        text = get_fail2ban_dashboard_text()
    assert "Всего банов:</b> 5" in text
    assert "5 попыток за 10м" in text
    assert "198.51.100.9" in text


def test_dedicated_security_dashboards_render(tmp_path):
    with patch("hydra.plugins.antidpi.plugin.AntiDPIPlugin.status") as adpi_status, \
         patch("hydra.plugins.antidpi.plugin.AntiDPIPlugin._load_state", return_value={"banned": {}, "events": 3}), \
         patch("hydra.plugins.honeypot.plugin.HoneypotPlugin.status") as hp_status, \
         patch("hydra.plugins.honeypot.plugin.HoneypotPlugin._load_state", return_value={"port": 9999, "banned": {}, "whitelist": []}):
        adpi_status.return_value = MagicMock(running=True)
        hp_status.return_value = MagicMock(running=True, port=9999)
        assert "защита всей VPS" in get_antidpi_dashboard_text()
        assert "отдельная ловушка" in get_honeypot_status_text()


def test_admin_bot_installer_starts_and_verifies_service():
    from hydra.ui import menus

    state = AppState(telegram=TelegramConfig(
        admin_token="123:TOKEN", admin_chat_id="999888",
    ))
    result = subprocess.CompletedProcess([], 0, "", "")
    with patch.object(menus, "install_service", return_value=True), \
         patch.object(menus.HOST, "run", return_value=result) as run, \
         patch.object(menus, "save_state"), \
         patch.object(menus, "success"), \
         patch.object(menus, "prompt"):
        menus._install_admin_bot(state)

    commands = [call.args[0] for call in run.call_args_list]
    assert ["systemctl", "restart", "hydra-tg-admin.service"] in commands
    assert ["systemctl", "is-active", "--quiet", "hydra-tg-admin.service"] in commands
    assert state.telegram.admin_enabled is True
