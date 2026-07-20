"""
tests/test_telegram_admin_bot.py — Tests for new Telegram Admin Bot & notification integration.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.state import AppState, TelegramConfig
from hydra.services.telegram.bot import (
    send_admin_notification,
    get_system_info_text,
    get_antidpi_status_text,
    get_fail2ban_status_text,
    unban_ip_everywhere,
    _process_fail2ban_log_line,
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
        assert "Fail2ban BAN" in msg
        assert "hydra-sshd" in msg
        assert "192.168.1.50" in msg


def test_antidpi_observe_event_notification():
    plugin = AntiDPIPlugin()
    event = {"kind": "malformed_tls", "protocol": "tls", "handshake_ok": False}
    
    with patch("hydra.services.telegram.bot.send_admin_notification") as mock_notify:
        with patch.object(plugin, "_load_state", return_value={"scores": {}, "banned": {}, "whitelist": []}):
            with patch.object(plugin, "_save_state"):
                plugin.observe_event("198.51.100.22", event)
                mock_notify.assert_called()
                msg = mock_notify.call_args[0][0]
                assert "AntiDPI Alert" in msg
                assert "198.51.100.22" in msg


def test_unban_ip_everywhere():
    with patch("hydra.plugins.antidpi.plugin.AntiDPIPlugin.unban", return_value=True):
        with patch("hydra.core.host.HOST.run") as mock_run:
            mock_res = MagicMock()
            mock_res.returncode = 0
            mock_res.stdout = "1.1.1.1 unbanned"
            mock_run.return_value = mock_res
            
            res = unban_ip_everywhere("1.1.1.1")
            assert "Результат разблокировки IP <code>1.1.1.1</code>" in res
            assert "AntiDPI: ✅ Разблокирован" in res
            assert "Fail2ban: ✅ Разблокирован" in res
