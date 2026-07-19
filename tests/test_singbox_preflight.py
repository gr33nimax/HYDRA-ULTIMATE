from unittest.mock import MagicMock, patch

from hydra.core import singbox
from hydra.core.singbox import _preflight_conflicts


def test_preflight_accepts_unique_inbounds():
    config = {
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080},
            {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 8080},
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    assert _preflight_conflicts(config) == []


def test_preflight_detects_duplicate_port_and_tag():
    config = {
        "inbounds": [
            {"type": "x", "tag": "same", "listen": "0.0.0.0", "listen_port": 443},
            {"type": "y", "tag": "other", "listen": "0.0.0.0", "listen_port": 443},
        ],
        "outbounds": [{"type": "direct", "tag": "same"}],
    }
    errors = _preflight_conflicts(config)
    assert any("порт 443" in error for error in errors)
    assert any("tag 'same'" in error for error in errors)


def test_preflight_detects_duplicate_sni_case_insensitive():
    config = {
        "inbounds": [
            {
                "type": "tls",
                "tag": "first",
                "listen": "0.0.0.0",
                "listen_port": 443,
                "tls": {"server_name": "Example.COM"},
            },
            {
                "type": "tls",
                "tag": "second",
                "listen": "127.0.0.1",
                "listen_port": 8443,
                "tls": {"server_name": "example.com"},
            },
        ]
    }
    errors = _preflight_conflicts(config)
    assert any("SNI 'example.com'" in error for error in errors)


def test_preflight_ignores_ephemeral_ports():
    config = {
        "inbounds": [
            {"type": "x", "tag": "first", "listen": "0.0.0.0", "listen_port": 0},
            {"type": "y", "tag": "second", "listen": "0.0.0.0", "listen_port": 0},
        ]
    }
    assert _preflight_conflicts(config) == []


def test_wait_until_stable_requires_consecutive_active_checks():
    with patch.object(singbox, "is_running", side_effect=[True, True, True]) as running, \
         patch.object(singbox.time, "sleep"):
        assert singbox.wait_until_stable(checks=3, interval=0) is True
    assert running.call_count == 3


def test_wait_until_stable_stops_on_first_failure():
    with patch.object(singbox, "is_running", side_effect=[True, False]) as running, \
         patch.object(singbox.time, "sleep"):
        assert singbox.wait_until_stable(checks=3, interval=0) is False
    assert running.call_count == 2


def test_reload_reports_runtime_failure():
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with patch.object(singbox, "is_running", return_value=True), \
         patch.object(singbox, "_run", return_value=completed), \
         patch.object(singbox, "wait_until_stable", return_value=False), \
         patch.object(singbox, "_service_failure_detail", return_value="процесс завершён"), \
         patch.object(singbox, "_log"):
        assert singbox.reload() is False
    assert "процесс завершён" in singbox.last_error()


def test_reload_clears_previous_error_after_stable_start():
    completed = MagicMock(returncode=0, stdout="", stderr="")
    singbox._set_error("старая ошибка")
    with patch.object(singbox, "is_running", return_value=True), \
         patch.object(singbox, "_run", return_value=completed), \
         patch.object(singbox, "wait_until_stable", return_value=True):
        assert singbox.reload() is True
    assert singbox.last_error() == ""
