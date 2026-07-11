"""
tests/test_diagnostics.py — Тесты для hydra/ui/diagnostics.py.
"""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock
import pytest
import urllib.error

from hydra.ui import diagnostics

class TestDiagnosticsHelpers:
    @patch("socket.socket")
    def test_check_system_ipv6_success(self, mock_socket_class):
        """Проверяет успешное определение поддержки IPv6."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        
        assert diagnostics.check_system_ipv6() is True
        mock_socket_class.assert_called_once()
        mock_socket.connect.assert_called_once_with(("2001:4860:4860::8888", 53))

    @patch("socket.socket")
    def test_check_system_ipv6_failure(self, mock_socket_class):
        """Проверяет поведение при отсутствии поддержки IPv6."""
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = Exception("No IPv6 route")
        mock_socket_class.return_value = mock_socket
        
        assert diagnostics.check_system_ipv6() is False

    @patch("urllib.request.urlopen")
    def test_make_http_request_success(self, mock_urlopen):
        """Проверяет успешное выполнение HTTP-запроса."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"OK Response"
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        res = diagnostics.make_http_request("https://example.com")
        assert res == "OK Response"

    @patch("urllib.request.urlopen")
    def test_make_http_request_http_error(self, mock_urlopen):
        """HTTP-ошибка корректно обрабатывается и возвращает тело ответа."""
        mock_error = urllib.error.HTTPError(
            url="https://example.com",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=MagicMock()
        )
        mock_error.fp.read.return_value = b"Forbidden body"
        mock_urlopen.side_effect = mock_error
        
        res = diagnostics.make_http_request("https://example.com")
        assert res == "Forbidden body"

    @patch("urllib.request.urlopen")
    def test_get_ip_address(self, mock_urlopen):
        """Получение внешнего IP-адреса."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"1.2.3.4\n"
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        ip = diagnostics.get_ip_address(4)
        assert ip == "1.2.3.4"


class TestDiagnosticsGeoIPAndServices:
    @patch("urllib.request.urlopen")
    def test_query_primary_geoip(self, mock_urlopen):
        """Проверка парсинга результатов GeoIP баз."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"country": "DE"}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        res = diagnostics.query_primary_geoip("1.2.3.4", "IPAPI_CO")
        assert res == "DE"

    @patch("urllib.request.urlopen")
    def test_check_custom_service_netflix(self, mock_urlopen):
        """Проверка определения страны библиотеки Netflix."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"client": {"location": {"country": "US"}}}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        res = diagnostics.check_custom_service("Netflix", 4, system_has_ipv6=False)
        assert res == "US"

    @patch("urllib.request.urlopen")
    def test_check_custom_service_chatgpt(self, mock_urlopen):
        """Проверка детекции региона в ChatGPT."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"derived_fields": {"country": "DE"}}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        res = diagnostics.check_custom_service("ChatGPT", 4, system_has_ipv6=False)
        assert res == "DE"


class TestDiagnosticsCensorcheck:
    @patch("urllib.request.urlopen")
    def test_check_domain_censor_accessible(self, mock_urlopen):
        """Успешный статус (200) для доступных доменов."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        status = diagnostics.check_domain_censor("google.com", secure=True)
        assert status == 200

    @patch("urllib.request.urlopen")
    def test_check_domain_censor_timeout(self, mock_urlopen):
        """Блокировка по таймауту возвращает 0."""
        mock_urlopen.side_effect = TimeoutError("Connection timed out")
        
        status = diagnostics.check_domain_censor("youtube.com", secure=True)
        assert status == 0

    @patch("urllib.request.urlopen")
    def test_run_censorcheck_python(self, mock_urlopen):
        """Запуск проверки блокировок для группы доменов."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        res = diagnostics.run_censorcheck_python("geoblock")
        results = res.get("results", [])
        assert len(results) > 0
        assert results[0]["service"] in diagnostics.GEO_BLOCKED_SITES
        assert results[0]["http"]["ipv4"]["status"] == 200
        assert results[0]["https"]["ipv4"]["status"] == 200
