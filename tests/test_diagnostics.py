"""Герметичные контрактные тесты для :mod:`hydra.ui.diagnostics`."""
from __future__ import annotations

import io
import json
import socket
import ssl
import urllib.error
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from hydra.ui import diagnostics


def response(body: bytes = b"", *, status: int = 200, headers=None):
    """Создать context manager, похожий на результат urlopen()."""
    resp = MagicMock()
    resp.read.return_value = body
    resp.status = status
    resp.headers = headers or {}
    cm = MagicMock()
    cm.__enter__.return_value = resp
    return cm


@pytest.fixture(autouse=True)
def reset_ip_selector():
    diagnostics._thread_local.ip_version = None
    yield
    diagnostics._thread_local.ip_version = None


@pytest.fixture
def resolved_dns(monkeypatch):
    monkeypatch.setattr(
        diagnostics.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0))],
    )


class TestSocketAndPackageHelpers:
    @pytest.mark.parametrize(
        ("version", "expected_family"),
        [(None, 0), (4, socket.AF_INET), (6, socket.AF_INET6)],
    )
    def test_filtered_getaddrinfo_selects_family(self, version, expected_family):
        diagnostics._thread_local.ip_version = version
        with patch.object(diagnostics, "original_getaddrinfo", return_value=["ok"]) as original:
            assert diagnostics.filtered_getaddrinfo("example.com", 443) == ["ok"]
        original.assert_called_once_with("example.com", 443, expected_family, 0, 0, 0)

    @pytest.mark.parametrize("connect_error, expected", [(None, True), (OSError("no route"), False)])
    def test_check_system_ipv6_closes_socket(self, connect_error, expected):
        sock = MagicMock()
        if connect_error:
            sock.connect.side_effect = connect_error
        socket_cm = MagicMock()
        socket_cm.__enter__.return_value = sock
        with patch.object(diagnostics.socket, "socket", return_value=socket_cm) as socket_class:
            assert diagnostics.check_system_ipv6() is expected
        socket_class.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout.assert_called_once_with(1.0)
        sock.connect.assert_called_once_with(("2001:4860:4860::8888", 53))
        socket_cm.__exit__.assert_called_once()

    def test_ensure_packages_skips_install_when_present(self):
        with patch.object(diagnostics.shutil, "which", return_value="/usr/bin/tool"), patch.object(
            diagnostics, "run_command"
        ) as run:
            assert diagnostics.ensure_packages(["dnsutils", "sysbench"]) is True
        run.assert_not_called()

    @pytest.mark.parametrize(("confirm_install", "returncode", "expected"), [(False, 0, False), (True, 0, True), (True, 1, False)])
    def test_ensure_packages_install_outcomes(self, confirm_install, returncode, expected):
        completed = MagicMock(returncode=returncode)
        with patch.object(diagnostics.shutil, "which", return_value=None), patch.object(
            diagnostics, "confirm", return_value=confirm_install
        ), patch.object(diagnostics, "run_command", return_value=completed) as run, patch.object(
            diagnostics, "prompt"
        ):
            assert diagnostics.ensure_packages(["dnsutils"]) is expected
        if confirm_install:
            assert run.call_args_list == [
                call(["apt-get", "update"], timeout=300),
                call(["apt-get", "install", "-y", "dnsutils"], timeout=300),
            ]
        else:
            run.assert_not_called()

    @pytest.mark.parametrize("bind_error, expected", [(None, False), (OSError("busy"), True)])
    def test_is_port_listening_closes_socket(self, bind_error, expected):
        sock = MagicMock()
        if bind_error:
            sock.bind.side_effect = bind_error
        socket_cm = MagicMock()
        socket_cm.__enter__.return_value = sock
        with patch.object(diagnostics.socket, "socket", return_value=socket_cm):
            assert diagnostics.is_port_listening(443) is expected
        sock.bind.assert_called_once_with(("127.0.0.1", 443))
        socket_cm.__exit__.assert_called_once()


class TestCommandRunners:
    def test_run_with_spinner_returns_stdout_and_contract(self):
        process = MagicMock(returncode=0)
        process.poll.return_value = 0
        process.communicate.return_value = ("result\n", None)
        with patch.object(diagnostics.HOST, "popen", return_value=process) as popen:
            assert diagnostics.run_with_spinner("work", "echo ok") == "result\n"
        popen.assert_called_once_with(
            ["echo", "ok"],
            stdout=diagnostics.subprocess.PIPE,
            stderr=diagnostics.subprocess.DEVNULL,
            text=True,
        )

    def test_run_with_spinner_rejects_nonzero_exit(self):
        process = MagicMock(returncode=7)
        process.poll.return_value = 7
        process.communicate.return_value = ("", None)
        with patch.object(diagnostics.HOST, "popen", return_value=process):
            with pytest.raises(Exception, match=r"ошибкой \(7\)"):
                diagnostics.run_with_spinner("work", "false")

    def test_run_function_with_spinner_returns_value(self):
        assert diagnostics.run_function_with_spinner("sum", lambda a, b: a + b, 2, 3) == 5

    def test_run_function_with_spinner_propagates_error(self):
        def fail():
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            diagnostics.run_function_with_spinner("fail", fail)

    def test_run_direct_cmd_uses_argv_without_shell(self):
        with patch.object(diagnostics, "clear"), patch.object(diagnostics.HOST, "run") as run:
            diagnostics.run_direct_cmd("title", "tool --flag")
        run.assert_called_once_with(["tool", "--flag"], timeout=diagnostics.DEFAULT_TIMEOUT, check=False)


class TestHttpAndAddressHelpers:
    def test_make_http_request_builds_post_contract_without_mutating_headers(self):
        original_headers = {"X-Test": "yes"}
        with patch.object(diagnostics.urllib.request, "urlopen", return_value=response(b"OK")) as opened:
            assert diagnostics.make_http_request(
                "https://example.com/api",
                method="POST",
                headers=original_headers,
                body='{"a": 1}',
                timeout=4.5,
            ) == "OK"

        req = opened.call_args.args[0]
        headers = dict(req.header_items())
        assert req.full_url == "https://example.com/api"
        assert req.method == "POST"
        assert req.data == b'{"a": 1}'
        assert headers["Content-type"] == "application/json"
        assert headers["X-test"] == "yes"
        assert "User-agent" in headers
        assert original_headers == {"X-Test": "yes"}
        assert opened.call_args.kwargs["timeout"] == 4.5
        context = opened.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_make_http_request_preserves_explicit_content_type(self):
        with patch.object(diagnostics.urllib.request, "urlopen", return_value=response(b"{}")) as opened:
            diagnostics.make_http_request(
                "https://example.com", method="POST", headers={"Content-Type": "text/plain"}, body="x"
            )
        assert dict(opened.call_args.args[0].header_items())["Content-type"] == "text/plain"

    def test_make_http_request_returns_http_error_body(self):
        http_error = urllib.error.HTTPError(
            "https://example.com", 403, "Forbidden", None, io.BytesIO(b"Forbidden body")
        )
        with patch.object(diagnostics.urllib.request, "urlopen", side_effect=http_error):
            assert diagnostics.make_http_request("https://example.com") == "Forbidden body"

    def test_make_http_request_returns_empty_string_on_transport_error(self):
        with patch.object(diagnostics.urllib.request, "urlopen", side_effect=OSError("offline")):
            assert diagnostics.make_http_request("https://example.com") == ""

    def test_get_ip_address_falls_back_and_clears_selector(self):
        with patch.object(
            diagnostics.urllib.request,
            "urlopen",
            side_effect=[urllib.error.URLError("first failed"), response(b"203.0.113.7\n")],
        ) as opened:
            assert diagnostics.get_ip_address(4) == "203.0.113.7"
        assert opened.call_count == 2
        assert diagnostics._thread_local.ip_version is None

    def test_get_ip_address_rejects_malformed_and_wrong_version_values(self):
        with patch.object(
            diagnostics.urllib.request,
            "urlopen",
            side_effect=[response(b"error: unavailable"), response(b"2001:db8::1"), response(b"198.51.100.8")],
        ) as opened:
            assert diagnostics.get_ip_address(4) == "198.51.100.8"
        assert opened.call_count == 3
        assert diagnostics._thread_local.ip_version is None

    def test_get_ip_address_returns_empty_when_all_endpoints_fail(self):
        with patch.object(diagnostics.urllib.request, "urlopen", side_effect=OSError("offline")) as opened:
            assert diagnostics.get_ip_address(6) == ""
        assert opened.call_count == 3
        assert diagnostics._thread_local.ip_version is None


class TestGeoIPAndCustomServices:
    @pytest.mark.parametrize(
        ("service", "payload", "expected"),
        [
            ("MAXMIND", {"country": {"iso_code": "de"}}, "DE"),
            ("IPINFO_IO", {"data": {"country": "fr"}}, "FR"),
            ("IPREGISTRY", {"location": {"country": {"code": "nl"}}}, "NL"),
            ("IPAPI_CO", {"country": "us"}, "US"),
            ("CLOUDFLARE", {"country": "fi"}, "FI"),
            ("IPAPI_COM", {"countryCode": "jp"}, "JP"),
            ("IPWHO_IS", {"country_code": "ca"}, "CA"),
            ("IP2LOCATION_IO", {"country_code": "br"}, "BR"),
            ("RIPE", {"data": {"located_resources": [{"location": "se"}]}}, "SE"),
        ],
    )
    def test_query_primary_geoip_json_contracts(self, service, payload, expected):
        with patch.object(
            diagnostics.urllib.request, "urlopen", return_value=response(json.dumps(payload).encode())
        ):
            assert diagnostics.query_primary_geoip("203.0.113.5", service) == expected
        assert diagnostics._thread_local.ip_version is None

    def test_query_primary_geoip_plain_text_and_unknown_service(self):
        with patch.object(diagnostics.urllib.request, "urlopen", return_value=response(b" gb\n")):
            assert diagnostics.query_primary_geoip("203.0.113.5", "IFCONFIG_CO") == "GB"
        assert diagnostics.query_primary_geoip("203.0.113.5", "UNKNOWN") == "—"
        assert diagnostics.query_primary_geoip("—", "RIPE") == "—"

    def test_query_primary_geoip_uses_fallback(self):
        with patch.object(
            diagnostics.urllib.request,
            "urlopen",
            side_effect=[OSError("primary down"), response(b'{"countryCode": "IT"}')],
        ) as opened:
            assert diagnostics.query_primary_geoip("203.0.113.5", "RIPE") == "IT"
        assert opened.call_count == 2
        assert diagnostics._thread_local.ip_version is None

    @pytest.mark.parametrize(
        ("service", "payload", "expected"),
        [
            ("Google", '<input name="region" value="PL">', "PL"),
            ("YouTube", json.dumps([[None, None, [[[None, "NL"]]]]]), "NL"),
            ("Twitch", '[{"data":{"requestInfo":{"countryCode":"SE"}}}]', "SE"),
            ("ChatGPT", '{"derived_fields":{"country":"DE"}}', "DE"),
            ("Netflix", '{"client":{"location":{"country":"US"}}}', "US"),
            ("Spotify", '{"country":"FI"}', "FI"),
        ],
    )
    def test_custom_service_parsers(self, service, payload, expected):
        with patch.object(diagnostics, "make_http_request", return_value=payload):
            assert diagnostics.check_custom_service(service, 4, system_has_ipv6=False) == expected
        assert diagnostics._thread_local.ip_version is None

    def test_custom_service_direct_http_parsers(self):
        with patch.object(
            diagnostics.urllib.request,
            "urlopen",
            side_effect=[response(b'itemprop="priceCurrency" content="USD"'), response(status=200)],
        ):
            assert diagnostics.check_custom_service("Steam", 4, False) == "USD"
            assert diagnostics.check_custom_service("Claude", 4, False) == "Yes"

    def test_custom_service_disney_three_step_exchange(self):
        nested_result = {"data": {"session": {"countryCode": "AU"}}}
        with patch.object(
            diagnostics.urllib.request,
            "urlopen",
            side_effect=[
                response(b'{"assertion":"assert"}'),
                response(b'{"refresh_token":"refresh","access_token":"access"}'),
                response(json.dumps(nested_result).encode()),
            ],
        ) as opened:
            assert diagnostics.check_custom_service("Disney+", 4, False) == "AU"
        assert opened.call_count == 3
        assert diagnostics._thread_local.ip_version is None

    def test_custom_service_unavailable_ipv6_does_not_leak_selector(self):
        diagnostics._thread_local.ip_version = None
        assert diagnostics.check_custom_service("Netflix", 6, system_has_ipv6=False) == "—"
        assert diagnostics._thread_local.ip_version is None

    def test_custom_service_malformed_response_is_no(self):
        with patch.object(diagnostics, "make_http_request", return_value="not json"):
            assert diagnostics.check_custom_service("Netflix", 4, False) == "No"
        assert diagnostics._thread_local.ip_version is None


class TestCensorcheck:
    def test_check_domain_censor_success_contract(self, resolved_dns):
        with patch.object(diagnostics.urllib.request, "urlopen", return_value=response(status=204)) as opened:
            assert diagnostics.check_domain_censor("example.com", secure=True) == 204
        req = opened.call_args.args[0]
        assert req.full_url == "https://example.com"
        assert opened.call_args.kwargs["timeout"] == 3.0
        assert opened.call_args.kwargs["context"].verify_mode == ssl.CERT_REQUIRED

    def test_check_domain_censor_detects_dns_spoof(self, monkeypatch):
        monkeypatch.setattr(
            diagnostics.socket,
            "getaddrinfo",
            lambda *_args, **_kwargs: [(socket.AF_INET, 0, 0, "", (next(iter(diagnostics.RKN_STUB_IPS)), 0))],
        )
        with patch.object(diagnostics.urllib.request, "urlopen") as opened:
            assert diagnostics.check_domain_censor("example.com") == -4
        opened.assert_not_called()

    def test_check_domain_censor_detects_dns_failure(self, monkeypatch):
        monkeypatch.setattr(diagnostics.socket, "getaddrinfo", MagicMock(side_effect=socket.gaierror("NXDOMAIN")))
        assert diagnostics.check_domain_censor("example.com") == -3

    def test_check_domain_censor_detects_regional_block_in_success_body(self, resolved_dns):
        blocked = response(
            b"Sorry, you have been blocked",
            status=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
        )
        with patch.object(diagnostics.urllib.request, "urlopen", return_value=blocked):
            assert diagnostics.check_domain_censor("openai.com") == -5

    def test_check_domain_censor_detects_regional_block_in_http_error(self, resolved_dns):
        http_error = urllib.error.HTTPError(
            "https://openai.com", 403, "Forbidden", None, io.BytesIO(b"not available in your country")
        )
        with patch.object(diagnostics.urllib.request, "urlopen", side_effect=http_error):
            assert diagnostics.check_domain_censor("openai.com") == -5

    def test_check_domain_censor_returns_plain_http_error_code(self, resolved_dns):
        http_error = urllib.error.HTTPError(
            "https://example.com", 451, "Unavailable", None, io.BytesIO(b"legal")
        )
        with patch.object(diagnostics.urllib.request, "urlopen", side_effect=http_error):
            assert diagnostics.check_domain_censor("example.com") == 451

    @pytest.mark.parametrize(
        ("reason", "expected"),
        [("timed out", 0), ("connection reset by peer", -2), ("connection refused", -1), ("name not known", -3)],
    )
    def test_check_domain_censor_maps_url_errors(self, resolved_dns, reason, expected):
        with patch.object(
            diagnostics.urllib.request, "urlopen", side_effect=urllib.error.URLError(reason)
        ):
            assert diagnostics.check_domain_censor("example.com") == expected

    def test_check_domain_censor_maps_ssl_error(self, resolved_dns):
        with patch.object(diagnostics.urllib.request, "urlopen", side_effect=ssl.SSLError("bad TLS")):
            assert diagnostics.check_domain_censor("example.com") == -6

    def test_run_censorcheck_returns_complete_sorted_result_and_asn(self, monkeypatch):
        monkeypatch.setattr(diagnostics, "GEO_BLOCKED_SITES", ["z.example", "a.example", "m.example"])

        def status(domain, secure=True):
            return len(domain) + (100 if secure else 0)

        with patch.object(diagnostics, "check_domain_censor", side_effect=status) as check, patch.object(
            diagnostics.urllib.request,
            "urlopen",
            return_value=response(b'{"status":"success","as":"AS64500 Test"}'),
        ):
            result = diagnostics.run_censorcheck_python("geoblock")

        assert result["asn"] == "AS64500"
        assert [item["service"] for item in result["results"]] == ["a.example", "m.example", "z.example"]
        assert len(result["results"]) == 3
        by_domain = {item["service"]: item for item in result["results"]}
        for domain in ("a.example", "m.example", "z.example"):
            assert by_domain[domain]["http"]["ipv4"]["status"] == len(domain)
            assert by_domain[domain]["https"]["ipv4"]["status"] == len(domain) + 100
        assert check.call_count == 6

    @pytest.mark.parametrize(
        ("http_status", "https_status", "expected"),
        [
            (200, 200, ("ok", "TLS")),
            (301, 302, ("ok", "TLS")),
            (200, 0, ("partial", "HTTPS TIMEOUT; HTTP OK")),
            (500, 0, ("blocked", "TIMEOUT")),
            (200, 500, ("partial", "HTTPS 500; HTTP OK")),
            (500, 500, ("blocked", "HTTP 500")),
            (200, 403, ("blocked", "HTTP 403")),
            (200, 451, ("blocked", "HTTP 451")),
            (200, -6, ("blocked", "TLS/SSL")),
            (200, -5, ("blocked", "REGIONAL")),
            (200, -4, ("blocked", "DNS-SPOOF")),
            (200, -3, ("blocked", "DNS")),
            (200, -2, ("blocked", "DPI/RESET")),
            (200, -1, ("blocked", "TCP/REFUSED")),
        ],
    )
    def test_classify_censor_status(self, http_status, https_status, expected):
        assert diagnostics.classify_censor_status(http_status, https_status) == expected

    def test_censorcheck_tui_renders_http_451_as_blocked(self, capsys):
        data = {
            "asn": "AS64500",
            "results": [
                {
                    "service": "blocked.example",
                    "http": {"ipv4": {"status": 200}},
                    "https": {"ipv4": {"status": 451}},
                }
            ],
        }
        with patch.object(diagnostics, "clear"), patch.object(diagnostics, "title"), patch.object(
            diagnostics, "run_function_with_spinner", return_value=data
        ), patch.object(diagnostics, "prompt"):
            diagnostics.test_censorcheck("geoblock")
        output = capsys.readouterr().out
        assert "BLOCKED" in output
        assert "HTTP 451" in output
        assert "OK:0" in output


class TestRadarSpeedAndConfig:
    def test_get_reality_sni_reads_nested_config(self):
        config = {"inbounds": [{"tls": {"reality": {"server_names": ["cdn.example.com"]}}}]}
        with patch.object(diagnostics.os.path, "exists", return_value=True), patch(
            "builtins.open", mock_open(read_data=json.dumps(config))
        ):
            assert diagnostics.get_reality_sni() == "cdn.example.com"

    def test_get_reality_sni_falls_back_on_invalid_config(self):
        with patch.object(diagnostics.os.path, "exists", return_value=True), patch(
            "builtins.open", mock_open(read_data="not json")
        ):
            assert diagnostics.get_reality_sni() == "dl.google.com"

    def test_run_tspu_radar_handles_create_error(self):
        with patch.object(diagnostics.urllib.request, "urlopen", side_effect=OSError("API down")):
            result = diagnostics.run_tspu_radar("203.0.113.2", "cdn.example.com")
        assert result["status"] == "error"
        assert "API create error" in result["message"]

    def test_run_tspu_radar_aggregates_probe_results(self):
        probes = [{"cert": "ok"} for _ in range(32)] + [{"prb_id": 77}]
        with patch.object(
            diagnostics.urllib.request,
            "urlopen",
            side_effect=[
                response(b'{"measurements":[42]}'),
                response(json.dumps(probes).encode()),
                response(b'{"results":[{"id":77,"asn_v4":64500}]}'),
            ],
        ), patch.object(diagnostics.time, "sleep"):
            result = diagnostics.run_tspu_radar("203.0.113.2", "cdn.example.com")
        assert result == {
            "status": "success",
            "total": 33,
            "success": 32,
            "blocked": 1,
            "blocked_asns": {64500: 1},
        }

    def test_run_parallel_pings_parses_average(self):
        completed = MagicMock(stdout="rtt min/avg/max/mdev = 1.0/12.34/20.0/1.0 ms\n")
        nodes = [{"url": "https://a.example/file"}, {"url": "https://b.example/file"}]
        with patch.object(diagnostics.HOST, "run", return_value=completed) as run:
            result = diagnostics.run_parallel_pings(nodes)
        assert result == {
            "https://a.example/file": ("12.3 ms", 12.34),
            "https://b.example/file": ("12.3 ms", 12.34),
        }
        assert run.call_count == 2

    def test_run_parallel_pings_marks_failure(self):
        with patch.object(diagnostics.HOST, "run", side_effect=OSError("no ping")):
            result = diagnostics.run_parallel_pings([{"url": "https://a.example/file"}])
        assert result["https://a.example/file"] == ("N/A", float("inf"))

    def test_run_http_speed_calculates_mbps(self):
        stream = response()
        stream.__enter__.return_value.read.side_effect = [b"x" * 125_000, b""]
        with patch.object(diagnostics.urllib.request, "urlopen", return_value=stream), patch.object(
            diagnostics.time, "time", side_effect=[100.0, 101.0]
        ):
            assert diagnostics.run_http_speed("https://example.com/file") == pytest.approx(1.0)

    @pytest.mark.parametrize("effect", [OSError("offline"), None])
    def test_run_http_speed_returns_zero_for_failure_or_empty_body(self, effect):
        if effect is None:
            opened = MagicMock(return_value=response(b""))
        else:
            opened = MagicMock(side_effect=effect)
        with patch.object(diagnostics.urllib.request, "urlopen", opened):
            assert diagnostics.run_http_speed("https://example.com/file") == 0.0


class TestReportsAndMenus:
    def test_run_diagnostics_report_is_fully_offline(self):
        writer = mock_open()
        service = MagicMock(stdout="active\n")
        with patch.object(diagnostics.os.path, "exists", return_value=False), patch.object(
            diagnostics, "get_ip_address", side_effect=["203.0.113.4", ""]
        ), patch.object(diagnostics, "check_system_ipv6", return_value=False), patch.object(
            diagnostics, "query_primary_geoip", return_value="DE"
        ) as geoip, patch.object(diagnostics, "check_custom_service", return_value="Yes") as custom, patch.object(
            diagnostics, "check_domain_censor", return_value=200
        ) as censor, patch.object(diagnostics.HOST, "run", return_value=service) as run, patch.object(
            diagnostics.os, "makedirs"
        ) as makedirs, patch("builtins.open", writer):
            result = diagnostics.run_diagnostics_report()

        assert "HYDRA" in result
        assert "СОСТОЯНИЕ HYDRA" in result
        assert "СЕРВИСЫ" in result
        assert "ПЛАГИНЫ" in result
        assert "ПОСЛЕДНЕЕ ПРИМЕНЕНИЕ" in result
        assert not writer.called
        assert geoip.call_count == 0
        assert custom.call_count == 0
        assert censor.call_count == 0

    def test_generate_report_success_contract(self):
        with patch.object(diagnostics, "clear"), patch.object(diagnostics, "title"), patch.object(
            diagnostics, "run_function_with_spinner", return_value="HYDRA report"
        ) as spinner, patch("builtins.print") as output, patch.object(diagnostics, "prompt"):
            diagnostics.test_generate_report()
        assert spinner.call_args.args[1] is diagnostics.run_diagnostics_report
        assert output.call_args_list[-1].args == ("HYDRA report",)

    def test_cpu_sysbench_parses_metrics(self):
        output = """
events per second: 1234.50
total time: 10.001s
total number of events: 12346
Latency (ms):
         min: 0.70
         avg: 0.81
         max: 2.40
"""
        with patch.object(diagnostics, "clear"), patch.object(diagnostics, "title"), patch.object(
            diagnostics, "ensure_packages", return_value=True
        ), patch.object(diagnostics, "run_with_spinner", return_value=output), patch.object(
            diagnostics, "panel"
        ) as panel, patch.object(diagnostics, "prompt"):
            diagnostics.test_cpu_sysbench()
        rendered = "\n".join(panel.call_args.args[1])
        for value in ("1234.50", "12346", "10.001s", "0.70", "0.81", "2.40"):
            assert value in rendered

    def test_global_speedtest_quick_mode_measures_five_fastest_nodes(self):
        def spinner(_title, func, nodes):
            assert func is diagnostics.run_parallel_pings
            return {node["url"]: (f"{index + 1}.0 ms", float(index + 1)) for index, node in enumerate(nodes)}

        with patch.object(diagnostics, "clear"), patch.object(diagnostics, "title"), patch.object(
            diagnostics, "ensure_packages", return_value=True
        ), patch.object(diagnostics, "menu", return_value="1"), patch.object(
            diagnostics, "run_function_with_spinner", side_effect=spinner
        ), patch.object(diagnostics, "run_http_speed", return_value=250.0) as speed, patch.object(
            diagnostics, "prompt"
        ):
            diagnostics.test_bench_speedtest()
        assert speed.call_count == 5

    def test_iperf3_ru_runs_download_and_upload_for_each_city(self):
        socket_cm = MagicMock()
        socket_cm.__enter__.return_value = MagicMock()

        def run_command(cmd, **_kwargs):
            completed = MagicMock(returncode=0)
            if cmd[0] == "ping":
                completed.stdout = "rtt min/avg/max/mdev = 1.0/12.5/20.0/1.0 ms\n"
            else:
                completed.stdout = json.dumps(
                    {"end": {"sum_sent": {"bits_per_second": 80_000_000}, "sum_received": {"bits_per_second": 75_000_000}}}
                )
            return completed

        with patch.object(diagnostics, "clear"), patch.object(diagnostics, "title"), patch.object(
            diagnostics, "ensure_packages", return_value=True
        ), patch.object(diagnostics.socket, "socket", return_value=socket_cm), patch.object(
            diagnostics.HOST, "run", side_effect=run_command
        ) as run, patch.object(diagnostics, "prompt"):
            diagnostics.test_iperf3_ru()

        commands = [call.args[0] for call in run.call_args_list]
        iperf_commands = [cmd for cmd in commands if cmd[0] == "iperf3"]
        ping_commands = [cmd for cmd in commands if cmd[0] == "ping"]
        assert len(iperf_commands) == 10
        assert sum("-R" in cmd for cmd in iperf_commands) == 5
        assert len(ping_commands) == 5
        assert socket_cm.__exit__.call_count >= 5

    def test_menu_diagnostics_dispatches_every_action(self):
        actions = ["1", "2", "3", "4", "5", "6", "7", "0"]
        with patch.object(diagnostics, "clear"), patch.object(diagnostics, "panel"), patch.object(
            diagnostics, "menu", side_effect=actions
        ), patch.object(diagnostics, "test_ip_region") as ip_region, patch.object(
            diagnostics, "test_censorcheck"
        ) as censor, patch.object(diagnostics, "test_bench_speedtest") as global_speed, patch.object(
            diagnostics, "test_iperf3_ru"
        ) as ru_speed, patch.object(diagnostics, "test_cpu_sysbench") as cpu, patch.object(
            diagnostics, "test_generate_report"
        ) as report:
            diagnostics.menu_diagnostics(MagicMock())

        ip_region.assert_called_once_with()
        assert censor.call_args_list[0].args == ("geoblock",)
        assert censor.call_args_list[1].args == ("dpi",)
        global_speed.assert_called_once_with()
        ru_speed.assert_called_once_with()
        cpu.assert_called_once_with()
        report.assert_called_once_with()
