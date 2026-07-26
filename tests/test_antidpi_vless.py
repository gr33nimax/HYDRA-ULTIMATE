"""AntiDPI coverage for the VLESS + XHTTP transport.

Caddy terminates TLS for the VLESS domain and forwards the request to the local
HTTP server over PROXY v2, so the shared decoy access log — not the sing-box
journal — is the surface that carries the real client address.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.state import AppState, PluginState
from hydra.plugins.antidpi.adapters import parse_protocol_line
from hydra.plugins.antidpi.agent import _bind_vless_normalizer
from hydra.plugins.antidpi.normalization import (
    normalize_decoy_record,
    normalize_vless_record,
    vless_endpoint,
    vless_normalizer,
)
from hydra.plugins.antidpi.plugin import AntiDPIPlugin
from hydra.plugins.antidpi.selftest_report import log_filter_matches

DOMAIN = "cdn.example.org"
PATHS = ("/xhttp",)
NOW = 1_800_000_000.0


def _record(
    *,
    uri: str = "/xhttp/abc",
    status: int = 404,
    host: str = DOMAIN,
    address: str = "203.0.113.77",
    method: str = "POST",
) -> dict:
    return {
        "status": status,
        "request": {
            "remote_ip": address,
            "host": host,
            "uri": uri,
            "method": method,
        },
    }


def _state(*, enabled: bool = True, path: str = "/xhttp") -> AppState:
    state = AppState()
    state.protocols["vless"] = PluginState(
        enabled=enabled,
        config={"domain": DOMAIN, "xhttp_path": path},
    )
    return state


def test_endpoint_is_read_from_plugin_configuration():
    assert vless_endpoint(_state()) == (DOMAIN, ("/xhttp",))
    assert vless_endpoint(_state(path="/api/v2/")) == (DOMAIN, ("/api/v2",))
    assert vless_endpoint(_state(enabled=False)) == ("", ())
    assert vless_endpoint(AppState()) == ("", ())
    assert vless_endpoint(None) == ("", ())


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 421, 426])
def test_rejected_request_to_the_xhttp_path_is_auth_evidence(status):
    match = normalize_vless_record(
        _record(status=status),
        domain=DOMAIN,
        paths=PATHS,
    )
    assert match == (
        "203.0.113.77",
        {
            "protocol": "vless",
            "kind": "auth_failure",
            "source": "caddy-vless",
        },
    )


@pytest.mark.parametrize("status", [200, 204, 206, 502, 503, 504])
def test_working_clients_and_upstream_failures_are_not_evidence(status):
    assert normalize_vless_record(
        _record(status=status),
        domain=DOMAIN,
        paths=PATHS,
    ) is None


def test_path_matching_covers_subpaths_but_not_neighbours():
    for uri in ("/xhttp", "/xhttp/", "/xhttp/x?y=1", "/xhttp/deep/path"):
        assert normalize_vless_record(
            _record(uri=uri),
            domain=DOMAIN,
            paths=PATHS,
        ) is not None
    # A neighbouring path is decoy traffic, not an endpoint probe.
    assert normalize_vless_record(
        _record(uri="/xhttproxy", status=404),
        domain=DOMAIN,
        paths=PATHS,
    ) is None


def test_scanner_paths_on_the_vless_site_stay_decoy_evidence():
    match = normalize_vless_record(
        _record(uri="/wp-login.php", status=404, method="GET"),
        domain=DOMAIN,
        paths=PATHS,
    )
    assert match is not None
    assert match[1]["kind"] == "active_decoy_probe"
    assert match[1]["source"] == "caddy-vless-decoy"


def test_records_of_other_domains_are_left_to_their_own_filters():
    other = _record(host="anytls.example.net", uri="/xhttp/abc")
    assert normalize_vless_record(other, domain=DOMAIN, paths=PATHS) is None
    # The shared decoy filter still classifies its own site's scanner paths.
    assert normalize_decoy_record(
        _record(host="anytls.example.net", uri="/.env", method="GET"),
    ) is not None


def test_normalizer_is_disabled_without_a_configured_endpoint():
    assert vless_normalizer("", PATHS) is None
    assert vless_normalizer(DOMAIN, ()) is None
    assert vless_normalizer(DOMAIN, PATHS) is not None


def test_agent_binds_and_releases_the_normalizer_with_configuration():
    tail = SimpleNamespace(normalizers=())

    _bind_vless_normalizer(tail, (DOMAIN, PATHS))
    assert len(tail.normalizers) == 2
    assert tail.normalizers[0](_record()) is not None

    _bind_vless_normalizer(tail, ("", ()))
    assert tail.normalizers == (normalize_decoy_record,)


def test_singbox_journal_rejections_are_recognized():
    match = parse_protocol_line(
        "sing-box",
        "inbound/vless[vless-xhttp-in]: process connection from "
        "127.0.0.1:41234: authenticate: invalid request",
    )
    assert match is not None
    address, event = match
    assert address == "127.0.0.1"
    assert event["protocol"] == "vless"
    assert event["kind"] == "auth_failure"
    # The peer port lets the source relay attribute the external client.
    assert event["peer_port"] == 41234


def test_unrelated_singbox_lines_are_not_attributed_to_vless():
    assert parse_protocol_line(
        "sing-box",
        "inbound/vless[vless-xhttp-in]: connection closed from 127.0.0.1:41234",
    ) is None


def test_selftest_replays_the_vless_filter_over_captured_logs():
    lines = {
        "/var/log/caddy-l4/decoy-access.log": [
            '{"status": 404, "request": {"remote_ip": "203.0.113.77", '
            f'"host": "{DOMAIN}", "uri": "/xhttp/probe", "method": "POST"}}}}',
        ],
    }
    matches = log_filter_matches(
        "vless",
        lines,
        vless_endpoint=(DOMAIN, PATHS),
    )
    assert [item["ip"] for item in matches] == ["203.0.113.77"]
    assert matches[0]["event"]["protocol"] == "vless"
    # Without a configured endpoint the filter stays silent.
    assert log_filter_matches("vless", lines) == []


def test_repeated_vless_probes_alert_before_they_ban(tmp_path):
    notify = MagicMock(return_value=True)
    plugin = AntiDPIPlugin(notifier=notify)
    state_file = tmp_path / "antidpi-vless.json"
    normalize = vless_normalizer(DOMAIN, PATHS)
    accepted = MagicMock(returncode=0, stdout="", stderr="")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=accepted):
        banned = [
            plugin.observe_event(
                *normalize(_record()),
                now=NOW + index,
            )
            for index in range(6)
        ]
        data = plugin._load_state()

    entry = data["scores"]["203.0.113.77"]
    assert not any(banned)
    assert entry["signals"] == ["auth_failure"]
    assert notify.call_count >= 1
    assert "auth" in entry["families"]


def test_endpoint_probe_and_decoy_probe_together_reach_a_ban(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi-vless-ban.json"
    normalize = vless_normalizer(DOMAIN, PATHS)
    accepted = MagicMock(returncode=0, stdout="", stderr="")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=accepted):
        plugin.observe_event(*normalize(_record()), now=NOW)
        banned = plugin.observe_event(
            *normalize(
                _record(uri="/wp-login.php", status=404, method="GET"),
            ),
            now=NOW + 1,
        )
        data = plugin._load_state()

    assert banned is True
    assert "203.0.113.77" in data["banned"]
