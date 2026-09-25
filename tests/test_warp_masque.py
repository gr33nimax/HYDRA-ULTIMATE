"""MASQUE endpoint selection must be a reversible, verified WARP change."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from hydra.core.host import HostBackend
from hydra.core.state_models import AppState, PluginState
from hydra.core.singbox_config import generate_config
from hydra.plugins.warp.plugin import WarpPlugin


REPORT = """# WARP endpoints: 2 working / 3 probed
# sorted by in-tunnel loss, then in-tunnel ping
# TUN PING / LOSS = RTT and packet loss measured inside the tunnel
ENDPOINT               ENDPOINT PING TUN PING  LOSS   SEEN AS    NODE   NODE LOCATION
162.159.198.1:443      25ms          38ms      0%     NL         HEL    Helsinki
162.159.198.2:443      30ms          52ms      2%     NL         HEL    Helsinki

# 1 torn down (handshake ok, data flowed, then cut and never recovered)
ENDPOINT               ENDPOINT PING TUN PING  LOSS   SEEN AS    NODE   NODE LOCATION
162.159.198.3:443      20ms          20ms      0%     NL         HEL    Helsinki

# best per node
"""


def test_report_excludes_torn_down_and_rejects_unrecognized_format():
    from hydra.plugins.warp.masque_scan import parse_report

    assert parse_report(REPORT) == [
        {"address": "162.159.198.1", "port": 443, "ping_ms": 38.0, "loss_percent": 0, "node": "HEL", "seen_as": "NL"},
        {"address": "162.159.198.2", "port": 443, "ping_ms": 52.0, "loss_percent": 2, "node": "HEL", "seen_as": "NL"},
    ]
    with pytest.raises(ValueError):
        parse_report("162.159.198.1:443 38ms")
    with pytest.raises(ValueError):
        parse_report(REPORT.replace("HEL    Helsinki", "\x1b[31mHEL    Helsinki", 1))


def test_failed_registration_leaves_no_account_file(tmp_path):
    from hydra.plugins.warp.masque_scan import register_masque

    account = tmp_path / "account.json"
    host = Mock()
    host.which.return_value = "/usr/bin/warpscout"

    def fail(argv, **kwargs):
        Path(argv[argv.index("-a") + 1]).write_text('{"token":"partial"}')
        return SimpleNamespace(returncode=1)

    host.run.side_effect = fail
    with pytest.raises(RuntimeError):
        register_masque(host, account)
    assert not account.exists()
    assert list(tmp_path.glob(".register-*")) == []


def test_registration_publishes_only_complete_masque_account(tmp_path, monkeypatch):
    from hydra.plugins.warp.masque_scan import register_masque

    account = tmp_path / "account.json"
    host = HostBackend()
    monkeypatch.setattr(host, "which", lambda name: "/usr/bin/warpscout")

    def register(argv, **kwargs):
        Path(argv[argv.index("-a") + 1]).write_text('{"masque":{"token":"private"}}')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(host, "run", register)
    register_masque(host, account)
    assert account.read_text() == '{"masque":{"token":"private"}}'
    assert list(tmp_path.glob(".register-*")) == []


def test_scan_uses_private_account_and_discards_report(tmp_path):
    from hydra.plugins.warp.masque_scan import scan_masque

    account = tmp_path / "account.json"
    account.write_text("{}")
    host = Mock()
    host.which.return_value = "/usr/bin/warpscout"

    def run(argv, **kwargs):
        report = Path(argv[argv.index("-o") + 1])
        report.write_text(REPORT)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    host.run.side_effect = run
    rows = scan_masque(host, account)
    assert rows[0]["address"] == "162.159.198.1"
    argv = host.run.call_args.args[0]
    assert argv[:3] == ["/usr/bin/warpscout", "scan", "-p"]
    assert "-P" in argv and "-plain" in argv
    assert argv[argv.index("-a") + 1] == str(account)
    assert not Path(argv[argv.index("-o") + 1]).exists()


def test_blocked_masque_is_empty_results_not_an_unknown_scan_error(tmp_path):
    from hydra.plugins.warp.masque_scan import scan_masque

    account = tmp_path / "account.json"
    account.write_text("{}")
    host = Mock()
    host.which.return_value = "/usr/bin/warpscout"
    host.run.return_value = SimpleNamespace(
        returncode=1, stderr="no MASQUE endpoint passed data - this network blocks it, try -p awg"
    )
    assert scan_masque(host, account) == []


def test_pin_is_rendered_for_native_masque_and_probe_is_isolated():
    state = AppState(
        protocols={
            "warp": PluginState(
                enabled=True,
                config={
                    "local_lists": {"test": {"domains": ["example.com"], "ips": []}},
                    "list_targets": {"local:test": "warp"},
                    "masque_endpoint": {"address": "162.159.198.1", "port": 443},
                },
            )
        }
    )
    fragment = WarpPlugin().configure(state)
    outbound = next(o for o in fragment.outbounds if o["type"] == "masque")
    assert outbound["address"] == "162.159.198.1" and outbound["port"] == 443
    assert {"inbound": ["warp-probe-in"], "outbound": "warp"} in fragment.route_rules
    assert any(i["listen"] == "127.0.0.1" and i["tag"] == "warp-probe-in" for i in fragment.inbounds)
    generated = generate_config(state, {"warp": fragment})
    assert generated["route"]["rules"][0] == {"inbound": ["warp-probe-in"], "outbound": "warp"}


def test_invalid_pin_fails_closed_not_direct():
    state = AppState(
        protocols={
            "warp": PluginState(
                config={
                    "masque_endpoint": {"address": "localhost", "port": 443},
                    "local_lists": {"test": {"domains": ["example.com"], "ips": []}},
                    "list_targets": {"local:test": "warp"},
                }
            )
        }
    )
    with pytest.raises(ValueError, match="MASQUE"):
        WarpPlugin().configure(state)


def test_pin_command_rejects_non_ip_and_reset_returns_to_core_default():
    plugin = WarpPlugin()
    set_endpoint = getattr(plugin, "set_masque_endpoint")
    state = AppState(protocols={"warp": PluginState(config={})})
    with pytest.raises(ValueError):
        set_endpoint(state, address="example.org", port=443)
    assert set_endpoint(state, address="162.159.198.1", port=443)
    assert state.protocols["warp"].config["masque_endpoint"] == {"address": "162.159.198.1", "port": 443}
    assert set_endpoint(state, address="", port=0)
    assert "masque_endpoint" not in state.protocols["warp"].config


def test_probe_must_prove_warp_not_only_http_success(monkeypatch):
    state = AppState(
        protocols={
            "warp": PluginState(
                enabled=True,
                config={
                    "masque_endpoint": {"address": "162.159.198.1", "port": 443},
                },
            )
        }
    )
    host = Mock()
    host.which.return_value = "/usr/bin/curl"
    host.run.return_value = SimpleNamespace(returncode=0, stdout="warp=off\n")
    monkeypatch.setattr("hydra.plugins.warp.plugin.HOST", host)
    monkeypatch.setattr("hydra.core.singbox.is_running", lambda: True)
    assert not WarpPlugin().health_result(state).healthy
    host.run.return_value = SimpleNamespace(returncode=0, stdout="colo=HEL\nwarp=on\n")
    assert WarpPlugin().health_result(state).healthy


def test_probe_failure_rejects_selected_endpoint(monkeypatch):
    state = AppState(
        protocols={
            "warp": PluginState(
                enabled=True,
                config={
                    "masque_endpoint": {"address": "162.159.198.1", "port": 443},
                },
            )
        }
    )
    host = Mock()
    host.which.return_value = "/usr/bin/curl"
    host.run.return_value = SimpleNamespace(returncode=28)
    monkeypatch.setattr("hydra.plugins.warp.plugin.HOST", host)
    monkeypatch.setattr("hydra.core.singbox.is_running", lambda: True)
    result = WarpPlugin().health_result(state)
    assert not result.healthy
    assert "WARP" in result.detail
