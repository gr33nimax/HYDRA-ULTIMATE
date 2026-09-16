"""End-to-end contract for the AntiScan detector.

The detector has exactly two inputs that can ban: a protocol-owned reject and a
decoy scanner path.  Everything else must leave no trace — no state, no
firewall call, no Telegram message.  These tests encode that, and they encode
what must survive: the ban lifecycle, the whitelist, and state compatibility.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.state_models import AppState
from hydra.plugins.antidpi.detection import (
    evidence_problem,
    is_enforcement_evidence,
)
from hydra.plugins.antidpi.plugin import AntiDPIPlugin

FIXTURES = Path(__file__).parent / "fixtures" / "antidpi"
NOW = 1_800_000_000.0
SNELL_IP = "203.0.113.44"
DECOY_IP = "203.0.113.7"


def _accepted():
    return MagicMock(returncode=0, stdout="", stderr="")


def _snell_event() -> dict:
    """The event the deployed Snell parser produces for a real reject."""
    from hydra.plugins.antidpi.adapters import parse_protocol_line

    line = next(
        line
        for line in (FIXTURES / "snell-cipher-auth-failure.txt").read_text(encoding="utf-8").splitlines()
        if SNELL_IP in line
    )
    match = parse_protocol_line("sing-box", line)
    assert match is not None, line
    address, event = match
    assert address == SNELL_IP
    return event


def _decoy_event() -> dict:
    from hydra.plugins.antidpi.normalization import normalize_decoy_record

    record = next(
        json.loads(line)
        for line in (FIXTURES / "decoy-scanner-paths.jsonl").read_text(encoding="utf-8").splitlines()
        if DECOY_IP in line
    )
    match = normalize_decoy_record(record)
    assert match is not None, record
    address, event = match
    assert address == DECOY_IP
    return event


@pytest.fixture
def wired(tmp_path):
    """Plugin whose state file and firewall runner are isolated per test.

    Yields the *patch mock* rather than its return value: ``assert
    returned_value.called`` would be vacuously false, because a return value is
    never itself called.
    """
    state_file = tmp_path / "antidpi.json"
    with (
        patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file),
        patch(
            "hydra.plugins.antidpi.plugin._run",
            return_value=_accepted(),
        ) as runner,
    ):
        yield state_file, runner


# --- the two allowed inputs ------------------------------------------------


def test_proven_snell_reject_bans_and_notifies(wired):
    _state_file, runner = wired
    notify = MagicMock(return_value=True)
    plugin = AntiDPIPlugin(notifier=notify)

    banned = plugin.observe_event(SNELL_IP, _snell_event(), now=NOW)

    assert banned is True
    assert SNELL_IP in plugin._load_state()["banned"]
    assert runner.call_count == 1
    command = runner.call_args.args[0]
    assert command[:2] == ["ipset", "add"]
    assert SNELL_IP in command
    plugin._drain_notifications()
    assert notify.call_count == 1
    component, action = notify.call_args.args[0], notify.call_args.args[1]
    assert (component, action) == ("AntiDPI", "BAN")


def test_proven_decoy_scan_bans(wired):
    _state_file, _runner = wired
    plugin = AntiDPIPlugin()

    assert plugin.observe_event(DECOY_IP, _decoy_event(), now=NOW) is True


def test_ban_record_keeps_bounded_evidence(wired):
    _state_file, _runner = wired
    plugin = AntiDPIPlugin()

    plugin.observe_event(SNELL_IP, _snell_event(), now=NOW)

    entry = plugin._load_state()["banned"][SNELL_IP]
    assert entry["protocol"] == "snell"
    assert entry["reason"] == "record_auth_failed"
    assert entry["attribution"] == "direct"
    assert entry["offense_count"] == 1
    assert entry["duration"] > 0
    assert entry["signals"] == ["snell:record_auth_failed"]


# --- everything else is silent --------------------------------------------


@pytest.mark.parametrize(
    "event",
    [
        {"kind": "unknown_sni", "protocol": "tls", "handshake_ok": False},
        {"kind": "handshake_failure", "protocol": "tls", "handshake_ok": False},
        {"kind": "malformed_tls", "protocol": "tls", "sni_known": False},
        {"kind": "port_scan", "protocol": "tcp", "connections_10s": 12},
        {"kind": "udp_probe", "protocol": "udp", "destination_port": 443},
        {"kind": "low_volume_session", "protocol": "mieru"},
        {"kind": "auth_failure", "protocol": "vless"},
        {"kind": "handshake_failure", "protocol": "anytls", "handshake_ok": False},
        {
            "kind": "protocol_reject",
            "protocol": "hysteria2",
            "reason": "x",
            "source": "journal",
            "attribution": "direct",
        },
        {
            "kind": "protocol_reject",
            "protocol": "snell",
            "reason": "record_auth_failed",
            "source": "journal",
            "attribution": "unique-recent-source",
        },
        {
            "kind": "decoy_scan",
            "protocol": "https",
            "reason": "scanner_path",
            "source": "kernel-firewall",
            "attribution": "direct",
        },
        {"kind": "anomaly", "protocol": "L4"},
    ],
)
def test_non_evidence_leaves_no_trace(wired, event):
    """The five live noise classes plus every removed signal kind."""
    state_file, runner = wired
    notify = MagicMock(return_value=True)
    plugin = AntiDPIPlugin(notifier=notify)

    banned = plugin.observe_event("198.51.100.9", dict(event), now=NOW)

    assert banned is False
    assert runner.call_count == 0
    plugin._drain_notifications()
    assert notify.call_count == 0
    state = plugin._load_state()
    assert state.get("banned", {}) == {}
    assert state.get("history", []) == []


def test_evidence_allowlist_rejects_every_unknown_combination():
    """A protocol or reason that was never proven cannot enforce."""
    assert (
        evidence_problem(
            {
                "kind": "protocol_reject",
                "protocol": "snell",
                "reason": "record_auth_failed",
                "source": "journal",
                "attribution": "direct",
            }
        )
        == ""
    )
    for protocol in ("mieru", "telemt", "wdtt", "amneziawg", "shadowtls", "naive", "trusttunnel", "vless", "anytls"):
        assert not is_enforcement_evidence(
            {
                "kind": "protocol_reject",
                "protocol": protocol,
                "reason": "record_auth_failed",
                "source": "journal",
                "attribution": "direct",
            }
        ), protocol


# --- ban lifecycle is preserved -------------------------------------------


def test_active_ban_does_not_notify_twice(wired):
    _state_file, _runner = wired
    notify = MagicMock(return_value=True)
    plugin = AntiDPIPlugin(notifier=notify)

    plugin.observe_event(SNELL_IP, _snell_event(), now=NOW)
    plugin._drain_notifications()
    plugin.observe_event(SNELL_IP, _snell_event(), now=NOW + 1)
    plugin._drain_notifications()

    assert notify.call_count == 1
    assert plugin._load_state()["banned"][SNELL_IP]["offense_count"] == 1


def test_firewall_refusal_is_never_reported_as_a_ban(tmp_path):
    state_file = tmp_path / "antidpi.json"
    refused = MagicMock(returncode=1, stdout="", stderr="ipset: permission denied")
    notify = MagicMock(return_value=True)
    with (
        patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file),
        patch("hydra.plugins.antidpi.plugin._run", return_value=refused),
    ):
        plugin = AntiDPIPlugin(notifier=notify)
        banned = plugin.observe_event(SNELL_IP, _snell_event(), now=NOW)
        state = plugin._load_state()

    assert banned is False
    assert state["banned"] == {}
    assert state["ban_failures"]["count"] == 1


def test_second_offense_uses_the_next_duration_step(wired):
    _state_file, _runner = wired
    plugin = AntiDPIPlugin()

    plugin.observe_event(SNELL_IP, _snell_event(), now=NOW)
    first = plugin._load_state()["banned"][SNELL_IP]["duration"]
    plugin.unban(SNELL_IP)
    plugin.observe_event(SNELL_IP, _snell_event(), now=NOW + 10)
    second = plugin._load_state()["banned"][SNELL_IP]["duration"]

    assert second > first


def test_whitelisted_address_is_never_banned(wired):
    state_file, runner = wired
    plugin = AntiDPIPlugin()
    state = plugin._load_state()
    state["whitelist"] = ["203.0.113.0/24"]
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file):
        plugin._state_store().save(state)
        assert plugin.observe_event(SNELL_IP, _snell_event(), now=NOW) is False
        assert plugin._load_state()["banned"] == {}
    assert runner.call_count == 0


def test_manual_ban_is_permanent_and_honest(wired):
    _state_file, _runner = wired
    plugin = AntiDPIPlugin()

    result = plugin.manual_ban("198.51.100.77", source="tui")

    assert result.get("ok") is True
    assert plugin._load_state()["banned"]["198.51.100.77"]["permanent"] is True


def test_loopback_and_private_peers_are_rejected_before_state(wired):
    state_file, runner = wired
    plugin = AntiDPIPlugin()

    for address in ("127.0.0.1", "10.1.2.3", "192.168.1.5", "not-an-ip"):
        assert plugin.observe_event(address, _snell_event(), now=NOW) is False

    assert runner.call_count == 0
    assert plugin._load_state().get("banned", {}) == {}


# --- compatibility ---------------------------------------------------------


def test_legacy_score_state_is_readable_but_never_decides(wired):
    """An upgraded host keeps its history; old evidence cannot ban again."""
    state_file, runner = wired
    plugin = AntiDPIPlugin()
    legacy = {
        "scores": {
            "198.51.100.5": {
                "score": 99.0,
                "verified_score": 99.0,
                "signals": ["unknown_sni", "handshake_failure"],
                "families": {"tls_negotiation": 1.0},
            },
        },
        "banned": {},
        "history": [],
    }
    plugin._state_store().save(legacy)

    banned = plugin.observe_event("198.51.100.5", {"kind": "unknown_sni", "protocol": "tls"}, now=NOW)

    assert banned is False
    assert runner.call_count == 0
    assert plugin._load_state()["banned"] == {}


def test_existing_active_ban_survives_a_reload(wired):
    _state_file, _runner = wired
    plugin = AntiDPIPlugin()
    plugin.manual_ban("198.51.100.88", source="tui")

    assert "198.51.100.88" in AntiDPIPlugin()._load_state()["banned"]


def test_plugin_identity_and_capabilities_stay_stable():
    """The machine key, service and management surface must not drift."""
    from hydra.plugins.antidpi.plugin import AntidpiPlugin

    assert AntiDPIPlugin.meta.name == "antidpi"
    assert AntidpiPlugin is AntiDPIPlugin
    assert AntiDPIPlugin.meta.commands == (
        "add_whitelist",
        "remove_whitelist",
        "unban_address",
    )


# --- service sandbox -------------------------------------------------------


def test_service_unit_grants_the_capabilities_iptables_needs(tmp_path):
    """The ipset matcher needs CAP_NET_RAW, not only CAP_NET_ADMIN.

    ``iptables`` opens a netlink socket while it parses ``-m set
    --match-set``.  Under the service sandbox the earlier unit granted only
    CAP_NET_ADMIN, so every ``-C``/``-I`` answered "Can't open socket to
    ipset": reconciliation reported a failed step on the live host and a lost
    DROP rule could never have been re-installed.
    """
    script = tmp_path / "hydra-antidpi.py"
    service = tmp_path / "hydra-antidpi.service"
    with (
        patch("hydra.plugins.antidpi.plugin.SCRIPT_FILE", script),
        patch("hydra.plugins.antidpi.plugin.SERVICE_FILE", service),
    ):
        AntiDPIPlugin()._write_service()

    unit = service.read_text(encoding="utf-8")
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW" in unit
    assert "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW" in unit
    # iptables serializes host-wide updates through /run/xtables.lock.
    assert "ReadWritePaths=/var/lib/hydra /var/log/caddy-l4 /run" in unit
    assert "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6" in unit


def test_reconciliation_keeps_the_underlying_step_cause(wired):
    """A bare step label hid why iptables refused; the cause must survive."""
    plugin = AntiDPIPlugin()
    cause = "правило iptables для hydra_antidpi: Can't open socket to ipset"

    def failing_rules() -> bool:
        plugin.last_error = cause
        return False

    with (
        patch.object(plugin, "_ensure_sets", return_value=True),
        patch.object(plugin, "_ensure_rules", side_effect=failing_rules),
        patch.object(plugin, "_remove_obsolete_telemetry", return_value=True),
        patch.object(plugin, "release_whitelisted_bans", return_value=0),
        patch.object(plugin, "whitelisted_bans", return_value=[]),
        patch.object(plugin, "_restore_bans", return_value=True),
        patch.object(plugin, "record_reconciliation", return_value=True),
    ):
        assert plugin.reconcile_enforcement(AppState()) is False

    assert "INPUT rules" in plugin.last_error
    assert "Can't open socket to ipset" in plugin.last_error
