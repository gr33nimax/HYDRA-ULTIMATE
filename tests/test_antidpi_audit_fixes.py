"""Regression tests for the AntiDPI audit fixes (debug branch, Sept 2026).

Each test pins the *fixed* behaviour of a defect documented in the audit:
spoofable kernel sources and time-correlated attribution never ban, ban
intent is durable before the firewall effect, collector restarts restore
enforcement, operator views stop reporting "no evidence" for addresses the
bounded lists cannot see, and diagnostic archives lose unknown secrets.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import queue
import re
import threading
import time
from contextlib import contextmanager, nullcontext
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.state_models import AppState
from hydra.plugins.antidpi.adapters import (
    parse_kernel_scan_line,
    parse_protocol_line,
)
from hydra.plugins.antidpi.agent import (
    JsonTail,
    _event_now,
    _journal_follow_command,
    _journal_worker,
    _load_cursor,
    _reconcile_enforcement,
    _resolve_unattributed_relay_source,
    _store_cursor,
    run,
)
from hydra.plugins.antidpi.detection import observe_state
from hydra.plugins.antidpi.normalization import (
    normalize_decoy_record,
    normalize_trusttunnel_record,
)
from hydra.plugins.antidpi.plugin import AntiDPIPlugin
from hydra.plugins.antidpi.projection import (
    address_details,
    management_projection,
)
from hydra.plugins.antidpi.selftest_report import redactor
from hydra.plugins.antidpi.state_store import (
    AntiDPIStateCorruptError,
    AntiDPIStateStore,
)
from hydra.services.telegram.dashboard_lists import address_card_text
from hydra.ui.plugin_managers import antidpi as tui_manager
from hydra.ui.plugin_managers._antidpi_views import ban_table

NOW = 1_800_000_000.0


def _isolated_store(data: dict) -> MagicMock:
    store = MagicMock()
    store.load.return_value = data
    return store


# --- Stage 1: dangerous decisions -----------------------------------------


def test_udp_sweep_via_public_plugin_never_bans():
    plugin = AntiDPIPlugin()
    data: dict = {}
    with patch.object(plugin, "_state_store", return_value=_isolated_store(data)), \
         patch.object(plugin, "_state_lock", side_effect=nullcontext), \
         patch.object(plugin, "_is_whitelisted", return_value=False), \
         patch.object(plugin, "_add_firewall_ban", return_value=True) as firewall:
        for port in (1001, 1002, 1003, 1004):
            address, event = parse_kernel_scan_line(
                f"HYDRA_SCAN_UDP SRC=198.51.100.9 DPT={port}",
            )
            assert plugin.observe_event(address, event, now=10000 + port) is False
    firewall.assert_not_called()
    assert data["scores"]["198.51.100.9"]["verified_score"] == 0
    assert data["banned"] == {}


def test_kernel_context_keeps_multi_port_scan_alert_only():
    data: dict = {}
    address = ipaddress.ip_address("198.51.100.9")
    observation = None
    for port in (1001, 1002, 1003, 1004, 1005):
        _, event = parse_kernel_scan_line(
            f"HYDRA_SCAN_TCP SRC=198.51.100.9 DPT={port}",
        )
        observation = observe_state(
            data,
            address,
            event,
            timestamp=10000 + port,
            max_score_entries=100,
        )
    assert observation.evidence_can_ban is False
    assert observation.entry["verified_score"] == 0
    assert not observation.should_ban
    assert observation.event["policy"] == "alert-only / unverified kernel source"


def test_tls_compatibility_policy_is_applied_by_the_detector():
    data: dict = {}
    event = {
        "kind": "unknown_sni",
        "protocol": "tls",
        "handshake_ok": False,
        "sni_known": False,
    }
    observation = observe_state(
        data,
        ipaddress.ip_address("198.51.100.10"),
        event,
        timestamp=10000,
        max_score_entries=10,
    )
    assert observation.evidence_can_ban is False
    assert observation.event["policy"] == (
        "alert-only / TLS compatibility or latency probe"
    )


def test_time_correlated_relay_attribution_stays_alert_only():
    with patch(
        "hydra.core.source_relay.resolve_recent_unique_source",
        return_value="198.51.100.9",
    ):
        result = _resolve_unattributed_relay_source(
            {"protocol": "shadowtls", "kind": "auth_failure"},
        )
    assert result[0] == "198.51.100.9"
    assert result[1]["ban_eligible"] is False
    assert result[1]["policy"] == "alert-only / time-correlated attribution"


def test_generic_singbox_pattern_does_not_mask_hysteria2():
    _, event = parse_protocol_line(
        "sing-box.service",
        "inbound/hysteria2[hysteria2-in]: handshake failed from "
        "198.51.100.9:1234",
    )
    assert event["protocol"] == "hysteria2"
    assert event["ban_eligible"] is False


@pytest.mark.parametrize(
    ("uri", "suspicious"),
    [
        ("/?next=/.env", False),
        ("/blog?redirect=/.env", False),
        ("/.env", True),
        ("/.env.production", True),
        ("/backup/.env.bak", True),
        ("/wp-login.php", True),
        ("/actuator/health", True),
        ("/cgi-bin/test.cgi", True),
        ("/index.html", False),
    ],
)
def test_decoy_matches_the_path_not_the_query(uri, suspicious):
    record = {"request": {"remote_ip": "198.51.100.9", "uri": uri}}
    result = normalize_decoy_record(record)
    assert (result is not None) is suspicious


def test_trusttunnel_valid_connect_is_never_scanner_evidence():
    valid = {
        "status": 200,
        "request": {
            "remote_ip": "203.0.113.21",
            "method": "CONNECT",
            "uri": "example.com:443",
        },
    }
    assert normalize_trusttunnel_record(valid) is None


# --- Stage 2: reliable enforcement ----------------------------------------


def test_persistence_failure_precedes_all_effects():
    actions = []
    plugin = AntiDPIPlugin(
        notifier=lambda *a, **kw: actions.append("notice") or True,
    )
    store = _isolated_store({})
    store.save.side_effect = OSError("disk failure")
    with patch.object(plugin, "_state_store", return_value=store), \
         patch.object(plugin, "_state_lock", side_effect=nullcontext), \
         patch.object(plugin, "_is_whitelisted", return_value=False), \
         patch.object(plugin, "_add_firewall_ban", side_effect=lambda *a, **kw: actions.append("firewall") or True):
        with pytest.raises(OSError, match="disk failure"):
            plugin.observe_event(
                "198.51.100.9",
                {"kind": "active_decoy_probe"},
                now=10000,
            )
    assert actions == []


def test_ban_intent_is_durable_before_the_firewall_effect(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"

    def firewall(address, *, duration):
        persisted = json.loads(state_file.read_text(encoding="utf-8"))
        assert "198.51.100.9" in persisted["banned"], (
            "ban intent must be saved before the firewall effect"
        )
        return True

    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=MagicMock(returncode=0)), \
         patch.object(plugin, "_add_firewall_ban", side_effect=firewall):
        assert plugin.observe_event(
            "198.51.100.9",
            {"kind": "active_decoy_probe"},
            now=10000,
        ) is True
        plugin._drain_notifications()


def test_firewall_refusal_reverts_the_ban_intent(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    refused = MagicMock(returncode=1, stdout="", stderr="ipset offline")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=refused):
        assert plugin.observe_event(
            "198.51.100.9",
            {"kind": "active_decoy_probe"},
            now=10000,
        ) is False
        data = plugin._load_state()
    assert data["banned"] == {}
    assert data["ban_counts"].get("198.51.100.9", 0) == 0
    assert data["history"][0]["status"] == "failed"
    assert data["ban_failures"]["count"] == 1


def test_notifications_leave_the_state_lock_before_delivery(tmp_path):
    lock_state = []

    @contextmanager
    def tracking_lock():
        lock_state.append(True)
        try:
            yield
        finally:
            lock_state.append(False)

    def notifier(*args, **kwargs):
        assert lock_state[-1] is False, (
            "Telegram delivery must never run under the state lock"
        )
        return True

    plugin = AntiDPIPlugin(notifier=notifier)
    state_file = tmp_path / "antidpi.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=MagicMock(returncode=0)), \
         patch.object(plugin, "_state_lock", tracking_lock):
        assert plugin.observe_event(
            "198.51.100.9",
            {"kind": "active_decoy_probe"},
            now=10000,
        ) is True
        plugin._drain_notifications()


def test_unban_holds_the_state_lock_across_the_firewall_delete():
    plugin = AntiDPIPlugin()
    lock_state = []

    @contextmanager
    def tracking_lock():
        lock_state.append(True)
        try:
            yield
        finally:
            lock_state.append(False)

    def command(args, **kwargs):
        assert lock_state[-1] is True, (
            "ipset delete must run inside the unban state transaction"
        )
        return MagicMock(returncode=0)

    store = _isolated_store(
        {"banned": {"198.51.100.9": {"at": 10000, "duration": 600}}, "history": []},
    )
    with patch.object(plugin, "_state_lock", tracking_lock), \
         patch.object(plugin, "_command", side_effect=command), \
         patch.object(plugin, "_state_store", return_value=store):
        assert plugin.unban("198.51.100.9") is True
    store.save.assert_called_once()


def test_unban_and_manual_ban_interleave_consistently(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=result):
        plugin._save_state(
            {
                "banned": {"198.51.100.9": {"at": 10000, "permanent": True}},
                "history": [],
            },
        )
        # A manual ban completed before the unban is overridden by it...
        assert plugin.unban("198.51.100.9") is True
        assert plugin._load_state()["banned"] == {}
        # ...and one completed after survives in both state and firewall.
        assert plugin.manual_ban("198.51.100.9", source="test")["ok"] is True
        assert "198.51.100.9" in plugin._load_state()["banned"]


def test_whitelist_reports_failed_release_of_covered_bans():
    plugin = AntiDPIPlugin()
    data = {
        "banned": {"198.51.100.9": {"permanent": True, "at": 10000}},
        "history": [],
    }
    with patch.object(plugin, "_state_store", return_value=_isolated_store(data)), \
         patch.object(plugin, "_state_lock", side_effect=nullcontext), \
         patch.object(plugin, "unban", return_value=False):
        assert plugin.add_whitelist(
            state=AppState(),
            network="198.51.100.9/32",
        ) is False
    assert "198.51.100.9/32" in data["whitelist"]
    assert "198.51.100.9" in data["banned"]
    assert plugin.last_error


def test_whitelisted_active_bans_are_released_at_startup(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    state = {
        "whitelist": ["198.51.100.0/24"],
        "banned": {
            "198.51.100.9": {"at": NOW, "duration": 86400},
            "203.0.113.9": {"at": NOW, "duration": 86400},
        },
        "history": [],
    }
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=MagicMock(returncode=0)):
        plugin._save_state(copy.deepcopy(state))
        assert plugin.release_whitelisted_bans() == 1
        data = plugin._load_state()
    assert set(data["banned"]) == {"203.0.113.9"}


def test_corrupt_state_is_quarantined_not_silently_reset(tmp_path):
    path = tmp_path / "antidpi.json"
    path.write_text("{corrupt", encoding="utf-8")
    store = AntiDPIStateStore(path)
    with pytest.raises(AntiDPIStateCorruptError):
        store.load()
    quarantined = list(tmp_path.glob("antidpi.json.corrupt-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_text(encoding="utf-8") == "{corrupt"
    assert not path.exists()


def test_collector_startup_restores_enforcement():
    plugin = MagicMock()
    tail = MagicMock()
    tail.read.return_value = []
    with patch("hydra.plugins.antidpi.agent.threading.Thread"), \
         patch("hydra.plugins.antidpi.agent.JsonTail", return_value=tail), \
         patch("hydra.plugins.antidpi.agent.time.monotonic", return_value=0), \
         patch("hydra.plugins.antidpi.agent.time.sleep", side_effect=RuntimeError("stop")):
        with pytest.raises(RuntimeError, match="stop"):
            run(plugin, state_reader=AppState)
    plugin.reconcile_enforcement.assert_called_once()


def test_collector_heartbeat_is_persisted_and_health_detects_staleness(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_clock", return_value=1000.0):
        assert plugin.record_collector_heartbeat() is True
        assert plugin._load_state()["collector_heartbeat_at"] == 1000.0
        assert plugin._collector_heartbeat_ok() is True
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_clock", return_value=1000.0 + 601.0):
        assert plugin._collector_heartbeat_ok() is False
    fresh = tmp_path / "fresh.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", fresh), \
         patch.object(plugin, "_clock", return_value=1000.0):
        # A missing heartbeat is unknown, not a failure.
        assert plugin._collector_heartbeat_ok() is True


# --- Stage 2: collector event fidelity (D09) ------------------------------


def test_rotation_reads_already_written_new_file(tmp_path):
    path = tmp_path / "access.jsonl"
    path.write_text("", encoding="utf-8")
    tail = JsonTail(path, (normalize_decoy_record,))
    assert tail.read() == []
    # Close only for Windows rename sharing; the old inode and position stay.
    tail.handle.close()
    path.rename(tmp_path / "access.old")
    path.write_text(
        json.dumps(
            {"request": {"remote_ip": "198.51.100.9", "uri": "/.env"}},
        ) + "\n",
        encoding="utf-8",
    )
    try:
        assert len(tail.read()) == 1
    finally:
        tail.handle.close()


def test_partial_json_line_waits_for_completion(tmp_path):
    path = tmp_path / "access.jsonl"
    path.write_text("", encoding="utf-8")
    tail = JsonTail(path, (normalize_decoy_record,))
    assert tail.read() == []
    text = json.dumps(
        {"request": {"remote_ip": "198.51.100.9", "uri": "/.env"}},
    )
    with path.open("a", encoding="utf-8") as output:
        output.write(text[:25])
    assert tail.read() == []
    with path.open("a", encoding="utf-8") as output:
        output.write(text[25:] + "\n")
    try:
        assert len(tail.read()) == 1
    finally:
        tail.handle.close()


def test_json_tail_passes_the_records_own_clock(tmp_path):
    path = tmp_path / "access.jsonl"
    path.write_text("", encoding="utf-8")
    tail = JsonTail(path, (normalize_decoy_record,))
    assert tail.read() == []
    record = {
        "ts": 1700000000.25,
        "request": {"remote_ip": "198.51.100.9", "uri": "/.env"},
    }
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record) + "\n")
    try:
        events = tail.read()
    finally:
        tail.handle.close()
    assert events[0][1]["event_time"] == 1700000000.25


def test_event_now_trusts_only_plausible_timestamps():
    assert _event_now({"event_time": 1234567890.5}) == 1234567890.5
    assert _event_now({}) is None
    assert _event_now({"event_time": time.time() + 3600}) is None
    assert _event_now({"event_time": -1}) is None


def test_journal_cursor_roundtrip_and_clear(tmp_path):
    cursor_file = tmp_path / "antidpi.cursor"
    with patch("hydra.plugins.antidpi.agent.CURSOR_FILE", cursor_file):
        assert _load_cursor() == ""
        _store_cursor("s=abc;i=1;m=1;t=1;x=1")
        assert _load_cursor() == "s=abc;i=1;m=1;t=1;x=1"
        _store_cursor("")
        assert not cursor_file.exists()
        assert _load_cursor() == ""


def test_journal_follow_command_resumes_from_cursor():
    command = _journal_follow_command("s=abc;i=1")
    assert command[command.index("--after-cursor") + 1] == "s=abc;i=1"
    assert "-n" not in command
    assert "_TRANSPORT=kernel" in command
    assert "+" in command


def test_replayed_event_uses_only_its_remaining_ban_window(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    firewall = MagicMock(return_value=True)
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_clock", return_value=1100.0), \
         patch.object(plugin, "_add_firewall_ban", firewall):
        assert plugin.observe_event(
            "198.51.100.9",
            {
                "kind": "active_decoy_probe",
                "protocol": "tls",
                "handshake_ok": False,
                "sni_known": False,
            },
            event_time=1000.0,
        ) is True
        data = plugin._load_state()
    firewall.assert_called_once()
    assert firewall.call_args.kwargs["duration"] == 500
    assert data["banned"]["198.51.100.9"]["at"] == 1100.0
    assert data["banned"]["198.51.100.9"]["duration"] == 500


def test_stale_replayed_event_decays_without_enforcement(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_clock", return_value=2000.0), \
         patch.object(plugin, "_add_firewall_ban") as firewall:
        assert plugin.observe_event(
            "198.51.100.9",
            {"kind": "active_decoy_probe"},
            event_time=1000.0,
        ) is False
        data = plugin._load_state()
    firewall.assert_not_called()
    assert data["banned"] == {}
    assert data["scores"]["198.51.100.9"]["updated"] == 1000.0


def test_journal_cursor_is_committed_with_evidence_and_deduplicates_replay(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    event = {"kind": "active_decoy_probe", "_journal_cursor": "cursor-1"}
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_add_firewall_ban", return_value=True) as firewall:
        assert plugin.observe_event("198.51.100.9", event, now=1000) is True
        assert plugin.observe_event("198.51.100.9", event, now=1001) is False
        data = plugin._load_state()
    assert data["journal_cursor"] == "cursor-1"
    assert data["events"] == 1
    firewall.assert_called_once()


def test_journal_worker_does_not_acknowledge_queued_records(tmp_path):
    record = json.dumps({
        "__CURSOR": "cursor-1",
        "_SYSTEMD_UNIT": "sing-box.service",
        "MESSAGE": "handshake failed from 198.51.100.9:443",
    })
    process = MagicMock(stdout=[record])
    process.poll.return_value = 0
    stop = MagicMock()
    stop.is_set.side_effect = [False, False, False, True]
    stop.wait.return_value = True
    events = queue.Queue(maxsize=1)
    with patch("hydra.plugins.antidpi.agent.HOST.popen", return_value=process), \
         patch("hydra.plugins.antidpi.agent._store_cursor") as store_cursor:
        _journal_worker(events, stop, AppState)
    normalized, cursor = events.get_nowait()
    assert normalized is not None
    assert cursor == "cursor-1"
    store_cursor.assert_not_called()


def test_failed_manual_promotion_restores_the_timed_ban(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    original = {
        "banned": {"198.51.100.9": {
            "at": 1000, "duration": 600, "offense_count": 2,
            "signals": ["malformed_tls"],
        }},
        "history": [{
            "ip": "198.51.100.9", "at": 1000, "duration": 600,
            "offense_count": 2, "signals": ["malformed_tls"],
            "status": "active",
        }],
        "ban_counts": {"198.51.100.9": 2},
    }
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_clock", return_value=1100.0), \
         patch.object(plugin, "_ensure_sets", return_value=True), \
         patch.object(plugin, "_ensure_rules", return_value=True), \
         patch.object(plugin, "_add_firewall_ban", return_value=False):
        plugin._save_state(copy.deepcopy(original))
        assert plugin.manual_ban("198.51.100.9")["error"] == "firewall_error"
        data = plugin._load_state()
    assert data["banned"] == original["banned"]
    assert data["history"] == original["history"]
    assert data["ban_counts"] == original["ban_counts"]


def test_slow_telegram_delivery_never_blocks_detection(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    def notify(*_args, **_kwargs):
        entered.set()
        release.wait(2)
        return True

    plugin = AntiDPIPlugin(notifier=notify)
    state_file = tmp_path / "antidpi.json"
    started = time.monotonic()
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_add_firewall_ban", return_value=True):
        assert plugin.observe_event(
            "198.51.100.9", {"kind": "active_decoy_probe"}, now=1000,
        ) is True
        assert time.monotonic() - started < 0.5
        assert entered.wait(1)
        release.set()
        plugin._drain_notifications()
        stats = plugin._load_state()["notification_stats"]
    assert stats["delivered"] == 1


def test_corruption_pauses_detection_and_is_exposed(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    state_file.write_text("{broken", encoding="utf-8")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_add_firewall_ban") as firewall:
        assert plugin.observe_event(
            "198.51.100.9", {"kind": "active_decoy_probe"}, now=1000,
        ) is False
        snapshot = plugin.management_snapshot()
        checks = plugin._persisted_health_checks()
    firewall.assert_not_called()
    assert snapshot["degraded"] is True
    assert checks["state"] is False
    assert list(tmp_path.glob("antidpi.json.corrupt-*"))


def test_reconciliation_restores_all_objects_and_exposes_failure(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    state = AppState()
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_ensure_sets", return_value=True) as sets, \
         patch.object(plugin, "_ensure_rules", return_value=True) as rules, \
         patch.object(plugin, "_ensure_scan_rules", return_value=False) as scans, \
         patch.object(plugin, "sync_udp_probe_rules", return_value=True) as udp, \
         patch.object(plugin, "sync_mieru_probe_rules", return_value=True) as mieru, \
         patch.object(plugin, "release_whitelisted_bans", return_value=0) as release_bans, \
         patch.object(plugin, "whitelisted_bans", return_value=[]), \
         patch.object(plugin, "_restore_bans", return_value=True) as restore:
        assert _reconcile_enforcement(plugin, state) is False
        outcome = plugin._load_state()["reconciliation"]
    for operation in (sets, rules, scans, udp, mieru, release_bans, restore):
        operation.assert_called_once()
    assert outcome["ok"] is False
    assert outcome["failed"] == ["scan telemetry"]


def test_reconciliation_never_restores_whitelist_covered_bans(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_ensure_sets", return_value=True), \
         patch.object(plugin, "_ensure_rules", return_value=True), \
         patch.object(plugin, "_ensure_scan_rules", return_value=True), \
         patch.object(plugin, "sync_udp_probe_rules", return_value=True), \
         patch.object(plugin, "sync_mieru_probe_rules", return_value=True), \
         patch.object(plugin, "release_whitelisted_bans", return_value=0), \
         patch.object(plugin, "whitelisted_bans", return_value=["198.51.100.9"]), \
         patch.object(plugin, "_restore_bans") as restore:
        assert _reconcile_enforcement(plugin, AppState()) is False
    restore.assert_not_called()


def test_enable_never_restores_whitelist_covered_bans():
    plugin = AntiDPIPlugin()
    state = AppState()
    with patch.object(plugin, "_ensure_sets", return_value=True), \
         patch.object(plugin, "_ensure_rules", return_value=True), \
         patch.object(plugin, "_ensure_scan_rules", return_value=True), \
         patch.object(plugin, "sync_udp_probe_rules", return_value=True), \
         patch.object(plugin, "sync_mieru_probe_rules", return_value=True), \
         patch.object(plugin, "release_whitelisted_bans", return_value=0), \
         patch.object(plugin, "whitelisted_bans", return_value=["198.51.100.9"]), \
         patch.object(plugin, "_restore_bans") as restore:
        with pytest.raises(RuntimeError, match="firewall runtime"):
            plugin.on_enable(state)
    restore.assert_not_called()


# --- D15: archive redaction ------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer AUDIT_SECRET_VALUE",
        "Proxy-Authorization: Basic dXNlcjpwYXNz",
        "Cookie: session=AUDIT_SECRET_VALUE",
        '{"Authorization": ["Bearer AUDIT_SECRET_VALUE"]}',
        '{"password": "AUDIT_SECRET_VALUE"}',
        '{"nested": {"private_key": "AUDIT_SECRET_VALUE"}}',
        "upstream said password=hunter2secret and failed",
        "https://user:hunter2secret@example.com/path",
    ],
)
def test_redactor_removes_unknown_secrets(text):
    redacted = redactor(AppState())(text)
    for secret in ("AUDIT_SECRET_VALUE", "hunter2secret", "dXNlcjpwYXNz"):
        assert secret not in redacted


def test_redactor_keeps_json_documents_parseable():
    text = (
        '{"Authorization": "Bearer abc", '
        '"note": "see Authorization: Bearer xyz in logs"}'
    )
    parsed = json.loads(redactor(AppState())(text))
    assert parsed["Authorization"] == "[REDACTED]"
    assert "xyz" not in parsed["note"]


def test_redactor_removes_known_state_secrets_anywhere():
    state = AppState()
    state.telegram.admin_token = "tgt-1234567890abcdef"
    redacted = redactor(state)("token in text: tgt-1234567890abcdef")
    assert "tgt-1234567890abcdef" not in redacted


# --- Stage 5: operator views ----------------------------------------------


def _watch_state() -> dict:
    return {
        "scores": {
            f"198.51.100.{index}": {
                "score": 5,
                "verified_score": 0,
                "updated": 10000,
                "signals": ["unknown_sni"],
            }
            for index in range(1, 27)
        },
    }


def test_address_details_finds_addresses_beyond_the_list_limit():
    data = _watch_state()
    projection = management_projection(data, now=10000)
    assert len(projection["watchlist"]) == 25
    details = address_details(data, "198.51.100.26", now=10000)
    assert details["watch"]["ip"] == "198.51.100.26"
    assert details["tracked"] is True


def test_address_details_query_answers_for_any_tracked_address(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch.object(plugin, "_clock", return_value=10000.0):
        plugin._save_state(_watch_state())
        details = plugin.address_details("198.51.100.26")
    assert details["watch"]["ip"] == "198.51.100.26"
    assert plugin.address_details("203.0.113.1")["tracked"] is False
    assert plugin.address_details("not-an-ip") == {"valid": False}


def test_card_does_not_claim_no_evidence_beyond_the_list_limit():
    data = _watch_state()
    projection = management_projection(data, now=10000)
    details = address_details(data, "198.51.100.26", now=10000)
    app = MagicMock()
    app.plugin_query.side_effect = (
        lambda name, query, **kwargs: (
            details if query == "address_details" else projection
        )
    )
    text = address_card_text(app, "198.51.100.26")
    assert "под наблюдением" in text
    assert "улик нет" not in text


def test_card_distinguishes_unavailable_from_clean():
    app = MagicMock()
    app.plugin_query.side_effect = RuntimeError("state unavailable")
    text = address_card_text(app, "198.51.100.9")
    assert "нет данных" in text
    assert "улик нет" not in text
    assert "не срабатывал" not in text


def test_tui_ban_numbers_only_select_visible_rows():
    data = {
        "banned": {
            f"198.51.100.{index}": {
                "at": 10000 + index,
                "duration": 600,
                "score": 8,
                "signals": ["active_decoy_probe"],
            }
            for index in range(1, 26)
        },
    }
    projection = management_projection(data, now=10050)
    addresses = [row["ip"] for row in projection["ban_rows"]]
    visible = addresses[: tui_manager.BAN_PAGE_SIZE]
    hidden = addresses[tui_manager.BAN_PAGE_SIZE]
    rendered = "\n".join(
        ban_table(
            projection,
            limit=tui_manager.BAN_PAGE_SIZE,
        ),
    )
    assert not re.search(re.escape(hidden) + r"(?![\d.])", rendered)
    assert tui_manager._resolve_targets(
        str(tui_manager.BAN_PAGE_SIZE + 1),
        visible,
    ) == []
    assert tui_manager._resolve_targets("1", visible) == [visible[0]]


def test_tui_second_page_labels_match_accepted_row_numbers():
    data = {
        "ban_rows": [
            {
                "ip": f"198.51.100.{index}",
                "score": 8,
                "icon": "🔴",
                "remaining_label": "10м",
            }
            for index in range(1, 21)
        ],
    }
    rendered = "\n".join(ban_table(data, limit=10, offset=10))
    assert "  1 " in re.sub(r"\x1b\[[0-9;]*m", "", rendered)
    assert "  11 " not in re.sub(r"\x1b\[[0-9;]*m", "", rendered)


@pytest.mark.parametrize("kind", ["ban", "watch"])
def test_address_card_fallback_retains_snapshot_records(kind):
    address = "198.51.100.9"
    snapshot = {
        "ban_rows": [{
            "ip": address,
            "remaining_label": "10м",
            "score": 9,
            "offense": 2,
            "reason": "decoy",
        }] if kind == "ban" else [],
        "watchlist": [{
            "ip": address,
            "score": 4,
            "threshold": 8,
            "reason": "auth",
        }] if kind == "watch" else [],
    }
    app = MagicMock()

    def query(plugin, name, **_kwargs):
        if plugin == "honeypot":
            return {"banned": {}}
        if name == "address_details":
            raise RuntimeError("old deployment")
        return snapshot

    app.plugin_query.side_effect = query
    text = address_card_text(app, address)
    expected = "заблокирован" if kind == "ban" else "под наблюдением"
    assert expected in text
    assert "улик нет" not in text
