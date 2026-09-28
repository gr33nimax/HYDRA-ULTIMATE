"""Contracts for the bounded AntiScan operator projection and its vocabulary.

The contraction removed scoring, evidence families and subnet correlation, so
the projection only ever presents what the runtime actually did: active bans,
closed records and aggregate counters.  Legacy score entries stay hidden.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from hydra.plugins.antidpi.labels import (
    ban_view,
    counter_rows,
    health_label,
    signal_label,
    signal_list,
    signal_summary,
    source_label,
)
from hydra.plugins.antidpi.model import (
    BAN_DURATIONS,
    active_bans,
    get_ban_duration,
    prune_runtime_state,
)
from hydra.plugins.antidpi.plugin import AntiDPIPlugin
from hydra.plugins.antidpi.projection import (
    address_details,
    ban_rows,
    counters,
    management_projection,
)

NOW = 1_800_000_000.0


# --- projection ------------------------------------------------------------


def test_projection_hides_derived_and_legacy_state():
    data = {
        "scores": {"198.51.100.1": {"score": 9.0, "updated": NOW}},
        "subnets": {"198.51.100.0/24": {"members": 3}},
        "banned": {"203.0.113.9": {"at": NOW, "duration": 600}},
        "history": [{"ip": "203.0.113.9", "at": NOW, "status": "active"}],
    }
    projection = management_projection(data, now=NOW)

    # Legacy ledgers are dropped entirely.
    assert "scores" not in projection
    assert "subnets" not in projection
    # Derived keys are recomputed, never copied through verbatim.
    assert "watchlist" not in projection
    assert "coordinated" not in projection
    assert projection["banned"] == active_bans(data, now=NOW)
    assert projection["history"] == data["history"]
    assert [row["ip"] for row in projection["ban_rows"]] == ["203.0.113.9"]


def test_projection_renders_evidence_vocabulary():
    data = {
        "banned": {
            "203.0.113.9": {
                "at": NOW,
                "duration": 600,
                "source": "journal",
                "protocol": "snell",
                "kind": "protocol_reject",
                "reason": "record_auth_failed",
                "signals": ["snell:record_auth_failed"],
            },
        },
    }
    row = ban_rows(data, now=NOW)[0]

    assert row["protocol"] == "snell"
    assert row["source"] == "журнал протокола"
    assert row["reason"] == "Snell: неверный ключ клиента"
    assert row["offense"] == 1
    assert row["expired"] is False


def test_projection_translates_counters_and_last_source():
    data = {
        "signal_counts": {"snell:record_auth_failed": 4, "https:scanner_path": 1},
        "source_counts": {"journal": 4, "caddy-decoy": 1},
        "last_event_source": "journal",
    }
    projection = management_projection(data, now=NOW)

    assert projection["last_event_source_label"] == "журнал протокола"
    assert [row["label"] for row in projection["counters"]["signals"]][0] == ("Snell: неверный ключ клиента")
    assert counters(data)["sources"][0]["label"] == "журнал протокола"


def test_address_details_reports_only_real_bans_and_history():
    data = {
        "banned": {"203.0.113.9": {"at": NOW, "duration": 600}},
        "history": [
            {"ip": "203.0.113.9", "at": NOW, "status": "active"},
            {"ip": "198.51.100.4", "at": NOW - 60, "status": "expired"},
        ],
    }
    banned = address_details(data, "203.0.113.9", now=NOW)
    closed = address_details(data, "198.51.100.4", now=NOW)
    unknown = address_details(data, "192.0.2.44", now=NOW)

    assert banned["tracked"] is True
    assert banned["ban"]["ip"] == "203.0.113.9"
    assert closed["tracked"] is True
    assert "ban" not in closed
    assert unknown == {"ip": "192.0.2.44", "now": NOW, "tracked": False}


def test_ban_rows_are_ordered_newest_first():
    data = {
        "banned": {
            "203.0.113.1": {"at": NOW - 100, "duration": 600},
            "203.0.113.2": {"at": NOW, "duration": 600},
        },
    }
    assert [row["ip"] for row in ban_rows(data, now=NOW)] == [
        "203.0.113.2",
        "203.0.113.1",
    ]


# --- ban lifecycle memory --------------------------------------------------


def test_escalation_memory_is_pruned_to_live_bans_and_history():
    data = {
        "banned": {"203.0.113.1": {"at": NOW, "duration": 600}},
        "history": [{"ip": "203.0.113.2", "at": NOW, "status": "expired"}],
        "ban_counts": {"203.0.113.1": 1, "203.0.113.2": 2, "203.0.113.3": 3},
        "sources": {"203.0.113.3": {"count": 1}},
    }
    prune_runtime_state(data, now=NOW, max_entries=100)

    assert set(data["ban_counts"]) == {"203.0.113.1", "203.0.113.2"}


def test_pruning_leaves_absent_escalation_memory_untouched():
    data = {"banned": {}, "history": []}
    prune_runtime_state(data, now=NOW, max_entries=100)

    assert "ban_counts" not in data


def test_progressive_durations_are_ordered_and_bounded():
    assert get_ban_duration(1) == BAN_DURATIONS[0]
    assert get_ban_duration(2) > get_ban_duration(1)
    assert get_ban_duration(99) == BAN_DURATIONS[-1]
    assert active_bans({}, now=NOW) == {}


def test_detector_records_a_failure_when_the_firewall_refuses_a_ban(tmp_path):
    state_file = tmp_path / "antidpi.json"
    refused = MagicMock(returncode=1, stdout="", stderr="ipset offline")
    evidence = {
        "kind": "decoy_scan",
        "protocol": "https",
        "reason": "scanner_path",
        "source": "caddy-decoy",
        "attribution": "direct",
    }
    with (
        patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file),
        patch("hydra.plugins.antidpi.plugin._run", return_value=refused),
    ):
        plugin = AntiDPIPlugin()
        assert plugin.observe_event("203.0.113.9", evidence, now=NOW) is False
        data = plugin._load_state()

    assert data["banned"] == {}
    assert data["ban_failures"]["count"] == 1
    assert data["ban_failures"]["last_ip"] == "203.0.113.9"


# --- labels ----------------------------------------------------------------


def test_labels_fall_back_to_raw_keys_instead_of_hiding_evidence():
    assert signal_label("snell:record_auth_failed") == "Snell: неверный ключ клиента"
    assert signal_label("some:new_reason") == "some:new_reason"
    assert source_label("caddy-decoy") == "decoy-сайт"
    assert source_label("future-source") == "future-source"
    assert health_label("obsolete_telemetry_removed") == ("устаревшая телеметрия удалена")


def test_signal_summary_truncates_with_an_overflow_marker():
    assert signal_summary(["snell:record_auth_failed"], limit=1) == ("Snell: неверный ключ клиента")
    assert signal_summary(["a", "b", "c"], limit=2).endswith("+1")
    assert signal_label("") == "—"


def test_signal_list_normalizes_legacy_shapes():
    assert signal_list("a, b") == ["a", "b"]
    assert signal_list(["a", "", "b"]) == ["a", "b"]
    assert signal_list(None) == []


def test_ban_view_states_cover_permanent_expired_and_running_bans():
    permanent = ban_view("203.0.113.1", {"permanent": True}, now=NOW)
    expired = ban_view("203.0.113.2", {"at": 0, "duration": 60}, now=NOW)
    running = ban_view("203.0.113.3", {"at": NOW, "duration": 600}, now=NOW)

    assert permanent["permanent"] is True and permanent["remaining"] == 0.0
    assert expired["expired"] is True
    assert running["expired"] is False and running["remaining"] > 0


def test_ban_view_survives_corrupt_persisted_records():
    row = ban_view("203.0.113.1", {"at": "not-a-number", "duration": {}}, now=NOW)

    assert row["ip"] == "203.0.113.1"
    assert row["expired"] is True
    assert row["offense"] >= 1


def test_counter_rows_are_ranked_and_labeled_within_the_limit():
    rows = counter_rows(
        {"https:scanner_path": 1, "snell:record_auth_failed": 9},
        signal_label,
        limit=1,
    )
    assert len(rows) == 1
    assert rows[0]["key"] == "snell:record_auth_failed"
    assert rows[0]["count"] == 9
    assert rows[0]["maximum"] == 9
