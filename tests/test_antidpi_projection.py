"""Contracts for the bounded AntiDPI operator projection and its vocabulary."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from hydra.plugins.antidpi.labels import (
    SIGNAL_LABELS,
    ban_view,
    counter_rows,
    health_label,
    signal_label,
    signal_summary,
    source_label,
)
from hydra.plugins.antidpi.model import (
    BAN_THRESHOLD,
    SIGNAL_WEIGHTS,
    prune_ban_counts,
    record_ban_failure,
)
from hydra.plugins.antidpi.plugin import AntiDPIPlugin
from hydra.plugins.antidpi.projection import (
    ban_rows,
    management_projection,
    watchlist,
)

NOW = 1_800_000_000.0


def _state() -> dict:
    return {
        "events": 12,
        "last_event_at": NOW - 30,
        "last_event_source": "kernel-firewall",
        "whitelist": ["203.0.113.10"],
        "ban_counts": {
            "198.51.100.5": 3,
            "198.51.100.30": 1,
            "203.0.113.200": 7,
        },
        "banned": {
            "198.51.100.5": {
                "at": NOW - 1200,
                "duration": 86400,
                "score": 14.0,
                "offense_count": 3,
                "signals": ["active_decoy_probe", "port_sweep"],
                "source": "caddy-decoy",
                "protocol": "https",
            },
            "198.51.100.6": {
                "at": NOW - 100_000,
                "duration": 600,
                "score": 9.0,
            },
        },
        "history": [
            {"ip": "198.51.100.30", "at": NOW - 90_000, "status": "expired"},
        ],
        "scores": {
            "203.0.113.77": {
                "score": 6.0,
                "verified_score": 3.0,
                "updated": NOW,
                "signals": ["unknown_sni", "handshake_failure"],
            },
            "198.51.100.5": {"score": 14.0, "updated": NOW},
            "203.0.113.90": {"score": 0.1, "updated": NOW},
            "203.0.113.91": {"score": 4.0, "updated": NOW - 86_400},
        },
        "signal_counts": {"unknown_sni": 40, "port_scan": 10},
        "source_counts": {"kernel-firewall": 30, "journal": 5},
    }


def test_projection_drops_raw_scores_but_reports_their_volume():
    projection = management_projection(_state(), now=NOW)

    assert "scores" not in projection
    assert projection["tracked_addresses"] == 4
    assert projection["now"] == NOW


def test_projection_exposes_only_active_bans_with_rendered_labels():
    projection = management_projection(_state(), now=NOW)

    assert set(projection["banned"]) == {"198.51.100.5"}
    row = projection["ban_rows"][0]
    assert row["ip"] == "198.51.100.5"
    assert row["remaining_label"] == "23ч 40м"
    assert row["reason"] == "активная проверка decoy, перебор разных портов"
    assert row["source"] == "decoy-сайт"
    assert row["offense"] == 3


def test_projection_translates_counters_and_the_last_event_source():
    projection = management_projection(_state(), now=NOW)

    assert projection["last_event_source_label"] == "телеметрия ядра"
    signals = projection["counters"]["signals"]
    assert [row["label"] for row in signals] == [
        "неизвестный SNI",
        "сканирование портов",
    ]
    assert signals[0]["maximum"] == 40
    assert [row["label"] for row in projection["counters"]["sources"]] == [
        "телеметрия ядра",
        "журнал протокола",
    ]


def test_watchlist_ranks_unbanned_evidence_and_decays_stale_entries():
    rows = watchlist(_state(), now=NOW)

    assert [row["ip"] for row in rows] == ["203.0.113.77"]
    entry = rows[0]
    assert entry["score"] == 6.0
    assert entry["verified_score"] == 3.0
    assert entry["reason"] == "неизвестный SNI, ошибка handshake"
    # Both signals belong to one family, so the address must clear the higher
    # solo bar before a ban.
    assert entry["evidence"] == "согласование TLS"
    assert entry["threshold"] > float(BAN_THRESHOLD)
    assert entry["block_reason"] == "below_threshold"


def test_watchlist_names_corroboration_as_the_only_missing_piece():
    state = _state()
    state["scores"]["203.0.113.77"].update(
        {"score": 9.0, "verified_score": 9.0, "families": {"auth": NOW}},
    )
    entry = watchlist(state, now=NOW)[0]

    # Enough evidence for the normal threshold, but all of it is one family.
    assert entry["verified_score"] >= float(BAN_THRESHOLD)
    assert entry["block_reason"] == "single_family"


def test_watchlist_threshold_drops_once_evidence_is_corroborated():
    state = _state()
    state["scores"]["203.0.113.77"]["families"] = {
        "tls_negotiation": NOW,
        "scanning": NOW,
    }
    entry = watchlist(state, now=NOW)[0]

    assert entry["threshold"] == float(BAN_THRESHOLD)
    assert entry["block_reason"] == "below_threshold"
    assert "сканирование" in entry["evidence"]


def test_watchlist_threshold_falls_for_repeat_offenders():
    state = _state()
    state["scores"]["203.0.113.77"]["families"] = {
        "tls_negotiation": NOW,
        "scanning": NOW,
    }
    state["ban_counts"]["203.0.113.77"] = 3
    entry = watchlist(state, now=NOW)[0]

    assert entry["offense_count"] == 3
    assert entry["threshold"] == 5.0


def test_projection_reports_coordinated_subnets_and_hides_raw_aggregates():
    state = _state()
    state["subnets"] = {
        "203.0.113.0/24": {
            "updated": NOW,
            "members": {f"203.0.113.{index}": NOW for index in range(1, 6)},
        },
        "198.51.100.0/24": {
            "updated": NOW,
            "members": {"198.51.100.1": NOW},
        },
    }
    projection = management_projection(state, now=NOW)

    assert "subnets" not in projection
    assert [row["prefix"] for row in projection["coordinated"]] == [
        "203.0.113.0/24",
    ]
    assert projection["coordinated"][0]["members"] == 5


def test_watchlist_is_bounded_by_the_requested_limit():
    state = {
        "scores": {
            f"198.51.100.{index}": {"score": index, "updated": NOW}
            for index in range(1, 20)
        },
    }
    rows = watchlist(state, now=NOW, limit=3)
    assert [row["ip"] for row in rows] == [
        "198.51.100.19",
        "198.51.100.18",
        "198.51.100.17",
    ]


def test_ban_rows_are_ordered_newest_first():
    state = _state()
    state["banned"]["198.51.100.7"] = {"at": NOW - 10, "duration": 600}
    rows = ban_rows(state, now=NOW)
    assert [row["ip"] for row in rows] == ["198.51.100.7", "198.51.100.5"]


def test_escalation_memory_is_pruned_to_live_bans_and_history():
    state = _state()
    prune_ban_counts(state, now=NOW)
    assert set(state["ban_counts"]) == {"198.51.100.5", "198.51.100.30"}


def test_pruning_leaves_absent_escalation_memory_untouched():
    state = {"banned": {}, "history": []}
    prune_ban_counts(state, now=NOW)
    assert "ban_counts" not in state


def test_ban_failures_are_persisted_for_operator_visibility():
    data: dict = {}
    record_ban_failure(data, "198.51.100.77", now=NOW)
    record_ban_failure(data, "198.51.100.78", now=NOW + 5)
    assert data["ban_failures"] == {
        "count": 2,
        "last_at": NOW + 5,
        "last_ip": "198.51.100.78",
    }


def test_detector_records_a_failure_when_the_firewall_refuses_a_ban(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi-ban-failure.json"
    event = {"kind": "active_decoy_probe", "protocol": "https"}
    refused = MagicMock(returncode=1, stdout="", stderr="ipset offline")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=refused):
        assert plugin.observe_event("203.0.113.5", event, now=NOW) is False
        data = plugin._load_state()

    assert data["banned"] == {}
    assert data["ban_failures"]["count"] == 1
    assert data["ban_failures"]["last_ip"] == "203.0.113.5"


def test_every_scoring_signal_has_a_human_label():
    assert set(SIGNAL_WEIGHTS) <= set(SIGNAL_LABELS)


def test_labels_fall_back_to_raw_keys_instead_of_hiding_evidence():
    assert signal_label("unknown_sni") == "неизвестный SNI"
    assert signal_label("future_signal") == "future_signal"
    assert source_label("caddy-decoy") == "decoy-сайт"
    assert source_label("") == "—"
    assert health_label("firewall") == "правила DROP в INPUT"


def test_signal_summary_truncates_with_an_overflow_marker():
    assert signal_summary(["port_scan", "unknown_sni"], limit=1) == (
        "сканирование портов, +1"
    )
    assert signal_summary("legacy_string") == "legacy_string"
    assert signal_summary(None) == "аномальное поведение"


def test_ban_view_states_cover_permanent_expired_and_running_bans():
    permanent = ban_view("198.51.100.1", {"permanent": True, "at": NOW}, now=NOW)
    assert (permanent["remaining_label"], permanent["icon"]) == (
        "бессрочно",
        "🔴",
    )

    expired = ban_view(
        "198.51.100.2",
        {"at": NOW - 700, "duration": 600},
        now=NOW,
    )
    assert (expired["remaining_label"], expired["expired"]) == ("истёк", True)

    closing = ban_view(
        "198.51.100.3",
        {"at": NOW - 500, "duration": 600},
        now=NOW,
    )
    assert closing["icon"] == "🟠"
    assert closing["remaining_label"] == "1м 40с"


def test_ban_view_survives_corrupt_persisted_records():
    view = ban_view("198.51.100.4", {"at": "broken", "score": None}, now=NOW)
    assert view["at"] == 0.0
    assert view["score"] == 0.0
    assert view["reason"] == "аномальное поведение"


def test_counter_rows_are_ranked_and_labeled_within_the_limit():
    rows = counter_rows(
        {"unknown_sni": 5, "port_scan": 9, "broken": "x"},
        signal_label,
        limit=1,
    )
    assert rows == [
        {
            "key": "port_scan",
            "count": 9,
            "label": "сканирование портов",
            "maximum": 9,
        },
    ]
