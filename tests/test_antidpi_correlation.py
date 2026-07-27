"""Behaviour contracts for AntiDPI evidence correlation.

These tests describe the two failure modes the correlation layer exists to
prevent: banning a real client that merely misbehaves, and missing a probe that
spreads itself thin across one subnet.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from hydra.plugins.antidpi.correlation import (
    DECISIVE_SIGNALS,
    SIGNAL_FAMILIES,
    active_families,
    ban_threshold,
    block_reason,
    coordinated_subnets,
    event_weight,
    record_families,
    record_subnet_activity,
    required_score,
    signal_family,
    subnet_of,
)
from hydra.plugins.antidpi.model import (
    BAN_THRESHOLD,
    SIGNAL_WEIGHTS,
    score_event,
)
from hydra.plugins.antidpi.plugin import AntiDPIPlugin

NOW = 1_800_000_000.0


def _plugin(tmp_path, name, **kwargs):
    plugin = AntiDPIPlugin(**kwargs)
    return plugin, tmp_path / name


def _accepted():
    return MagicMock(returncode=0, stdout="", stderr="")


def test_every_weighted_signal_belongs_to_a_family():
    assert set(SIGNAL_WEIGHTS) <= set(SIGNAL_FAMILIES)
    assert DECISIVE_SIGNALS <= set(SIGNAL_WEIGHTS)


def test_repeated_signals_saturate_instead_of_accumulating():
    entry: dict = {}
    weights = [
        event_weight(entry, ("auth_failure",), timestamp=NOW + index)
        for index in range(5)
    ]

    assert weights[0] == float(SIGNAL_WEIGHTS["auth_failure"])
    assert weights == sorted(weights, reverse=True)
    assert weights[-1] > 0
    # Five identical failures stay under a single ban threshold.
    assert sum(weights) < float(BAN_THRESHOLD) * 1.5


def test_distinct_signals_are_not_penalised_by_each_others_repeats():
    entry: dict = {}
    event_weight(entry, ("auth_failure",), timestamp=NOW)
    event_weight(entry, ("auth_failure",), timestamp=NOW + 1)
    fresh = event_weight(entry, ("malformed_tls",), timestamp=NOW + 2)

    assert fresh == float(SIGNAL_WEIGHTS["malformed_tls"])


def test_repeat_memory_expires_so_old_noise_does_not_mute_new_evidence():
    entry: dict = {}
    event_weight(entry, ("auth_failure",), timestamp=NOW)
    later = event_weight(entry, ("auth_failure",), timestamp=NOW + 1000)

    assert later == float(SIGNAL_WEIGHTS["auth_failure"])
    assert set(entry["signal_hits"]) == {"auth_failure"}


def test_repeat_ledger_is_bounded():
    entry: dict = {}
    for index in range(40):
        event_weight(entry, (f"signal_{index}", "auth_failure"), timestamp=NOW)
    assert len(entry["signal_hits"]) <= 24


def test_families_are_recorded_and_expire():
    entry: dict = {}
    record_families(entry, ("unknown_sni", "handshake_failure"), timestamp=NOW)
    assert active_families(entry, timestamp=NOW) == ("tls_negotiation",)

    record_families(entry, ("port_scan",), timestamp=NOW + 10)
    assert active_families(entry, timestamp=NOW + 10) == (
        "scanning",
        "tls_negotiation",
    )
    assert active_families(entry, timestamp=NOW + 100_000) == ()


def test_one_family_must_clear_a_higher_bar_than_corroborated_evidence():
    solo = required_score(families=("auth",), signals=("auth_failure",))
    corroborated = required_score(
        families=("auth", "scanning"),
        signals=("auth_failure", "port_scan"),
    )

    assert corroborated == float(BAN_THRESHOLD)
    assert solo > corroborated


@pytest.mark.parametrize("signal", sorted(DECISIVE_SIGNALS))
def test_decisive_signals_never_wait_for_a_second_family(signal):
    threshold = required_score(families=("decoy",), signals=(signal,))
    assert threshold <= float(SIGNAL_WEIGHTS[signal])
    assert threshold <= float(BAN_THRESHOLD)


def test_known_offenders_need_less_new_evidence_but_never_zero():
    assert ban_threshold(0) == float(BAN_THRESHOLD)
    assert ban_threshold(2) < ban_threshold(1) < ban_threshold(0)
    assert ban_threshold(99) >= 4.0


def test_block_reason_names_the_missing_piece():
    assert block_reason(
        score=9.0,
        required=12.0,
        families=("auth",),
        evidence_can_ban=True,
    ) == "single_family"
    assert block_reason(
        score=2.0,
        required=8.0,
        families=("auth", "scanning"),
        evidence_can_ban=True,
    ) == "below_threshold"
    assert block_reason(
        score=99.0,
        required=8.0,
        families=(),
        evidence_can_ban=False,
    ) == "unverified_source"
    assert block_reason(
        score=9.0,
        required=8.0,
        families=("auth", "scanning"),
        evidence_can_ban=True,
    ) == ""


def test_subnet_aggregation_uses_ipv4_and_ipv6_prefixes():
    assert subnet_of("203.0.113.9") == "203.0.113.0/24"
    assert subnet_of("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert subnet_of("nonsense") == ""


def test_coordination_is_reported_once_per_cooldown():
    data: dict = {}
    reports = [
        record_subnet_activity(data, f"203.0.113.{index}", timestamp=NOW)
        for index in range(1, 7)
    ]

    assert all(report == {} for report in reports[:3])
    assert reports[3]["prefix"] == "203.0.113.0/24"
    assert reports[3]["first_report"] is True
    # Later members keep counting but do not re-notify inside the cooldown.
    assert reports[4]["first_report"] is False
    assert reports[5]["members"] == 6


def test_coordination_expires_and_is_bounded():
    data: dict = {}
    for index in range(1, 5):
        record_subnet_activity(data, f"203.0.113.{index}", timestamp=NOW)
    assert coordinated_subnets(data, now=NOW)[0]["members"] == 4
    assert coordinated_subnets(data, now=NOW + 10_000) == []

    for index in range(700):
        record_subnet_activity(
            data,
            f"198.{index // 256}.{index % 256}.1",
            timestamp=NOW,
        )
    assert len(data["subnets"]) <= 512


def test_signal_family_falls_back_to_the_raw_key():
    assert signal_family("auth_failure") == "auth"
    assert signal_family("future_signal") == "future_signal"


def test_repeated_auth_failures_alert_but_never_ban_a_real_client(tmp_path):
    """A user retyping a password must not lose every port on the VPS."""
    notify = MagicMock(return_value=True)
    plugin, state_file = _plugin(tmp_path, "auth-noise.json", notifier=notify)
    event = {
        "kind": "auth_failure",
        "protocol": "anytls",
        "source": "journal",
    }
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=_accepted()):
        banned = [
            plugin.observe_event("203.0.113.77", event, now=NOW + index)
            for index in range(8)
        ]
        data = plugin._load_state()

    assert not any(banned)
    assert data.get("banned", {}) == {}
    assert notify.call_count >= 1


def test_sustained_brute_force_still_reaches_a_ban(tmp_path):
    """Saturation slows single-family evidence; it does not grant immunity."""
    plugin, state_file = _plugin(tmp_path, "brute-force.json")
    event = {
        "kind": "auth_failure",
        "protocol": "anytls",
        "source": "journal",
    }
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=_accepted()):
        banned = any(
            plugin.observe_event("203.0.113.78", event, now=NOW + index)
            for index in range(120)
        )
        data = plugin._load_state()

    assert banned
    assert "203.0.113.78" in data["banned"]


def test_two_evidence_families_ban_at_the_normal_threshold(tmp_path):
    plugin, state_file = _plugin(tmp_path, "corroborated.json")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=_accepted()):
        plugin.observe_event(
            "203.0.113.79",
            {"kind": "malformed_tls", "protocol": "tls", "source": "journal"},
            now=NOW,
        )
        plugin.observe_event(
            "203.0.113.79",
            {"kind": "auth_failure", "protocol": "anytls", "source": "journal"},
            now=NOW + 1,
        )
        banned = plugin.observe_event(
            "203.0.113.79",
            {
                "kind": "invalid_first_packet",
                "protocol": "snell",
                "source": "journal",
            },
            now=NOW + 2,
        )
        data = plugin._load_state()

    assert banned is True
    metadata = data["banned"]["203.0.113.79"]
    assert metadata["score"] >= float(BAN_THRESHOLD)


def test_decoy_probe_still_bans_on_first_contact(tmp_path):
    plugin, state_file = _plugin(tmp_path, "decoy.json")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=_accepted()):
        banned = plugin.observe_event(
            "203.0.113.80",
            {
                "kind": "active_decoy_probe",
                "protocol": "https",
                "source": "caddy-decoy",
            },
            now=NOW,
        )

    assert banned is True
    assert score_event({"kind": "active_decoy_probe"})[0] >= BAN_THRESHOLD


def test_repeat_offender_is_banned_by_less_new_evidence(tmp_path):
    plugin, state_file = _plugin(tmp_path, "offender.json")
    event = {"kind": "malformed_tls", "protocol": "tls", "source": "journal"}
    second = {"kind": "auth_failure", "protocol": "anytls", "source": "journal"}
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=_accepted()):
        plugin._save_state(
            {
                "banned": {},
                "scores": {},
                "history": [],
                "ban_counts": {"203.0.113.81": 3},
            },
        )
        plugin.observe_event("203.0.113.81", event, now=NOW)
        banned = plugin.observe_event("203.0.113.81", second, now=NOW + 1)

    assert banned is True


def test_coordinated_subnet_notifies_once_without_banning_its_members(tmp_path):
    notify = MagicMock(return_value=True)
    plugin, state_file = _plugin(tmp_path, "coordinated.json", notifier=notify)
    event = {"kind": "malformed_tls", "protocol": "tls", "source": "journal"}
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=_accepted()):
        for index in range(1, 7):
            plugin.observe_event(
                f"198.51.100.{index}",
                event,
                now=NOW + index,
            )
        data = plugin._load_state()

    assert data.get("banned", {}) == {}
    actions = [call.args[1] for call in notify.call_args_list]
    assert actions.count("COORDINATED") == 1
    coordinated = next(
        call for call in notify.call_args_list if call.args[1] == "COORDINATED"
    )
    fields = dict(coordinated.args[2])
    assert fields["Subnet"] == "198.51.100.0/24"
    assert fields["Addresses"] >= 4
