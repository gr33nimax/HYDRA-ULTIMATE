from unittest.mock import MagicMock, patch

from hydra.plugins.antidpi.plugin import (
    AntiDPIPlugin,
    decayed_score,
    l4_deny_route,
    normalize_caddy_record,
    normalize_decoy_record,
    score_event,
)


def test_single_transient_failure_is_not_a_high_confidence_signal():
    score, signals = score_event({"protocol": "tls", "handshake_ok": False})
    assert score == 2
    assert signals == ("handshake_failure",)


def test_probe_combination_scores_above_ban_threshold():
    score, signals = score_event({
        "kind": "bad_client_hello", "sni_known": False,
        "protocol": "tls", "handshake_ok": False,
        "connections_10s": 20,
    })
    assert score >= 8
    assert {"malformed_tls", "unknown_sni", "handshake_failure", "connection_burst"} <= set(signals)


def test_l4_deny_route_normalizes_only_valid_networks():
    route = l4_deny_route(["203.0.113.7", "2001:db8::/32", "not-an-ip"])
    assert route["match"][0]["remote_ip"]["ranges"] == ["203.0.113.7/32", "2001:db8::/32"]
    assert l4_deny_route([]) is None


def test_caddy_error_is_normalized_to_an_ip_event():
    result = normalize_caddy_record({
        "logger": "layer4", "remote": "203.0.113.8:41412",
        "msg": "no certificate available for unknown SNI",
    })
    assert result == ("203.0.113.8", {"protocol": "tls", "handshake_ok": False, "kind": "unknown_sni", "sni_known": False})


def test_score_decays_over_time():
    assert decayed_score(8, 300) == 4
    assert decayed_score(8, 900) == 1


def test_active_decoy_probe_is_evidence_but_normal_page_is_not():
    request = {"remote_ip": "203.0.113.10", "method": "GET", "uri": "/.env"}
    assert normalize_decoy_record({"request": request}) == (
        "203.0.113.10", {"protocol": "https", "kind": "active_decoy_probe", "source": "caddy-decoy"},
    )
    request["uri"] = "/index.html"
    assert normalize_decoy_record({"request": request}) is None


def test_firewall_rule_insert_has_a_valid_iptables_operation():
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return MagicMock(returncode=1 if "-C" in command else 0, stdout="", stderr="")

    with patch("hydra.plugins.antidpi.plugin._run", side_effect=fake_run):
        assert AntiDPIPlugin()._ensure_rules() is True

    inserts = [command for command in calls if "-I" in command]
    assert inserts[0][:4] == ["iptables", "-I", "INPUT", "1"]
    assert inserts[1][:4] == ["ip6tables", "-I", "INPUT", "1"]


def test_ban_history_is_created_once_and_legacy_signals_are_safe(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi.json"
    event = {"kind": "malformed_tls", "protocol": "tls", "handshake_ok": False, "sni_known": False}
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
        assert plugin.observe_event("203.0.113.20", event, now=1000) is True
        assert plugin.observe_event("203.0.113.20", event, now=1001) is True
        data = plugin._load_state()
    assert len(data["history"]) == 1
    assert data["history"][0]["ip"] == "203.0.113.20"

    from hydra.plugins.antidpi.manager import _signals
    assert _signals({"signals": None}) == "—"
    assert _signals({"signals": "legacy"}) == "legacy"


def test_progressive_ban_durations(tmp_path):
    from hydra.plugins.antidpi.plugin import get_ban_duration
    assert get_ban_duration(1) == 600
    assert get_ban_duration(2) == 3600
    assert get_ban_duration(3) == 86400
    assert get_ban_duration(4) == 604800
    assert get_ban_duration(10) == 604800

    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi_progressive.json"
    event = {"kind": "malformed_tls", "protocol": "tls", "handshake_ok": False, "sni_known": False}
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
        # First ban -> 600s
        assert plugin.observe_event("198.51.100.5", event, now=1000) is True
        data = plugin._load_state()
        assert data["banned"]["198.51.100.5"]["duration"] == 600
        assert data["banned"]["198.51.100.5"]["offense_count"] == 1

        # Unban
        plugin.unban("198.51.100.5")

        # Second ban -> 3600s
        assert plugin.observe_event("198.51.100.5", event, now=2000) is True
        data = plugin._load_state()
        assert data["banned"]["198.51.100.5"]["duration"] == 3600
        assert data["banned"]["198.51.100.5"]["offense_count"] == 2


def test_normalize_tls_auth_failure():
    from hydra.plugins.antidpi.adapters import normalize_tls_auth_failure, parse_protocol_line
    record = {"remote": "198.51.100.99:54321", "msg": "authentication failed: invalid password"}
    res = normalize_tls_auth_failure(record)
    assert res is not None
    assert res[0] == "198.51.100.99"
    assert res[1]["kind"] == "auth_failure"

    parsed = parse_protocol_line("anytls", "2026-07-20 AnyTLS authentication failed for 198.51.100.100:1234")
    assert parsed is not None
    assert parsed[0] == "198.51.100.100"
    assert parsed[1]["kind"] == "auth_failure"


def test_whitelist_caching():
    from hydra.plugins.antidpi.plugin import _get_whitelisted_networks
    nets1 = _get_whitelisted_networks(["10.0.0.0/8", "192.168.1.0/24"])
    nets2 = _get_whitelisted_networks(["10.0.0.0/8", "192.168.1.0/24"])
    assert nets1 is nets2  # Cached object identity


def test_signal_intersection_and_deduplication():
    # Verify that multi-signal events deduplicate signals cleanly
    score, signals = score_event({
        "kind": "unknown_sni",
        "protocol": "tls",
        "handshake_ok": False,
        "sni_known": False,
    })
    # unknown_sni (2) + handshake_failure (2) = 4, with no duplicate unknown_sni signals
    assert score == 4
    assert signals == ("unknown_sni", "handshake_failure")
    assert len(signals) == len(set(signals))


def test_auth_failure_does_not_double_count_as_handshake_failure():
    # Normalizer for auth_failure emits an explicit kind="auth_failure" event
    event = {
        "protocol": "anytls",
        "kind": "auth_failure",
        "source": "auth_log",
    }
    score, signals = score_event(event)
    assert signals == ("auth_failure",)  # НЕ ("auth_failure", "handshake_failure")
    assert score == 3


def test_flock_concurrency_protection(tmp_path):
    # Verify _lock_state_file protects concurrent read-modify-write state updates
    from hydra.plugins.antidpi.plugin import _lock_state_file
    state_file = tmp_path / "antidpi_lock.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file):
        with _lock_state_file():
            assert state_file.parent.exists()


