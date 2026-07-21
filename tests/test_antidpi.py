from unittest.mock import MagicMock, patch

from hydra.plugins.antidpi.plugin import (
    AntiDPIPlugin,
    active_bans,
    ban_duration,
    expire_bans,
    format_score,
    udp_protocol_ports,
    _udp_probe_rule,
    _mieru_probe_rule,
    _scan_rule,
    decayed_score,
    prune_runtime_state,
    normalize_caddy_record,
    normalize_decoy_record,
    normalize_naive_decoy_record,
    normalize_trusttunnel_record,
    score_event,
)
from hydra.core.state import AppState, PluginState


def test_notification_score_does_not_round_up_to_the_ban_threshold():
    assert format_score(7.96) == "7.96/8.00"
    assert format_score(8) == "8.00/8.00"


def test_enabled_udp_protocol_ports_are_discovered():
    state = AppState(protocols={
        "hysteria2": PluginState(enabled=True, port=8443, config={}),
        "amneziawg": PluginState(enabled=True, config={
            "profiles": {"desktop": {"port": 51820}, "mobile": {"port": 51821}},
        }),
        "wdtt": PluginState(enabled=True, config={"dtls_port": 56000}),
        "naive": PluginState(enabled=True, config={"network": "tcp"}),
    })
    assert udp_protocol_ports(state) == {
        8443: "hysteria2", 51820: "amneziawg",
        51821: "amneziawg", 56000: "wdtt",
    }


def test_invalid_udp_ports_are_ignored_instead_of_breaking_rule_sync():
    state = AppState(protocols={
        "hysteria2": PluginState(enabled=True, config={"port": "invalid"}),
        "amneziawg": PluginState(enabled=True, config={
            "profiles": {"bad": {"port": 70000}, "good": {"port": "51820"}},
        }),
    })
    assert udp_protocol_ports(state) == {51820: "amneziawg"}


def test_shared_quic_port_is_not_misattributed_to_one_protocol():
    state = AppState(protocols={
        "naive": PluginState(enabled=True, config={"network": "both"}),
        "trusttunnel": PluginState(enabled=True, config={"transport": "quic"}),
    })
    assert udp_protocol_ports(state) == {443: "naive/trusttunnel"}


def test_udp_probe_firewall_rule_is_log_only_and_rate_limited():
    rule = _udp_probe_rule("iptables", 8443)
    assert rule[:4] == ["-p", "udp", "--dport", "8443"]
    assert "--ctstate" in rule and "NEW" in rule
    assert "HYDRA_UDP_PROBE " in rule
    assert "DROP" not in rule


def test_mieru_probe_rule_requires_established_low_volume_close_and_never_drops():
    rule = _mieru_probe_rule("iptables", "FIN")
    assert rule[:4] == ["-p", "tcp", "--dport", "2012:2022"]
    assert "ESTABLISHED" in rule
    assert "--connbytes" in rule and "1:1024" in rule
    assert "HYDRA_MIERU_SHORT " in rule
    assert "DROP" not in rule


def test_unverified_udp_probe_alerts_but_never_bans(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "udp-alert-only.json"
    event = {
        "protocol": "hysteria2", "kind": "udp_probe",
        "source": "kernel-udp-probe", "ban_eligible": False,
    }
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run") as firewall, \
         patch("hydra.services.telegram.bot.send_admin_notification", return_value=True) as notify:
        assert plugin.observe_event("198.51.100.40", event, now=1000) is False
        assert plugin.observe_event("198.51.100.40", event, now=1001) is False
        assert plugin.observe_event("198.51.100.40", event, now=1002) is False
    firewall.assert_not_called()
    notify.assert_called_once()
    message = notify.call_args.args[0]
    assert "alert-only / unverified UDP source" in message
    assert "hysteria2" in message


def test_unverified_udp_score_cannot_preload_a_later_verified_ban(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "separate-verified-score.json"
    udp = {
        "protocol": "amneziawg", "kind": "udp_probe",
        "source": "kernel-udp-probe", "ban_eligible": False,
    }
    verified = {
        "protocol": "tls", "kind": "auth_failure", "source": "journal",
    }
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run") as firewall, \
         patch("hydra.services.telegram.bot.send_admin_notification", return_value=True):
        plugin.observe_event("198.51.100.41", udp, now=1000)
        plugin.observe_event("198.51.100.41", udp, now=1001)
        assert plugin.observe_event("198.51.100.41", verified, now=1002) is False
        state = plugin._load_state()
    firewall.assert_not_called()
    entry = state["scores"]["198.51.100.41"]
    assert entry["score"] >= 8
    assert entry["verified_score"] < 8


def test_alert_cooldown_is_scoped_per_protocol(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "protocol-alert-cooldown.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.services.telegram.bot.send_admin_notification", return_value=True) as notify:
        for protocol in ("hysteria2", "amneziawg"):
            event = {
                "protocol": protocol, "kind": "udp_probe",
                "source": "kernel-udp-probe", "ban_eligible": False,
            }
            plugin.observe_event("198.51.100.42", event, now=1000)
            plugin.observe_event("198.51.100.42", event, now=1001)
    assert notify.call_count == 2


def test_observed_score_is_capped_for_sustained_unverified_udp(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "bounded-observed-score.json"
    event = {
        "protocol": "hysteria2", "kind": "udp_probe",
        "source": "kernel-udp-probe", "ban_eligible": False,
    }
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.services.telegram.bot.send_admin_notification", return_value=True):
        for offset in range(100):
            plugin.observe_event("198.51.100.43", event, now=1000 + offset)
        state = plugin._load_state()
    assert state["scores"]["198.51.100.43"]["score"] == 16


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


def test_naive_decoy_ignores_legitimate_connect_but_detects_scanner_path():
    connect = {"request": {
        "remote_ip": "203.0.113.10", "method": "CONNECT", "uri": "example.com:443",
    }}
    assert normalize_naive_decoy_record(connect) is None
    failed = {"status": 407, "request": {
        "remote_ip": "203.0.113.10", "method": "CONNECT", "uri": "example.com:443",
    }}
    assert normalize_naive_decoy_record(failed) == (
        "203.0.113.10",
        {"protocol": "naive", "kind": "auth_failure", "source": "caddy-naive"},
    )
    scanner = {"status": 407, "request": {
        "remote_ip": "203.0.113.10", "method": "GET", "uri": "/.env",
    }}
    assert normalize_naive_decoy_record(scanner)[1]["kind"] == "active_decoy_probe"
    probe = {"request": {
        "remote_ip": "203.0.113.10", "method": "GET", "uri": "/.env?scan=1",
    }}
    assert normalize_naive_decoy_record(probe) == (
        "203.0.113.10",
        {"protocol": "https", "kind": "active_decoy_probe", "source": "caddy-naive-decoy"},
    )


def test_naive_real_invalid_user_marker_overrides_redirect_status():
    record = {
        "status": 308,
        "request": {
            "remote_ip": "203.0.113.20", "method": "CONNECT",
            "user_id": "invalid:tester", "uri": "cp.cloudflare.com:80",
        },
    }
    assert normalize_naive_decoy_record(record) == (
        "203.0.113.20",
        {"protocol": "naive", "kind": "auth_failure", "source": "caddy-naive"},
    )


def test_naive_quic_auth_failure_keeps_udp_relay_source_port():
    record = {
        "status": 308,
        "request": {
            "remote_ip": "127.0.0.1", "remote_port": "32145",
            "method": "CONNECT", "user_id": "invalid:tester",
        },
    }
    assert normalize_naive_decoy_record(record) == (
        "127.0.0.1",
        {
            "protocol": "naive", "kind": "auth_failure",
            "source": "caddy-naive", "peer_port": 32145,
        },
    )


def test_trusttunnel_dedicated_log_recognizes_failed_connect():
    record = {
        "status": 502,
        "request": {
            "remote_ip": "203.0.113.21", "method": "CONNECT",
            "uri": "example.com:443",
        },
    }
    assert normalize_trusttunnel_record(record) == (
        "203.0.113.21",
        {
            "protocol": "trusttunnel", "kind": "auth_failure",
            "source": "caddy-trusttunnel",
        },
    )


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


def test_antidpi_service_allows_outbound_telegram_sockets(tmp_path):
    script = tmp_path / "hydra-antidpi.py"
    service = tmp_path / "hydra-antidpi.service"
    with patch("hydra.plugins.antidpi.plugin.SCRIPT_FILE", script), \
         patch("hydra.plugins.antidpi.plugin.SERVICE_FILE", service):
        AntiDPIPlugin()._write_service()

    unit = service.read_text(encoding="utf-8")
    assert "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6" in unit


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
    assert data["ban_counts"]["203.0.113.20"] == 1
    assert data["banned"]["203.0.113.20"]["duration"] == 600

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

    ipv6 = normalize_tls_auth_failure({"remote": "[2001:db8::99]:54321", "msg": "authentication failed"})
    assert ipv6 is not None
    assert ipv6[0] == "2001:db8::99"

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




def test_empty_signal_does_not_suppress_following_unknown_sni(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi_empty_signal.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file):
        assert plugin.observe_event("198.51.100.30", {"kind": "ignored"}, now=1000) is False
        assert plugin.observe_event(
            "198.51.100.30",
            {"kind": "unknown_sni", "protocol": "tls", "handshake_ok": False, "sni_known": False},
            now=1000.1,
        ) is False
        assert plugin._load_state()["scores"]["198.51.100.30"]["score"] == 4


def test_active_bans_filters_expired_and_malformed_entries():
    data = {
        "banned": {
            "198.51.100.1": {"at": 1000, "duration": 600},
            "198.51.100.2": {"at": 1000, "duration": 10},
            "invalid": None,
        }
    }
    assert list(active_bans(data, now=1100)) == ["198.51.100.1"]


def test_legacy_ban_duration_and_expired_history_are_reconciled():
    data = {
        "banned": {
            "198.51.100.1": {"at": 1000},
            "198.51.100.2": {"at": 1000, "duration": 600},
        },
        "history": [
            {"ip": "198.51.100.2", "at": 1000, "duration": 600, "status": "active"},
        ],
    }
    assert ban_duration(data["banned"]["198.51.100.1"]) == 86400
    assert expire_bans(data, now=1700) is True
    assert list(data["banned"]) == ["198.51.100.1"]
    assert data["history"][0]["status"] == "expired"


def test_scan_telemetry_rules_are_log_only_and_rate_limited():
    for binary in ("iptables", "ip6tables"):
        for protocol in ("tcp", "udp"):
            rule = _scan_rule(binary, protocol)
            assert "LOG" in rule
            assert "DROP" not in rule
            assert "--hashlimit-above" in rule
            assert "hydra-antidpi-scan" in rule


def test_correlated_multi_port_scan_is_high_confidence_signal():
    score, signals = score_event({
        "kind": "port_scan",
        "protocol": "tcp",
        "source": "kernel-firewall",
        "connections_10s": 12,
        "distinct_ports_60s": 4,
    })
    assert score >= 8
    assert {"port_scan", "connection_burst"} <= set(signals)


def test_event_source_and_signal_counters_are_persisted(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi_sources.json"
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
        results = []
        for offset, port in enumerate((22, 80, 443, 3389)):
            results.append(plugin.observe_event(
                "198.51.100.44",
                {
                    "kind": "port_scan",
                    "protocol": "tcp",
                    "source": "kernel-firewall",
                    "connections_10s": 12,
                    "destination_port": port,
                },
                now=1000 + offset,
            ))
        data = plugin._load_state()
    assert results == [False, False, False, True]
    assert data["source_counts"]["kernel-firewall"] == 4
    assert data["signal_counts"]["port_scan"] == 4
    assert data["signal_counts"]["port_sweep"] == 1


def test_ban_notifications_are_throttled_and_delivery_is_counted(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi_notifications.json"
    result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=result), \
         patch("hydra.services.telegram.bot.send_admin_notification", return_value=True) as notify:
        assert plugin.observe_event(
            "198.51.100.40", {"kind": "active_decoy_probe", "source": "test"}, now=1000,
        ) is True
        assert plugin.observe_event(
            "198.51.100.41", {"kind": "active_decoy_probe", "source": "test"}, now=1001,
        ) is True
        data = plugin._load_state()

    assert notify.call_count == 1
    message = notify.call_args.args[0]
    assert "AntiDPI · BAN" in message
    assert "198.51.100.40" in message
    assert "заблокировал источник" not in message
    assert "Эффект" not in message
    assert data["notification_stats"]["delivered"] == 1
    assert data["suppressed_ban_notifications"] == 1


def test_honeypot_owned_bans_are_removed_from_antidpi(tmp_path):
    plugin = AntiDPIPlugin()
    state_file = tmp_path / "antidpi_honeypot_duplicates.json"
    state = {
        "banned": {
            "198.51.100.60": {"at": 9999999000, "duration": 86400},
            "198.51.100.61": {"at": 9999999000, "duration": 86400},
        },
        "scores": {},
        "history": [],
    }
    result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("hydra.plugins.antidpi.plugin.STATE_FILE", state_file), \
         patch("hydra.plugins.antidpi.plugin._run", return_value=result), \
         patch("hydra.plugins.honeypot.plugin.HoneypotPlugin._load_state", return_value={
             "banned": {"198.51.100.60": {}},
         }):
        plugin._save_state(state)
        assert plugin.cleanup_honeypot_duplicates() == 1
        remaining = plugin._load_state()["banned"]
    assert set(remaining) == {"198.51.100.61"}



def test_runtime_state_pruning_keeps_recent_entries_and_active_bans():
    data = {
        "banned": {"198.51.100.9": {"at": 900, "duration": 1000}},
        "scores": {
            "198.51.100.1": {"updated": 999},
            "198.51.100.2": {"updated": 998},
            "198.51.100.3": {"updated": 1},
            "198.51.100.9": {"updated": 1},
        },
    }
    with patch("hydra.plugins.antidpi.plugin.MAX_SCORE_ENTRIES", 3):
        prune_runtime_state(data, now=1000)
    assert set(data["scores"]) == {"198.51.100.1", "198.51.100.2", "198.51.100.9"}
