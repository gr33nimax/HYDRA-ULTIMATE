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
