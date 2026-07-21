from __future__ import annotations

import json
import tarfile
from pathlib import Path
from unittest.mock import patch

from hydra.core.state import AppState, PluginState, TelegramConfig, User
from hydra.plugins.antidpi import selftest


def test_external_capture_writes_redacted_bundle_without_probes(tmp_path):
    archive = tmp_path / "capture.tar.gz"
    state = AppState()
    with patch("hydra.plugins.antidpi.selftest._is_linux_host", return_value=True), \
         patch("hydra.plugins.antidpi.selftest._offsets", return_value={}), \
         patch("hydra.plugins.antidpi.selftest._all_journal", return_value=[]), \
         patch("hydra.plugins.antidpi.selftest._all_new_log_lines", return_value={}), \
         patch("hydra.plugins.antidpi.selftest._environment", return_value={}), \
         patch("hydra.plugins.antidpi.selftest.time.sleep"), \
         patch("hydra.plugins.antidpi.selftest.time.time", side_effect=[100.0, 101.0, 102.0]), \
         patch("hydra.plugins.antidpi.plugin.AntiDPIPlugin._load_state", return_value={"events": 2}):
        result = selftest.capture_external_tests(state, str(archive), 10)
    assert result["ok"] is True
    with tarfile.open(archive) as bundle:
        report = json.loads(bundle.extractfile("hydra-antidpi-capture/report.json").read())
    assert report["mode"] == "external_capture"
    assert report["antidpi_runtime"]["events"] == 2


def test_targets_cover_enabled_protocol_shapes():
    state = AppState(
        protocols={
            "anytls": PluginState(enabled=True, config={"domain": "a.example"}),
            "hysteria2": PluginState(enabled=True, config={"port": 4443}),
            "wdtt": PluginState(enabled=True, config={"dtls_port": 56009}),
            "snell": PluginState(enabled=True),
            "amneziawg": PluginState(enabled=True, config={"profiles": {"desktop": {"port": 51830}}}),
        },
        users=[User(email="u", uuid="id", credentials={"snell": {"port": 32123}})],
    )
    with patch("hydra.plugins.antidpi.selftest.get_effective_port", return_value=20444):
        assert {target.transport for target in selftest._targets(state, "anytls")} == {"tcp", "tls"}
    assert selftest._targets(state, "hysteria2") == [selftest.Target("udp", 4443)]
    assert selftest._targets(state, "wdtt") == [selftest.Target("udp", 56009)]
    assert selftest._targets(state, "snell") == [selftest.Target("tcp", 32123)]
    assert selftest._targets(state, "amneziawg") == [selftest.Target("udp", 51830)]


def test_naive_targets_use_global_domain_and_transport_mode():
    state = AppState(
        protocols={"naive": PluginState(enabled=True, config={"network": "both"})},
    )
    state.network.domain = "naive.example"
    with patch("hydra.plugins.antidpi.selftest.get_effective_port", return_value=10443):
        targets = selftest._targets(state, "naive")
    assert selftest.Target("tcp", 10443) in targets
    assert selftest.Target("udp", 10443) in targets
    assert selftest.Target("tls", 443, sni="naive.example") in targets


def test_journal_relevance_rejects_background_traffic():
    assert selftest._relevant_journal_record("anytls", {
        "_SYSTEMD_UNIT": "sing-box.service",
        "MESSAGE": "inbound/anytls: unknown user password from 127.0.0.1:1234",
    }) is True
    assert selftest._relevant_journal_record("anytls", {
        "_SYSTEMD_UNIT": "sing-box.service",
        "MESSAGE": "inbound/tproxy: connection from 127.0.0.1:1234",
    }) is False
    assert selftest._relevant_journal_record("amneziawg", {
        "_SYSTEMD_UNIT": "kernel",
        "MESSAGE": "HYDRA-PORTSCAN SRC=127.0.0.1 DST=127.0.0.1",
    }) is False


def test_redactor_removes_state_secrets():
    state = AppState(
        telegram=TelegramConfig(admin_token="123456:SECRET-TOKEN"),
        users=[User(email="u", uuid="secret-uuid", credentials={"naive": {"password": "secret-password"}})],
    )
    redact = selftest._redactor(state)
    result = redact("token=123456:SECRET-TOKEN password=secret-password uuid secret-uuid")
    assert "SECRET-TOKEN" not in result
    assert "secret-password" not in result
    assert "secret-uuid" not in result


def test_run_selftest_writes_redacted_archive(tmp_path):
    state = AppState(
        protocols={"telemt": PluginState(enabled=True, port=8443, config={"secret": "native-secret"})},
    )
    archive = tmp_path / "result.tar.gz"
    record = {"_SYSTEMD_UNIT": "telemt.service", "MESSAGE": "invalid handshake from 192.0.2.10 native-secret"}
    with patch.object(selftest, "_is_linux_host", return_value=True), \
         patch.object(selftest, "_environment", return_value={"hydra_version": "test"}), \
         patch.object(selftest, "_probe", return_value=[{"error": ""}]), \
         patch.object(selftest, "_journal", return_value=[record]), \
         patch.object(selftest, "_offsets", return_value={}), \
         patch.object(selftest, "_new_log_lines", return_value={}), \
         patch.object(selftest.time, "sleep"):
        result = selftest.run_selftest(state, str(archive), wait_seconds=0)
    assert result["ok"] is True
    with tarfile.open(archive, "r:gz") as bundle:
        report = json.loads(bundle.extractfile("hydra-antidpi-selftest/report.json").read())
        journal = bundle.extractfile("hydra-antidpi-selftest/journal/telemt.jsonl").read().decode()
    assert report["protocols"]["telemt"]["status"] in {"filter_match", "native_log_unmatched"}
    assert report["protocols"]["telemt"]["coverage"]["native_log_observed"] is True
    assert "native-secret" not in journal
    assert "[REDACTED]" in journal


def test_invalid_native_client_config_changes_only_ephemeral_copy():
    state = AppState(
        protocols={"hysteria2": PluginState(enabled=True, config={"domain": "hy.example", "port": 443})},
        users=[User(email="u", uuid="user-id")],
    )
    generated = {
        "log": {"level": "info"},
        "dns": {"servers": [{"address": "8.8.8.8"}]},
        "outbounds": [{
            "type": "hysteria2", "tag": "hy", "server": "203.0.113.1",
            "server_port": 443, "password": "real-password",
            "obfs": {"type": "salamander", "password": "real-obfs"},
            "tls": {"enabled": True, "server_name": "hy.example"},
        }],
        "route": {"final": "hy"},
    }
    plugin = type("Plugin", (), {"generate_client_config": lambda self, user, app: json.dumps(generated)})()
    with patch("hydra.plugins.registry.get", return_value=plugin):
        config, status = selftest._invalid_client_config(state, "hysteria2", 12345)
    assert status == "ready"
    assert config["outbounds"][0]["server"] == "127.0.0.1"
    assert config["outbounds"][0]["password"] == "HYDRA-INVALID-PASSWORD"
    assert config["outbounds"][0]["obfs"]["password"] == "real-obfs"
    assert config["inbounds"][0]["listen_port"] == 12345
    assert config["dns"] == generated["dns"]
    assert generated["outbounds"][0]["password"] == "real-password"


def test_awg_handshake_payload_uses_profile_header_and_padding():
    state = AppState(protocols={
        "amneziawg": PluginState(enabled=True, config={"profiles": {
            "desktop": {
                "port": 51830,
                "obfuscation": {"H1": "287454020", "S1": "40"},
            },
        }}),
    })
    payload = selftest._awg_handshake_payload(state, selftest.Target("udp", 51830))
    assert payload[:4] == b"\x44\x33\x22\x11"
    assert len(payload) == 188


def test_native_client_environment_enables_legacy_dns_without_mutating_host(monkeypatch):
    monkeypatch.delenv("ENABLE_DEPRECATED_LEGACY_DNS_SERVERS", raising=False)
    environment = selftest._client_environment()
    assert environment["ENABLE_DEPRECATED_LEGACY_DNS_SERVERS"] == "true"
    assert environment["ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER"] == "true"
    assert "ENABLE_DEPRECATED_LEGACY_DNS_SERVERS" not in selftest.os.environ
    assert "ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER" not in selftest.os.environ


def test_native_naive_probe_uses_curl_against_loopback_sni():
    state = AppState()
    state.network.domain = "naive.example"
    completed = type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    with patch.object(selftest.HOST, "which", return_value="/usr/bin/curl"), \
         patch.object(selftest.HOST, "run", return_value=completed) as run:
        result = selftest._native_naive_probe(state)
    assert result["triggered"] is True
    command = run.call_args.args[0]
    assert "naive.example:443:127.0.0.1" in command
    assert "http://selftest.invalid/__hydra_antidpi_selftest__" in command


def test_naive_log_filter_summary_recognizes_proxy_auth_failure():
    line = json.dumps({
        "status": 407,
        "request": {"remote_ip": "127.0.0.1", "method": "GET", "uri": "/test"},
    })
    matches = selftest._log_filter_matches("naive", {"/tmp/access.log": [line]})
    assert matches[0]["event"]["kind"] == "auth_failure"


def test_full_mode_records_native_client_coverage(tmp_path):
    state = AppState(
        protocols={"snell": PluginState(enabled=True)},
        users=[User(email="u", uuid="id", credentials={"snell": {"port": 32123}})],
    )
    archive = tmp_path / "full.tar.gz"
    with patch.object(selftest, "_is_linux_host", return_value=True), \
         patch.object(selftest, "_environment", return_value={}), \
         patch.object(selftest, "_probe", return_value=[{"error": ""}]), \
         patch.object(selftest, "_native_client_probe", return_value={
             "status": "executed", "started": True, "triggered": True,
         }), \
         patch.object(selftest, "_journal", return_value=[]), \
         patch.object(selftest, "_offsets", return_value={}), \
         patch.object(selftest, "_new_log_lines", return_value={}), \
         patch.object(selftest.time, "sleep"):
        result = selftest.run_selftest(state, str(archive), wait_seconds=0, full=True)
    item = result["report"]["protocols"]["snell"]
    assert result["report"]["mode"] == "full"
    assert item["coverage"]["native_client_probe_sent"] is True
