from __future__ import annotations

import json
import subprocess
import tarfile
from pathlib import Path
from unittest.mock import patch

from hydra.core.state import AppState, PluginState, TelegramConfig, User
from hydra.plugins.antidpi import selftest


def test_runtime_diagnostics_executes_inside_its_function():
    """Only the firewall and socket state AntiScan owns is collected."""
    completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
    with patch("hydra.plugins.antidpi.selftest.HOST.run",
               return_value=completed) as run:
        result = selftest._runtime_diagnostics()

    assert set(result["commands"]) == {
        "input_rules_v4", "input_rules_v6", "udp_sockets", "tcp_sockets",
    }
    assert run.call_count == 4
    # UDP listener attribution and the AWG debug hook are gone.
    assert "protocol_ports" not in result
    assert "source_relay_mappings" not in result
    assert "amneziawg_dynamic_debug" not in result


def test_external_capture_writes_redacted_bundle_without_probes(tmp_path):
    archive = tmp_path / "capture.tar.gz"
    state = AppState()
    snapshots = iter([
        {"events": 1, "notification_stats": {"delivered": 3}},
        {"events": 2, "notification_stats": {"delivered": 4}},
    ])
    with patch("hydra.plugins.antidpi.selftest._is_linux_host", return_value=True), \
         patch("hydra.plugins.antidpi.selftest._offsets", return_value={}), \
         patch("hydra.plugins.antidpi.selftest._all_journal", return_value=[]), \
         patch("hydra.plugins.antidpi.selftest._all_new_log_lines", return_value={}), \
         patch("hydra.plugins.antidpi.selftest._environment", return_value={}), \
         patch("hydra.plugins.antidpi.selftest._runtime_diagnostics", return_value={"ok": True}), \
         patch("hydra.plugins.antidpi.selftest.time.sleep"), \
         patch("hydra.plugins.antidpi.selftest.time.time", side_effect=[100.0, 101.0, 102.0]):
        result = selftest.capture_external_tests(
            state,
            str(archive),
            10,
            runtime_snapshot=lambda: next(snapshots),
        )
    assert result["ok"] is True
    with tarfile.open(archive) as bundle:
        report = json.loads(bundle.extractfile("hydra-antidpi-capture/report.json").read())
    assert report["mode"] == "external_capture"
    assert report["antidpi_runtime"]["events"] == 2
    assert report["runtime_diagnostics"] == {"ok": True}
    assert report["capture_delta"]["events"] == 1
    assert report["capture_delta"]["notifications"]["delivered"] == 1


def test_capture_summary_counts_only_proven_rejects():
    """Kernel UDP probes and AWG telemetry must not appear in a capture."""
    records = [
        {"SYSLOG_IDENTIFIER": "kernel", "MESSAGE": (
            "HYDRA_UDP_PROBE SRC=198.51.100.5 SPT=12345 DPT=8443"
        )},
        {"SYSLOG_IDENTIFIER": "kernel", "MESSAGE": (
            "amneziawg: awg0: Invalid MAC of handshake, dropping packet "
            "from 198.51.100.6:12346"
        )},
        {"_SYSTEMD_UNIT": "sing-box.service", "MESSAGE": (
            "inbound/snell[snell-1111aaaa2222-in]: process connection from "
            "198.51.100.7:1234: snell: serve 198.51.100.7:1234: read request: "
            "open record header: cipher: message authentication failed"
        )},
    ]
    summary = selftest._capture_event_summary(records)

    assert len(summary) == 1
    assert summary[0]["protocol"] == "snell"
    assert summary[0]["count"] == 1


def test_only_snell_has_a_probe_target():
    state = AppState(
        protocols={
            "anytls": PluginState(enabled=True, config={"domain": "a.example"}),
            "hysteria2": PluginState(enabled=True, config={"port": 4443}),
            "wdtt": PluginState(enabled=True, config={"dtls_port": 56009}),
            "snell": PluginState(enabled=True),
            "amneziawg": PluginState(enabled=True, config={"profiles": {"desktop": {"port": 51830}}}),
            "vless": PluginState(enabled=True, config={"domain": "vless.example"}),
            "naive": PluginState(enabled=True, config={"network": "both"}),
        },
        users=[User(email="u", uuid="id", credentials={"snell": {"port": 32123}})],
    )
    assert selftest._targets(state, "snell") == [selftest.Target("tcp", 32123)]
    for protocol in ("anytls", "hysteria2", "wdtt", "amneziawg", "vless", "naive"):
        assert selftest._targets(state, protocol) == [], protocol
    assert selftest.SUPPORTED_PROTOCOLS == ("snell",)
    assert selftest.JOURNAL_UNITS == {"snell": ("sing-box",)}


def test_journal_relevance_rejects_background_traffic():
    assert selftest._relevant_journal_record("snell", {
        "_SYSTEMD_UNIT": "sing-box.service",
        "MESSAGE": (
            "inbound/snell[snell-1111aaaa2222-in]: process connection from "
            "127.0.0.1:1234: snell: serve 127.0.0.1:1234: read request: "
            "open record header: cipher: message authentication failed"
        ),
    }) is True
    assert selftest._relevant_journal_record("snell", {
        "_SYSTEMD_UNIT": "sing-box.service",
        "MESSAGE": "inbound/tproxy: connection from 127.0.0.1:1234",
    }) is False
    assert selftest._relevant_journal_record("snell", {
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
        protocols={"snell": PluginState(
            enabled=True,
            port=32123,
            config={"secret": "native-secret"},
        )},
    )
    archive = tmp_path / "result.tar.gz"
    record = {"_SYSTEMD_UNIT": "sing-box.service", "MESSAGE": (
        "inbound/snell[snell-1111aaaa2222-in]: process connection from "
        "192.0.2.10:1234: snell: serve 192.0.2.10:1234: read request: "
        "open record header: cipher: message authentication failed "
        "native-secret"
    )}
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
        journal = bundle.extractfile("hydra-antidpi-selftest/journal/snell.jsonl").read().decode()
    # A proven journal reject satisfies the protocol-context filter.
    assert report["protocols"]["snell"]["status"] == "filter_match"
    assert report["protocols"]["snell"]["coverage"]["native_log_observed"] is True
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
    protocols = type(
        "Protocols",
        (),
        {
            "client_config": lambda self, app, name, user: json.dumps(generated),
        },
    )()
    config, status = selftest._invalid_client_config(
        state,
        "hysteria2",
        12345,
        protocols=protocols,
    )
    assert status == "ready"
    assert config["outbounds"][0]["server"] == "127.0.0.1"
    assert config["outbounds"][0]["password"] == "HYDRA-INVALID-PASSWORD"
    assert config["outbounds"][0]["obfs"]["password"] == "real-obfs"
    assert config["inbounds"][0]["listen_port"] == 12345
    assert config["dns"] == generated["dns"]
    assert generated["outbounds"][0]["password"] == "real-password"


def test_vless_native_probe_invalidates_uuid_in_ephemeral_copy():
    state = AppState(
        protocols={"vless": PluginState(enabled=True)},
        users=[User(email="u", uuid="real-uuid")],
    )
    generated = {
        "outbounds": [{
            "type": "vless",
            "server": "vless.example",
            "server_port": 443,
            "uuid": "real-uuid",
            "tls": {"enabled": True, "server_name": "vless.example"},
        }],
    }
    protocols = type(
        "Protocols",
        (),
        {
            "client_config": lambda self, app, name, user: json.dumps(
                generated,
            ),
        },
    )()

    config, status = selftest._invalid_client_config(
        state,
        "vless",
        12345,
        protocols=protocols,
    )

    assert status == "ready"
    assert config["outbounds"][0]["uuid"] == "HYDRA-INVALID-UUID"
    assert generated["outbounds"][0]["uuid"] == "real-uuid"


def test_amneziawg_probe_payload_is_gone():
    """AntiScan no longer observes AmneziaWG, so it has no payload builder."""
    assert not hasattr(selftest, "_awg_handshake_payload")
    assert not hasattr(selftest, "awg_handshake_payload")


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


def test_log_filter_summary_recognizes_only_scanner_paths():
    """Every decoy surface replays through the same scanner-path filter."""
    scanner = json.dumps({
        "status": 404,
        "request": {"remote_ip": "203.0.113.7", "method": "GET", "uri": "/.env"},
    })
    normal = json.dumps({
        "status": 200,
        "request": {"remote_ip": "203.0.113.8", "method": "GET", "uri": "/about"},
    })
    matches = selftest._log_filter_matches(
        "snell",
        {"/tmp/access.log": [scanner, normal]},
    )

    assert len(matches) == 1
    assert matches[0]["ip"] == "203.0.113.7"
    assert matches[0]["event"]["kind"] == "decoy_scan"
    assert matches[0]["event"]["reason"] == "scanner_path"


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
