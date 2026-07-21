from __future__ import annotations

import json
import tarfile
from pathlib import Path
from unittest.mock import patch

from hydra.core.state import AppState, PluginState, TelegramConfig, User
from hydra.plugins.antidpi import selftest


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
    assert report["protocols"]["telemt"]["status"] == "captured"
    assert "native-secret" not in journal
    assert "[REDACTED]" in journal
