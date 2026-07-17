from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from hydra.core import source_transparency as source


def test_ruleset_marks_only_owned_backend_source_ports():
    ruleset = source._ruleset({10801, 20444}, {20445}, table_exists=True)

    assert "delete table inet hydra-caddy-source" in ruleset
    assert "th sport { 10801, 20444 }" in ruleset
    assert "th sport { 20445 }" in ruleset
    assert "ip daddr != 127.0.0.0/8" in ruleset
    assert f"meta mark set {source.FWMARK}" in ruleset


def test_apply_writes_persistent_sysctl_and_checks_nft(tmp_path):
    sysctl_file = tmp_path / "sysctl.conf"
    state_file = tmp_path / "state.json"
    checked = []

    def fake_checked(command, **kwargs):
        checked.append((command, kwargs.get("input")))
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch.object(source, "SYSCTL_FILE", sysctl_file), \
         patch.object(source, "STATE_FILE", state_file), \
         patch.object(source, "_current_sysctl", return_value="0"), \
         patch.object(source, "_ensure_policy_rule"), \
         patch.object(source, "_run", return_value=MagicMock(returncode=1)), \
         patch.object(source, "_run_checked", side_effect=fake_checked):
        source.apply({20444}, {20445})

    assert sysctl_file.read_text(encoding="utf-8") == f"{source.SYSCTL_KEY}=1\n"
    assert json.loads(state_file.read_text(encoding="utf-8"))["sysctl"] == "0"
    commands = [item[0] for item in checked]
    assert ["sysctl", "-w", f"{source.SYSCTL_KEY}=1"] in commands
    assert ["nft", "--check", "-f", "-"] in commands
    assert ["nft", "-f", "-"] in commands


def test_clear_restores_baseline(tmp_path):
    sysctl_file = tmp_path / "sysctl.conf"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({
        "sysctl": "0",
        "sysctl_file": "original=1\n",
    }), encoding="utf-8")

    with patch.object(source, "SYSCTL_FILE", sysctl_file), \
         patch.object(source, "STATE_FILE", state_file), \
         patch.object(source, "_run", return_value=MagicMock(returncode=0)) as run:
        source.clear()

    assert sysctl_file.read_text(encoding="utf-8") == "original=1\n"
    assert not state_file.exists()
    run.assert_any_call(["sysctl", "-w", f"{source.SYSCTL_KEY}=0"])


def test_clear_does_not_flush_unowned_policy_table(tmp_path):
    state_file = tmp_path / "missing-state.json"

    def fake_run(command, **kwargs):
        if command[:4] == ["nft", "list", "table", "inet"]:
            return MagicMock(returncode=1, stdout="", stderr="")
        if command[:4] == ["ip", "-4", "rule", "show"]:
            return MagicMock(
                returncode=0,
                stdout=f"100: from all lookup {source.ROUTE_TABLE}\n",
                stderr="",
            )
        raise AssertionError(f"unexpected destructive command: {command}")

    with patch.object(source, "STATE_FILE", state_file), \
         patch.object(source, "_run", side_effect=fake_run):
        source.clear()
