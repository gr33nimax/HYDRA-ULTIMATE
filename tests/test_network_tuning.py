from __future__ import annotations

import json
import subprocess

from hydra.core import network_tuning as tuning


def _completed(command, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_desired_sysctls_scale_buffers_with_available_ram():
    small = tuning.desired_sysctls(512 * 1024**2)
    medium = tuning.desired_sysctls(2 * 1024**3)
    large = tuning.desired_sysctls(8 * 1024**3)

    assert small["net.core.rmem_max"] == str(8 * 1024**2)
    assert medium["net.core.rmem_max"] == str(16 * 1024**2)
    assert large["net.core.rmem_max"] == str(32 * 1024**2)
    assert small["net.netfilter.nf_conntrack_max"] == "65536"
    assert large["net.netfilter.nf_conntrack_max"] == "262144"
    assert large["net.ipv4.tcp_congestion_control"] == "bbr"
    assert large["net.ipv4.ip_local_port_range"] == "10240 65535"


def test_apply_is_idempotent_and_rollback_restores_original_values(tmp_path, monkeypatch):
    sysctl_conf = tmp_path / "99-hydra-network-tuning.conf"
    backup_file = tmp_path / "network-tuning-backup.json"
    legacy_conf = tmp_path / "99-hydra-tuning.conf"
    legacy_conf.write_text("net.core.rmem_max = 7500000\n", encoding="utf-8")

    monkeypatch.setattr(tuning, "SYSCTL_CONF", sysctl_conf)
    monkeypatch.setattr(tuning, "BACKUP_FILE", backup_file)
    monkeypatch.setattr(tuning, "LEGACY_CONF", legacy_conf)

    values = {key: "0" for key in tuning.desired_sysctls(512 * 1024**2)}
    values["net.ipv4.tcp_available_congestion_control"] = "reno cubic bbr"

    def fake_run(command):
        if command[:2] == ["sysctl", "-n"]:
            key = command[2]
            if key in values:
                return _completed(command, stdout=values[key] + "\n")
            return _completed(command, returncode=1, stderr="unknown key")
        if command[:2] == ["sysctl", "-w"]:
            key, value = command[2].split("=", 1)
            values[key] = value
            return _completed(command, stdout=command[2] + "\n")
        return _completed(command)

    monkeypatch.setattr(tuning, "_run", fake_run)

    report = tuning.apply_network_tuning(512 * 1024**2)
    original_backup = backup_file.read_text(encoding="utf-8")

    assert report["success"] is True
    assert report["bbr_available"] is True
    assert all(item["changed"] for item in report["sysctl"].values())
    assert "net.ipv4.tcp_congestion_control = bbr" in sysctl_conf.read_text(encoding="utf-8")
    assert not legacy_conf.exists()
    assert json.loads(original_backup)["legacy_config"]["exists"] is True

    second = tuning.apply_network_tuning(512 * 1024**2)
    assert not any(item["changed"] for item in second["sysctl"].values())
    assert backup_file.read_text(encoding="utf-8") == original_backup

    rollback = tuning.rollback_network_tuning()
    assert rollback["success"] is True
    assert all(values[key] == "0" for key in tuning.desired_sysctls(512 * 1024**2))
    assert not sysctl_conf.exists()
    assert legacy_conf.read_text(encoding="utf-8") == "net.core.rmem_max = 7500000\n"
    assert not backup_file.exists()


def test_apply_skips_bbr_when_kernel_does_not_offer_it(tmp_path, monkeypatch):
    monkeypatch.setattr(tuning, "SYSCTL_CONF", tmp_path / "profile.conf")
    monkeypatch.setattr(tuning, "BACKUP_FILE", tmp_path / "backup.json")
    monkeypatch.setattr(tuning, "LEGACY_CONF", tmp_path / "legacy.conf")

    def fake_get(key):
        if key == "net.ipv4.tcp_available_congestion_control":
            return "reno cubic"
        return "0"

    monkeypatch.setattr(tuning, "_sysctl_get", fake_get)
    monkeypatch.setattr(tuning, "_run", lambda command: _completed(command))

    report = tuning.apply_network_tuning(2 * 1024**3)
    content = tuning.SYSCTL_CONF.read_text(encoding="utf-8")

    assert report["bbr_available"] is False
    assert "tcp_congestion_control" not in report["sysctl"]
    assert "tcp_congestion_control" not in content


def test_rollback_requires_a_backup(tmp_path, monkeypatch):
    monkeypatch.setattr(tuning, "BACKUP_FILE", tmp_path / "missing.json")
    report = tuning.rollback_network_tuning()
    assert report["success"] is False
    assert report["restored"] == 0
