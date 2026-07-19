from pathlib import Path
from unittest.mock import MagicMock, patch

from hydra.core.host import HostBackend, HostPaths


def test_host_backend_atomic_write_and_systemd_command(tmp_path):
    host = HostBackend(HostPaths(systemd_dir=tmp_path / "systemd", iptables_rules=tmp_path / "rules.v4"))
    host.atomic_write(tmp_path / "config" / "demo.conf", "hello")
    assert (tmp_path / "config" / "demo.conf").read_text(encoding="utf-8") == "hello"
    with patch.object(host, "run", return_value=MagicMock(returncode=0)) as run:
        assert host.systemd("restart", "demo.service").returncode == 0
    run.assert_called_once_with(["systemctl", "restart", "demo.service"], timeout=30)


def test_host_backend_firewall_persistence_is_injectable(tmp_path):
    rules = tmp_path / "rules.v4"
    host = HostBackend(HostPaths(iptables_rules=rules))
    with patch.object(host, "which", return_value=None), \
         patch.object(host, "run", return_value=MagicMock(returncode=0, stdout="*filter\n")):
        assert host.persist_firewall() is True
    assert rules.read_text(encoding="utf-8") == "*filter\n"


def test_host_backend_forwards_stdin_and_environment():
    host = HostBackend()
    with patch("hydra.core.host.commands.run", return_value=MagicMock(returncode=0)) as run:
        host.run(["ipset", "restore"], input="create hydra_manual_ban hash:ip", env={"LANG": "C"})

    run.assert_called_once_with(
        ["ipset", "restore"],
        timeout=30,
        check=False,
        text=False,
        input="create hydra_manual_ban hash:ip",
        env={"LANG": "C"},
    )
