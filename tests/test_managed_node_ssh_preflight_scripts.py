import json
import os
import shlex
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest

from hydra.core.host import HostBackend
from hydra.contracts.managed_node_models import Operation
from hydra.services.managed_nodes import ssh
from tests.test_managed_node_enrollment import _FINGERPRINT, request
from tests.test_managed_node_removal import installed_node


@pytest.mark.parametrize("use_sudo", [True, False])
@pytest.mark.parametrize("action,expected", [
    ("uninstall", ["uninstall", "--yes"]),
    ("provision", ["--provision"]),
    ("read-certificate", ["--read-public-certificate"]),
    ("remove-firewall", ["--remove-firewall"]),
])
def test_remote_module_actions_work_outside_install_directory_with_legacy_wrapper(
    tmp_path, action, expected, use_sudo,
):
    from hydra.core import state as state_backend
    from hydra.services.managed_nodes.records import ManagedNodeRecords

    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    plan = replace(installed_node(records), use_sudo=use_sudo)
    source = tmp_path / "installed"
    package = source / "hydra"
    entrypoints = package / "entrypoints"
    entrypoints.mkdir(parents=True)
    (package / "__init__.py").touch()
    (entrypoints / "__init__.py").touch()
    stub = "import json, sys; print(json.dumps(sys.argv[1:]))\n"
    (package / "cli.py").write_text(stub)
    (entrypoints / "managed_node.py").write_text(stub)
    legacy = source / "main.py"
    legacy.write_text(
        "import sys\n"
        "sys.exit('ERROR: на ноде доступна только локальная диагностика; управление — на основе')\n"
    )
    login = tmp_path / "login"
    login.mkdir()
    refused = subprocess.run([sys.executable, str(legacy), "uninstall", "--yes"], capture_output=True, text=True)
    assert refused.returncode != 0 and "локальная диагностика" in refused.stderr

    # Emulate sudo without requiring privileges or touching the actual host.
    sudo = login / "sudo"
    sudo.write_text('#!/bin/sh\n[ "$1" = "-n" ] || exit 1\nshift\nexec "$@"\n')
    sudo.chmod(0o700)
    environment = dict(os.environ, PATH=str(login) + os.pathsep + os.environ.get("PATH", ""))
    environment.pop("PYTHONPATH", None)
    command = ssh.OpenSshManagedNodeSSH.remote_command_for(plan, action)
    command = command.replace("/opt/hydra/.venv/bin/python", shlex.quote(sys.executable))
    command = command.replace("/opt/hydra", shlex.quote(str(source)))
    result = subprocess.run(["sh", "-c", command], cwd=login, env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == expected


@pytest.mark.parametrize(
    "name", ["_REMOTE_OS", "_REMOTE_FACTS", "_REMOTE_BOOTSTRAP_STATUS", "_REMOTE_UNINSTALL_VERIFY"]
)
def test_remote_probe_python_survives_shell_quoting_and_compiles(name):
    script = getattr(ssh, name)
    args = shlex.split("python3 -c " + shlex.quote(script))
    assert args == ["python3", "-c", script]
    compile(args[2], "<remote-probe>", "exec")


@pytest.mark.parametrize("os_id,version", [("ubuntu", "24.04"), ("debian", "12")])
def test_os_probe_reads_json_without_nested_exec_or_host_access(capsys, os_id, version):
    data = f'NAME="Example Linux"\nID={os_id}\nVERSION_ID="{version}"\nPRETTY_NAME="Linux=Example"\n'
    with patch.object(Path, "read_text", return_value=data) as read:
        exec(compile(ssh._REMOTE_OS, "<remote-probe>", "exec"), {})
    read.assert_called_once()
    assert json.loads(capsys.readouterr().out) == {"id": os_id, "version": version}


def test_real_inspect_consumes_binary_ssh_outputs_without_installation(monkeypatch, tmp_path):
    commands = []

    def run(args, *, timeout, input, env, text):
        assert args[0] == "ssh" and "-oStrictHostKeyChecking=yes" in args
        assert text is False and input is None and env is None and timeout in {10, 15}
        command = args[-1]
        commands.append(command)
        if command.startswith("python3 -c "):
            args = shlex.split(command)
            compile(args[2], "<remote-probe>", "exec")
            output = (
                b'{"id":"ubuntu","version":"24.04"}'
                if args[2] == ssh._REMOTE_OS
                else b'{"source":"198.51.100.8","existing":false}'
            )
        elif command == "id -u":
            output = b"0\n"
        elif command == "ss -H -lntu":
            output = b"udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:*\n"
        else:
            raise AssertionError("unexpected command; preflight must not install or mutate")
        return CompletedProcess(command, 0, output, b"")

    owner = ssh.OpenSshManagedNodeSSH(
        host=cast(HostBackend, SimpleNamespace(run=run)), known_hosts_root=tmp_path / "known-hosts"
    )
    monkeypatch.setattr(owner, "_pin_host_key", lambda *_args: _FINGERPRINT)
    facts = owner.inspect(request(control_port=25555), None)

    assert (facts.os_id, facts.os_version, facts.uid) == ("ubuntu", "24.04", 0)
    assert facts.source_address == "198.51.100.8"
    assert facts.used_ports == frozenset({443}) and not facts.existing_installation
    assert len(commands) == 4
    assert not (tmp_path / "known-hosts").exists()


def test_port_output_rejects_invalid_encoding_instead_of_ignoring_bytes():
    with pytest.raises(UnicodeDecodeError):
        ssh._parse_listening_ports(b"\xff")


def test_remove_already_clean_vps_only_verifies_over_pinned_ssh(tmp_path):
    from hydra.core import state as state_backend
    from hydra.services.managed_nodes.records import ManagedNodeRecords

    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    plan = installed_node(records, complete=False)
    commands = []

    def run(args, **_kwargs):
        assert "-oStrictHostKeyChecking=yes" in args
        commands.append(args[-1])
        assert shlex.split(args[-1])[:4] == ["sudo", "-n", "python3", "-c"]
        return CompletedProcess(args, 0, b'{"clean":true}', b"")

    owner = ssh.OpenSshManagedNodeSSH(host=SimpleNamespace(run=run), known_hosts_root=tmp_path / "known-hosts")
    owner.remove_node(plan, None)
    assert len(commands) == 1


@pytest.mark.parametrize("remaining", ["/opt/hydra", "/etc/hydra", "/etc/systemd/system/sing-box.service"])
def test_cleanup_probe_detects_partial_installation_remnants(capsys, remaining):
    with patch.object(Path, "exists", lambda path: str(path) == remaining), patch.object(Path, "is_symlink", return_value=False):
        exec(compile(ssh._REMOTE_UNINSTALL_VERIFY, "<remote-probe>", "exec"), {})
    assert json.loads(capsys.readouterr().out) == {"clean": False}


@pytest.mark.parametrize("status", [b'{}', b'{"clean":0}', b'{"clean":"true"}'])
def test_invalid_cleanup_status_cannot_confirm_removal(tmp_path, status):
    from hydra.core import state as state_backend
    from hydra.services.managed_nodes.records import ManagedNodeRecords

    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    plan = installed_node(records, complete=False)
    owner = ssh.OpenSshManagedNodeSSH(
        host=SimpleNamespace(run=lambda *args, **kwargs: CompletedProcess(args, 0, status, b"")),
        known_hosts_root=tmp_path / "known-hosts",
    )
    with pytest.raises(ssh.SshOperationError, match="invalid remote cleanup status"):
        owner.remove_node(plan, None)


def test_reconcile_remove_does_not_confirm_partial_cleanup(tmp_path):
    from hydra.core import state as state_backend
    from hydra.services.managed_nodes.records import ManagedNodeRecords

    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    plan = installed_node(records)
    owner = ssh.OpenSshManagedNodeSSH(
        host=SimpleNamespace(run=lambda *args, **kwargs: CompletedProcess(args, 0, b'{"clean":false}', b"")),
        known_hosts_root=tmp_path / "known-hosts",
    )
    operation = Operation("remove-1", "remove", plan.definition.id, "a" * 64,
                          "recovery_required", active_step="remote_uninstall")
    assert owner.reconcile_remove(plan, operation, None) == "retry"


@pytest.mark.parametrize("clean_after", [True, False])
def test_remove_runs_standard_uninstall_and_requires_clean_result(tmp_path, clean_after):
    from hydra.core import state as state_backend
    from hydra.services.managed_nodes.records import ManagedNodeRecords

    records = ManagedNodeRecords(state_reader=state_backend.load_state, state_updater=state_backend.update_state)
    plan = installed_node(records, complete=False)
    commands = []
    probes = 0

    def run(args, **kwargs):
        nonlocal probes
        command = args[-1]
        commands.append(command)
        if "python3 -c" in command:
            probes += 1
            clean = probes > 1 and clean_after
            return CompletedProcess(args, 0, json.dumps({"clean": clean}).encode(), b"")
        if command.startswith("test -f "):
            return CompletedProcess(args, 1, b"", b"")
        assert command == "cd /opt/hydra && sudo -n /opt/hydra/.venv/bin/python -m hydra.cli uninstall --yes"
        return CompletedProcess(args, 0, b"", b"")

    owner = ssh.OpenSshManagedNodeSSH(host=SimpleNamespace(run=run), known_hosts_root=tmp_path / "known-hosts")
    if clean_after:
        owner.remove_node(plan, None)
    else:
        with pytest.raises(ssh.SshOperationError, match="remnants remain"):
            owner.remove_node(plan, None)
    assert probes == 2
    assert commands.count("cd /opt/hydra && sudo -n /opt/hydra/.venv/bin/python -m hydra.cli uninstall --yes") == 1
