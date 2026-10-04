import json
import shlex
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest

from hydra.core.host import HostBackend
from hydra.services.managed_nodes import ssh
from tests.test_managed_node_enrollment import _FINGERPRINT, request


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
