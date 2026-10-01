from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.host import HostBackend
from hydra.services.nodes.bootstrap import NodeBootstrap


class _Host(HostBackend):
    def __init__(self):
        super().__init__()
        self.calls = []

    def run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == "ssh-keyscan":
            return CompletedProcess(args, 0, stdout="[203.0.113.3]:2222 ssh-ed25519 AAAA\n", stderr="")
        if args[0] == "ssh-keygen":
            return CompletedProcess(args, 0, stdout="256 SHA256:abcDEF123= host (ED25519)\n", stderr="")
        return CompletedProcess(args, 0, stdout="installed", stderr="")

    def ensure_directory(self, path, *, mode=0o755):
        self.directory = (path, mode)

    def atomic_write(self, path, content, *, mode=0o644, durable=False):
        self.saved = (path, content, mode)


def test_bootstrap_pins_confirmed_ssh_host_and_installs_exact_revision(tmp_path):
    host = _Host()
    pinned = "#!/usr/bin/env bash\necho pinned\n"
    bootstrap = NodeBootstrap(
        host=host,
        script="#!/usr/bin/env bash\necho base-copy\n",
        known_hosts_root=tmp_path,
    )

    with patch.object(bootstrap, "bootstrap_script", return_value=pinned) as source:
        fingerprint = bootstrap.install(
            node_id="de-1",
            address="203.0.113.3",
            ssh_port=2222,
            branch="dev",
            revision="a" * 40,
            confirm_fingerprint=lambda value: value == "SHA256:abcDEF123=",
        )

    source.assert_called_once_with("a" * 40)

    assert fingerprint == "SHA256:abcDEF123="
    assert host.directory == (tmp_path / "de-1", 0o700)
    assert host.saved == (
        tmp_path / "de-1" / "known_hosts",
        "[203.0.113.3]:2222 ssh-ed25519 AAAA\n",
        0o600,
    )
    command, options = host.calls[-1]
    assert command[0] == "ssh"
    assert "-T" in command
    assert "-tt" not in command
    assert "BatchMode=no" in command
    assert options["capture_output"] is False
    assert "StrictHostKeyChecking=yes" in command
    assert "UserKnownHostsFile=" + str(host.saved[0]) in command
    assert "HYDRA_ROLE=node" in command[-1]
    assert "HYDRA_REF=dev" in command[-1]
    assert "HYDRA_TARGET_REV=" + "a" * 40 in command[-1]
    # The streamed installer is the one at the pinned revision, never the base's own
    # copy: those two diverged once and installed a newer script over an older tree.
    assert options["input"] == pinned
    assert options["input"] != bootstrap.script


def test_bootstrap_stops_before_ssh_when_host_fingerprint_is_not_confirmed(tmp_path):
    host = _Host()
    bootstrap = NodeBootstrap(host=host, script="install", known_hosts_root=tmp_path)

    with pytest.raises(PermissionError, match="fingerprint was not confirmed"):
        bootstrap.install(
            node_id="de-1",
            address="203.0.113.3",
            ssh_port=2222,
            branch="main",
            revision="b" * 40,
            confirm_fingerprint=lambda _: False,
        )

    assert [call[0][0] for call in host.calls] == ["ssh-keyscan", "ssh-keygen"]
    assert not hasattr(host, "saved")


def test_bootstrap_rejects_unsafe_host_branch_and_revision_before_network():
    host = _Host()
    bootstrap = NodeBootstrap(host=host, script="install")
    with pytest.raises(ValueError):
        bootstrap.install(
            node_id="de-1",
            address="-oProxyCommand=bad",
            ssh_port=22,
            branch="main",
            revision="c" * 40,
            confirm_fingerprint=MagicMock(return_value=True),
        )
    with pytest.raises(ValueError):
        bootstrap.install(
            node_id="de-1",
            address="203.0.113.3",
            ssh_port=22,
            branch="main; id",
            revision="c" * 40,
            confirm_fingerprint=MagicMock(return_value=True),
        )
    with pytest.raises(ValueError):
        bootstrap.install(
            node_id="de-1",
            address="203.0.113.3",
            ssh_port=22,
            branch="main",
            revision="not-a-sha",
            confirm_fingerprint=MagicMock(return_value=True),
        )
    assert host.calls == []


def test_bootstrap_does_not_fetch_the_installer_before_the_host_key_is_confirmed(tmp_path):
    """A refused host key must not cause any external work, not even a download."""
    host = _Host()
    fetched: list[str] = []
    bootstrap = NodeBootstrap(host=host, script="#!/bin/sh\necho base\n", known_hosts_root=tmp_path)

    with patch.object(
        bootstrap,
        "bootstrap_script",
        side_effect=lambda revision: fetched.append(revision) or "install",
    ):
        with pytest.raises(PermissionError, match="fingerprint was not confirmed"):
            bootstrap.install(
                node_id="de-1",
                address="203.0.113.3",
                ssh_port=2222,
                branch="main",
                revision="b" * 40,
                confirm_fingerprint=lambda _: False,
            )

    assert fetched == []
    assert [call[0][0] for call in host.calls] == ["ssh-keyscan", "ssh-keygen"]


def test_bootstrap_fetches_the_installer_of_the_pinned_revision(tmp_path):
    host = _Host()
    fetched: list[str] = []
    bootstrap = NodeBootstrap(host=host, script="#!/bin/sh\necho base\n", known_hosts_root=tmp_path)

    with patch.object(
        bootstrap,
        "bootstrap_script",
        side_effect=lambda revision: fetched.append(revision) or "#!/usr/bin/env bash\necho pinned\n",
    ):
        bootstrap.install(
            node_id="de-1",
            address="203.0.113.3",
            ssh_port=2222,
            branch="dev",
            revision="c" * 40,
            confirm_fingerprint=lambda _: True,
        )

    assert fetched == ["c" * 40]
    streamed = host.calls[-1][1]["input"]
    assert "pinned" in streamed
