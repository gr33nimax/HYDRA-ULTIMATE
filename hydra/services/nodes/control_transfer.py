"""The two SSH actions that move material between the base and one node.

Both run over the connection the installer already pinned, so they never scan or trust
a host key again, and both can carry the one-time password channel while the node has
no key of its own yet.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path

from hydra.core.host import HostBackend
from hydra.services.nodes.credentials import validate_control_certificate
from hydra.services.nodes.installer import remote_command, ssh_target
from hydra.services.nodes.ssh_auth import SshPasswordAuth, askpass_environment

_CONTROL_ACTION_TIMEOUT = 180
_CERTIFICATE_TIMEOUT = 120


def copy_node_certificate(
    *,
    host: HostBackend,
    connection_flags: Callable[..., Sequence[str]],
    address: str,
    ssh_port: int,
    node_id: str,
    known_hosts: Path,
    directory: Path,
    ssh_user: str = "root",
    auth: SshPasswordAuth | None = None,
) -> tuple[Path, str]:
    """Fetch the node's own certificate and pin its fingerprint locally."""
    host_target = ssh_target(ssh_user, address)
    pending = directory / ".node.crt.pending"
    target = directory / "node.crt"
    host.remove_file(pending)
    result = host.run(
        [
            "scp",
            *connection_flags(ssh_port, known_hosts, scp=True),
            f"{host_target}:/etc/hydra/node/node.crt",
            str(pending),
        ],
        timeout=_CERTIFICATE_TIMEOUT,
        text=True,
        capture_output=False,
        env=askpass_environment(auth),
    )
    if result.returncode != 0:
        host.remove_file(pending)
        raise RuntimeError("could not retrieve the pinned node certificate")
    try:
        certificate_pem = pending.read_bytes()
        fingerprint = validate_control_certificate(
            certificate_pem,
            node_id=node_id,
            role="server",
            address=address,
        )
        host.atomic_copy(pending, target, mode=0o644)
        return target, fingerprint
    finally:
        host.remove_file(pending)


def run_control_action(
    *,
    host: HostBackend,
    connection_flags: Callable[..., Sequence[str]],
    address: str,
    ssh_port: int,
    known_hosts: Path,
    request: dict[str, object],
    operation: str,
    ssh_user: str = "root",
    auth: SshPasswordAuth | None = None,
) -> None:
    """Run one provisioning/rotation/revocation request on the node itself."""
    host_target = ssh_target(ssh_user, address)
    remote = remote_command(
        ssh_user,
        "cd /opt/hydra && exec /opt/hydra/.venv/bin/python -m hydra.entrypoints.node_provision",
    )
    result = host.run(
        [
            "ssh",
            # -T: без PTY, чтобы строка JSON не экранировалась и не получала CRLF.
            "-T",
            *connection_flags(ssh_port, known_hosts),
            host_target,
            remote,
        ],
        input=json.dumps(request, separators=(",", ":")) + "\n",
        timeout=_CONTROL_ACTION_TIMEOUT,
        text=True,
        capture_output=False,
        env=askpass_environment(auth),
    )
    if result.returncode != 0:
        raise RuntimeError(f"node control identity {operation} failed")


def run_remote_shell(
    *,
    host: HostBackend,
    connection_flags: Callable[..., Sequence[str]],
    address: str,
    ssh_port: int,
    known_hosts: Path,
    command: str,
    operation: str,
    ssh_user: str = "root",
    auth: SshPasswordAuth | None = None,
    identity_file: Path | None = None,
) -> None:
    """Run one fixed command (never operator input) on the node over the pinned key."""
    host_target = ssh_target(ssh_user, address)
    result = host.run(
        [
            "ssh",
            "-T",
            *connection_flags(ssh_port, known_hosts),
            *(["-i", str(identity_file), "-o", "IdentitiesOnly=yes"] if identity_file else []),
            host_target,
            remote_command(ssh_user, command),
        ],
        timeout=_CONTROL_ACTION_TIMEOUT,
        text=True,
        capture_output=True,
        env=askpass_environment(auth),
    )
    if result.returncode != 0:
        raise RuntimeError(f"node {operation} failed")


__all__ = ["copy_node_certificate", "run_control_action", "run_remote_shell"]
