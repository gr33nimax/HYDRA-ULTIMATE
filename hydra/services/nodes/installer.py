"""Pinned SSH installation of one clean Hydra node."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from collections.abc import Callable
from pathlib import Path

from hydra.contracts.node_validation import checked_node_branch, checked_node_id, checked_node_revision
from hydra.core.host import HostBackend

_FINGERPRINT = re.compile(r"(?<!\w)SHA256:[A-Za-z0-9+/=]+")
_NODE_SSH_ACTION_TIMEOUT = 180


def ssh_connection_flags(port: int, known_hosts: Path, *, scp: bool = False) -> list[str]:
    return [
        "-P" if scp else "-p",
        str(port),
        "-o",
        "BatchMode=no",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
    ]


def valid_node_address(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        labels = address.rstrip(".").split(".")
        return (
            bool(address)
            and len(address) <= 253
            and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels)
        )


def install_node(
    *,
    host: HostBackend,
    script: str,
    known_hosts_root: Path,
    node_id: str,
    address: str,
    ssh_port: int,
    branch: str,
    revision: str,
    confirm_fingerprint: Callable[[str], bool],
) -> str:
    """Confirm the scanned host key, pin it, then stream the installer over SSH."""
    checked_node_id(node_id, context="node_id")
    if not isinstance(address, str) or not valid_node_address(address):
        raise ValueError("address must be an IP address or DNS hostname")
    if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
        raise ValueError("ssh_port must be 1..65535")
    checked_node_branch(branch, context="branch")
    checked_node_revision(revision, context="revision")
    if not callable(confirm_fingerprint):
        raise ValueError("confirm_fingerprint must be callable")

    keyscan = host.run(
        ["ssh-keyscan", "-p", str(ssh_port), "-t", "ed25519", address],
        timeout=15,
        text=True,
    )
    keys = sorted(
        {line.strip() for line in (keyscan.stdout or "").splitlines() if line.strip() and not line.startswith("#")}
    )
    if keyscan.returncode != 0 or len(keys) != 1:
        raise RuntimeError("could not identify one SSH host key")
    key_parts = keys[0].split()
    if len(key_parts) != 3 or key_parts[1] != "ssh-ed25519":
        raise RuntimeError("SSH host key scan returned an unsupported key")

    fingerprint_result = host.run(
        ["ssh-keygen", "-lf", "-"],
        input=keys[0] + "\n",
        timeout=15,
        text=True,
    )
    fingerprints = _FINGERPRINT.findall(fingerprint_result.stdout or "")
    if fingerprint_result.returncode != 0 or len(set(fingerprints)) != 1:
        raise RuntimeError("could not calculate SSH host fingerprint")
    fingerprint = fingerprints[0]
    if not confirm_fingerprint(fingerprint):
        raise PermissionError("SSH host fingerprint was not confirmed")

    known_hosts = known_hosts_root / node_id / "known_hosts"
    host.ensure_directory(known_hosts.parent, mode=0o700)
    host.atomic_write(known_hosts, keys[0] + "\n", mode=0o600)
    target = f"root@[{address}]" if ":" in address else f"root@{address}"
    remote = f"HYDRA_ROLE=node HYDRA_REF={shlex.quote(branch)} HYDRA_TARGET_REV={shlex.quote(revision)} bash -s"
    result = host.run(
        [
            "ssh",
            "-tt",
            "-p",
            str(ssh_port),
            "-o",
            "BatchMode=no",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            target,
            remote,
        ],
        input=script,
        timeout=900,
        text=True,
        capture_output=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"node bootstrap failed (exit {result.returncode})")
    return fingerprint


def uninstall_node(
    *,
    host: HostBackend,
    known_hosts_root: Path,
    node_id: str,
    address: str,
    ssh_port: int,
) -> None:
    """Remove one node through its confirmed SSH identity, never a shell payload."""
    checked_node_id(node_id, context="node_id")
    if not valid_node_address(address):
        raise ValueError("address must be an IP address or DNS hostname")
    if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
        raise ValueError("ssh_port must be 1..65535")
    if not known_hosts_root.is_absolute() or known_hosts_root.is_symlink():
        raise ValueError("known_hosts_root must be an absolute non-symlink path")
    node_directory = known_hosts_root / node_id
    known_hosts = node_directory / "known_hosts"
    if node_directory.is_symlink() or known_hosts.is_symlink() or not known_hosts.is_file():
        raise RuntimeError("SSH host key is not pinned; node uninstallation was not attempted")

    target = f"root@[{address}]" if ":" in address else f"root@{address}"
    remote = "cd /opt/hydra && exec /opt/hydra/.venv/bin/python -m hydra.entrypoints.node_provision"
    result = host.run(
        ["ssh", "-tt", *ssh_connection_flags(ssh_port, known_hosts), target, remote],
        input=json.dumps({"action": "uninstall", "node_id": node_id}, separators=(",", ":")) + "\n",
        timeout=_NODE_SSH_ACTION_TIMEOUT,
        text=True,
        capture_output=False,
    )
    if result.returncode != 0:
        raise RuntimeError("node uninstallation failed")


__all__ = ["install_node", "ssh_connection_flags", "uninstall_node", "valid_node_address"]
