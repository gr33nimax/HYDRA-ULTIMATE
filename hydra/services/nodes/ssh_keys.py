"""A per-node SSH key the base owns, so later cleanup does not need a password.

The installer's password (or the operator's terminal prompt) covers the first contact.
Afterwards the base should be able to reach the node on its own terms: a dedicated key
kept in the protected credentials directory, installed with an owner tag, and used by
uninstall, revocation and cookie import. Nothing else in ``authorized_keys`` is touched,
and the removal path deletes only the tagged line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from collections.abc import Callable, Sequence

from hydra.contracts.node_validation import checked_node_id
from hydra.core.host import HostBackend
from hydra.services.nodes.control_transfer import run_remote_shell
from hydra.services.nodes.ssh_auth import SshPasswordAuth

MANAGED_KEY_NAME = "managed-ssh.key"
MANAGED_KEY_TAG_PREFIX = "hydra-managed"
# The comment carries the owner tag, so it must accept the tag's separator.
_KEY_COMMENT = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


@dataclass(frozen=True)
class ManagedSshKey:
    """The private key path plus the tagged public line that identifies it remotely."""

    private_key: Path
    public_line: str
    tag: str


def managed_key_tag(node_id: str) -> str:
    checked_node_id(node_id, context="node_id")
    return f"{MANAGED_KEY_TAG_PREFIX}:{node_id}"


def managed_key_path(credentials_directory: Path) -> Path:
    return credentials_directory / MANAGED_KEY_NAME


def ensure_managed_keypair(
    *,
    host: HostBackend,
    directory: Path,
    node_id: str,
) -> ManagedSshKey:
    """Create the key once and keep it; regenerating would lose remote access."""
    tag = managed_key_tag(node_id)
    path = managed_key_path(directory)
    if path.is_symlink():
        raise RuntimeError("managed node SSH key must not be a symlink")
    if path.exists():
        private_key = serialization.load_ssh_private_key(path.read_bytes(), password=None)
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        host.atomic_write(path, pem, mode=0o600)
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return ManagedSshKey(path, f"{public.decode('ascii')} {tag}", tag)


def tagged_authorized_key_line(line: str, *, tag: str) -> bool:
    """True only for the line this base installed for this node."""
    parts = line.strip().split()
    if len(parts) < 3:
        return False
    comment = parts[-1]
    if not _KEY_COMMENT.fullmatch(comment):
        return False
    return comment == tag


def remote_install_command(tag: str, public_line: str) -> str:
    """Idempotent append that never rewrites other keys.

    The public line travels as a quoted literal, and the command only adds it when the
    tag is absent, so a repeated enrollment cannot duplicate or reorder entries.
    """
    import shlex

    quoted = shlex.quote(public_line)
    directory = '"$HOME/.ssh"'
    authorized = '"$HOME/.ssh/authorized_keys"'
    return (
        f"mkdir -p {directory} && chmod 700 {directory} && "
        f"touch {authorized} && chmod 600 {authorized} && "
        f"grep -qF {shlex.quote(tag)} {authorized} || printf '%s\\n' {quoted} >> {authorized}"
    )


def remote_remove_command(tag: str) -> str:
    """Remove only the tagged line, leaving every other key untouched."""
    import shlex

    quoted_tag = shlex.quote(tag)
    authorized = '"$HOME/.ssh/authorized_keys"'
    return (
        f"if [ -f {authorized} ]; then "
        f"grep -vF {quoted_tag} {authorized} > {authorized}.hydra-tmp && "
        f"mv {authorized}.hydra-tmp {authorized}; fi"
    )


def managed_key_file(credentials_root: Path, node_id: str) -> Path | None:
    """The base-owned SSH key for this node, when enrollment installed one."""
    checked_node_id(node_id, context="node_id")
    path = managed_key_path(credentials_root / node_id)
    if path.is_symlink():
        return None
    return path if path.is_file() else None


def install_managed_key(
    *,
    host: HostBackend,
    credentials_root: Path,
    known_hosts_root: Path,
    connection_flags: Callable[..., Sequence[str]],
    node_id: str,
    address: str,
    ssh_port: int,
    ssh_user: str = "root",
    auth: SshPasswordAuth | None = None,
) -> ManagedSshKey:
    """Install the base's own key so later cleanup needs no account password."""
    checked_node_id(node_id, context="node_id")
    if credentials_root.is_symlink():
        raise RuntimeError("node credentials root must not be a symlink")
    directory = credentials_root / node_id
    if directory.is_symlink():
        raise RuntimeError("node credential directory must not be a symlink")
    known_hosts = known_hosts_root / node_id / "known_hosts"
    if not known_hosts.is_file():
        raise RuntimeError("SSH host key is not pinned; install the node first")
    host.ensure_directory(directory, mode=0o700)
    key = ensure_managed_keypair(host=host, directory=directory, node_id=node_id)
    run_remote_shell(
        host=host,
        connection_flags=connection_flags,
        address=address,
        ssh_port=ssh_port,
        known_hosts=known_hosts,
        command=remote_install_command(key.tag, key.public_line),
        operation="managed key installation",
        ssh_user=ssh_user,
        auth=auth,
    )
    return key


__all__ = [
    "MANAGED_KEY_NAME",
    "ManagedSshKey",
    "ensure_managed_keypair",
    "install_managed_key",
    "managed_key_file",
    "managed_key_path",
    "managed_key_tag",
    "remote_install_command",
    "remote_remove_command",
    "tagged_authorized_key_line",
]
