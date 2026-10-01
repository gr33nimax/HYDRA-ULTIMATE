"""Pinned, single-purpose SSH bootstrap for clean Hydra nodes."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from hydra.contracts.node_validation import NODE_CONTRACT_VERSION, checked_node_id
from hydra.core.host import HostBackend
from hydra.core.node_identity import NodeIdentity
from hydra.services.nodes.control_client import NodeControlClient
from hydra.services.nodes.control_transfer import copy_node_certificate, run_control_action
from hydra.services.nodes.installer import (
    install_node,
    remote_command,
    ssh_target,
    valid_node_address as _valid_address,
)
from hydra.services.nodes.ssh_auth import SshPasswordAuth, askpass_environment
from hydra.services.nodes.ssh_keys import install_managed_key, managed_key_file
from hydra.services.nodes.credentials import (
    NodeControlCredentials,
    generate_control_certificate,
    validate_control_certificate,
)


from hydra.services.nodes.revision import resolve_branch_revision

_LOGGER = logging.getLogger(__name__)


class NodeBootstrap:
    """Install only a clean node, after explicit SSH host-key confirmation."""

    def __init__(
        self,
        *,
        host: HostBackend,
        script: str,
        known_hosts_root: Path = Path("/var/lib/hydra/ssh"),
        credentials_root: Path = Path("/var/lib/hydra/node-credentials"),
    ):
        if not isinstance(script, str) or not script.strip():
            raise ValueError("bootstrap script must not be empty")
        self.host = host
        self.script = script
        self.known_hosts_root = Path(known_hosts_root)
        self.credentials_root = Path(credentials_root)

    def resolve_revision(self, branch: str) -> str:
        return resolve_branch_revision(branch)

    def install(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        branch: str,
        revision: str,
        confirm_fingerprint: Callable[[str], bool],
        ssh_user: str = "root",
        auth: SshPasswordAuth | None = None,
    ) -> str:
        return install_node(
            host=self.host,
            script=self.script,
            known_hosts_root=self.known_hosts_root,
            node_id=node_id,
            address=address,
            ssh_port=ssh_port,
            branch=branch,
            revision=revision,
            confirm_fingerprint=confirm_fingerprint,
            ssh_user=ssh_user,
            auth=auth,
        )

    def managed_key_file(self, node_id: str) -> Path | None:
        """The base-owned SSH key for this node, when enrollment installed one."""
        return managed_key_file(self.credentials_root, node_id)

    def _connection_flags(self, port: int, known_hosts: Path, *, scp: bool = False) -> list[str]:
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

    def _credentials_directory(self, node_id: str) -> Path:
        if self.credentials_root.is_symlink():
            raise RuntimeError("node credentials root must not be a symlink")
        directory = self.credentials_root / node_id
        if directory.is_symlink():
            raise RuntimeError("node credential directory must not be a symlink")
        self.host.ensure_directory(directory, mode=0o700)
        return directory

    def _active_client_paths(self, directory: Path) -> tuple[Path, Path]:
        active = directory / "base-client.active"
        if active.is_symlink():
            raise RuntimeError("active node control credential pointer must not be a symlink")
        if not active.exists():
            return directory / "base-client.crt", directory / "base-client.key"
        fingerprint = active.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise RuntimeError("active node control credential pointer is invalid")
        stem = directory / f"base-client-{fingerprint}"
        return stem.with_suffix(".crt"), stem.with_suffix(".key")

    def _read_client_credentials(
        self,
        node_id: str,
        certificate_path: Path,
        private_key_path: Path,
    ) -> tuple[bytes, str]:
        if certificate_path.is_symlink() or private_key_path.is_symlink():
            raise RuntimeError("node control credential files must not be symlinks")
        certificate_exists, private_key_exists = certificate_path.exists(), private_key_path.exists()
        if certificate_exists != private_key_exists or not certificate_exists:
            raise RuntimeError("local node control credential pair is incomplete")
        certificate_pem = certificate_path.read_bytes()
        fingerprint = validate_control_certificate(certificate_pem, node_id=node_id, role="client")
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
        certificate_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if certificate_public != key_public:
            raise RuntimeError("local node control certificate and key do not match")
        return certificate_pem, fingerprint

    def _ensure_base_client_credentials(
        self,
        node_id: str,
        directory: Path,
    ) -> tuple[Path, Path, bytes, str]:
        certificate_path, private_key_path = self._active_client_paths(directory)
        if certificate_path.exists() or private_key_path.exists():
            certificate_pem, fingerprint = self._read_client_credentials(node_id, certificate_path, private_key_path)
            return certificate_path, private_key_path, certificate_pem, fingerprint

        generated = generate_control_certificate(node_id, role="client")
        created: list[Path] = []
        try:
            for path, content, mode in (
                (certificate_path, generated.certificate, 0o644),
                (private_key_path, generated.private_key, 0o600),
            ):
                created.append(path)
                self.host.atomic_write(path, content, mode=mode)
        except Exception as exc:
            cleanup_errors = []
            for path in reversed(created):
                try:
                    self.host.remove_file(path)
                except Exception as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            if cleanup_errors:
                raise RuntimeError("could not roll back local node control credentials") from exc
            raise
        return certificate_path, private_key_path, generated.certificate, generated.fingerprint

    def _pending_client_credentials(self, node_id: str, directory: Path) -> tuple[Path, Path, bytes, str]:
        certificate_path = directory / "base-client.pending.crt"
        private_key_path = directory / "base-client.pending.key"
        if certificate_path.exists() and private_key_path.exists():
            certificate_pem, fingerprint = self._read_client_credentials(node_id, certificate_path, private_key_path)
            return certificate_path, private_key_path, certificate_pem, fingerprint
        self.host.remove_file(certificate_path)
        self.host.remove_file(private_key_path)
        generated = generate_control_certificate(node_id, role="client")
        self.host.atomic_write(certificate_path, generated.certificate, mode=0o644)
        try:
            self.host.atomic_write(private_key_path, generated.private_key, mode=0o600)
        except Exception:
            self.host.remove_file(certificate_path)
            raise
        return certificate_path, private_key_path, generated.certificate, generated.fingerprint

    def _activate_pending_client_credentials(
        self,
        directory: Path,
        pending_certificate: Path,
        pending_key: Path,
        fingerprint: str,
    ) -> tuple[Path, Path]:
        stem = directory / f"base-client-{fingerprint}"
        certificate_path, private_key_path = stem.with_suffix(".crt"), stem.with_suffix(".key")
        if certificate_path.is_symlink() or private_key_path.is_symlink():
            raise RuntimeError("credential generation files must not be symlinks")
        for source, target, mode in (
            (pending_certificate, certificate_path, 0o644),
            (pending_key, private_key_path, 0o600),
        ):
            if target.exists():
                if target.read_bytes() != source.read_bytes():
                    raise RuntimeError("credential generation fingerprint collision")
            else:
                self.host.atomic_copy(source, target, mode=mode)
        self.host.atomic_write(directory / "base-client.active", fingerprint + "\n", mode=0o600)
        for path in directory.iterdir():
            if path in {certificate_path, private_key_path, pending_certificate, pending_key}:
                continue
            if path.name.startswith("base-client-") and path.suffix in {".crt", ".key"}:
                self.host.remove_file(path)
            elif path.name in {"base-client.crt", "base-client.key"}:
                self.host.remove_file(path)
        self.host.remove_file(pending_certificate)
        self.host.remove_file(pending_key)
        return certificate_path, private_key_path

    def provision_control_identity(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        base_url: str,
        control_port: int,
        ssh_user: str = "root",
        auth: SshPasswordAuth | None = None,
    ) -> NodeControlCredentials:
        """Issue per-node credentials over its already-pinned SSH connection."""
        checked_node_id(node_id, context="node_id")
        if not _valid_address(address):
            raise ValueError("address must be an IP address or DNS hostname")
        if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
            raise ValueError("ssh_port must be 1..65535")
        if not self.credentials_root.is_absolute():
            raise ValueError("credentials_root must be absolute")
        NodeIdentity(
            node_id=node_id,
            base_url=base_url,
            base_ip="192.0.2.1",
            control_port=control_port,
            certificate="/etc/hydra/node/node.crt",
            private_key="/etc/hydra/node/node.key",
            base_ca="/etc/hydra/node/base-ca.crt",
            base_fingerprint="0" * 64,
        ).validate()

        known_hosts = self.known_hosts_root / node_id / "known_hosts"
        if not known_hosts.is_file():
            raise RuntimeError("SSH host key is not pinned; install the node first")
        directory = self._credentials_directory(node_id)
        client_certificate, client_key, client_pem, base_fingerprint = self._ensure_base_client_credentials(
            node_id, directory
        )
        run_control_action(
            host=self.host,
            connection_flags=self._connection_flags,
            address=address,
            ssh_port=ssh_port,
            known_hosts=known_hosts,
            request={
                "node_id": node_id,
                "base_url": base_url,
                "control_address": address,
                "control_port": control_port,
                "base_certificate": client_pem.decode("ascii"),
            },
            operation="provisioning",
            ssh_user=ssh_user,
            auth=auth,
        )
        node_certificate, node_fingerprint = copy_node_certificate(
            host=self.host,
            connection_flags=self._connection_flags,
            address=address,
            ssh_port=ssh_port,
            node_id=node_id,
            known_hosts=known_hosts,
            ssh_user=ssh_user,
            auth=auth,
            directory=directory,
        )
        return NodeControlCredentials(
            client_certificate=client_certificate,
            client_private_key=client_key,
            node_certificate=node_certificate,
            base_fingerprint=base_fingerprint,
            node_fingerprint=node_fingerprint,
        )

    def rotate_control_credentials(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        base_url: str,
        control_port: int,
        ssh_user: str = "root",
        auth: SshPasswordAuth | None = None,
    ) -> NodeControlCredentials:
        """Rotate the base client certificate through the pinned SSH channel."""
        checked_node_id(node_id, context="node_id")
        if not _valid_address(address):
            raise ValueError("address must be an IP address or DNS hostname")
        if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
            raise ValueError("ssh_port must be 1..65535")
        if not self.credentials_root.is_absolute():
            raise ValueError("credentials_root must be absolute")
        NodeIdentity(
            node_id=node_id,
            base_url=base_url,
            base_ip="192.0.2.1",
            control_port=control_port,
            certificate="/etc/hydra/node/node.crt",
            private_key="/etc/hydra/node/node.key",
            base_ca="/etc/hydra/node/base-ca.crt",
            base_fingerprint="0" * 64,
        ).validate()

        known_hosts = self.known_hosts_root / node_id / "known_hosts"
        if not known_hosts.is_file():
            raise RuntimeError("SSH host key is not pinned; install the node first")
        directory = self._credentials_directory(node_id)
        pending_certificate, pending_key, client_pem, base_fingerprint = self._pending_client_credentials(
            node_id, directory
        )
        run_control_action(
            host=self.host,
            connection_flags=self._connection_flags,
            address=address,
            ssh_port=ssh_port,
            known_hosts=known_hosts,
            request={
                "action": "rotate",
                "node_id": node_id,
                "base_url": base_url,
                "control_address": address,
                "control_port": control_port,
                "base_certificate": client_pem.decode("ascii"),
            },
            operation="rotation",
            ssh_user=ssh_user,
            auth=auth,
        )
        node_certificate, node_fingerprint = copy_node_certificate(
            host=self.host,
            connection_flags=self._connection_flags,
            address=address,
            ssh_port=ssh_port,
            node_id=node_id,
            known_hosts=known_hosts,
            directory=directory,
            ssh_user=ssh_user,
            auth=auth,
        )
        try:
            install_managed_key(
                host=self.host,
                credentials_root=self.credentials_root,
                known_hosts_root=self.known_hosts_root,
                connection_flags=self._connection_flags,
                node_id=node_id,
                address=address,
                ssh_port=ssh_port,
                ssh_user=ssh_user,
                auth=auth,
            )
        except Exception as exc:
            # Enrollment already succeeded; cleanup can still use the account password.
            _LOGGER.warning("managed node SSH key was not installed: %s", type(exc).__name__)
        try:
            health = NodeControlClient(
                host=address,
                port=control_port,
                node_id=node_id,
                ca_file=node_certificate,
                certificate=pending_certificate,
                private_key=pending_key,
                server_fingerprint=node_fingerprint,
            ).health()
        except Exception as exc:
            raise RuntimeError("rotated node mTLS health check failed") from exc
        if not isinstance(health.get("ok"), bool) or not health["ok"]:
            raise RuntimeError("rotated node mTLS health check failed")
        if health.get("contract_version") != NODE_CONTRACT_VERSION:
            raise RuntimeError("rotated node mTLS health check failed")
        client_certificate, client_key = self._activate_pending_client_credentials(
            directory, pending_certificate, pending_key, base_fingerprint
        )
        return NodeControlCredentials(
            client_certificate=client_certificate,
            client_private_key=client_key,
            node_certificate=node_certificate,
            base_fingerprint=base_fingerprint,
            node_fingerprint=node_fingerprint,
        )

    def load_control_credentials(self, node_id: str, *, address: str) -> NodeControlCredentials:
        """Load the current per-node credential generation after process restart."""
        checked_node_id(node_id, context="node_id")
        if not _valid_address(address):
            raise ValueError("address must be an IP address or DNS hostname")
        if not self.credentials_root.is_absolute():
            raise ValueError("credentials_root must be absolute")
        directory = self.credentials_root / node_id
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError("node control credentials are unavailable")
        certificate_path, private_key_path = self._active_client_paths(directory)
        _, base_fingerprint = self._read_client_credentials(node_id, certificate_path, private_key_path)
        node_certificate = directory / "node.crt"
        node_fingerprint = validate_control_certificate(
            node_certificate.read_bytes(), node_id=node_id, role="server", address=address
        )
        return NodeControlCredentials(
            client_certificate=certificate_path,
            client_private_key=private_key_path,
            node_certificate=node_certificate,
            base_fingerprint=base_fingerprint,
            node_fingerprint=node_fingerprint,
        )

    def revoke_control_identity(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        ssh_user: str = "root",
        auth: SshPasswordAuth | None = None,
    ) -> None:
        """Revoke remote trust over pinned SSH before deleting local credentials."""
        checked_node_id(node_id, context="node_id")
        if not _valid_address(address):
            raise ValueError("address must be an IP address or DNS hostname")
        if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
            raise ValueError("ssh_port must be 1..65535")
        if not self.credentials_root.is_absolute() or self.credentials_root.is_symlink():
            raise ValueError("credentials_root must be an absolute non-symlink path")
        directory = self.credentials_root / node_id
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise RuntimeError("node credential directory is not a managed directory")
        known_hosts = self.known_hosts_root / node_id / "known_hosts"
        if not known_hosts.is_file():
            raise RuntimeError("SSH host key is not pinned; node revocation was not attempted")
        run_control_action(
            host=self.host,
            connection_flags=self._connection_flags,
            address=address,
            ssh_port=ssh_port,
            known_hosts=known_hosts,
            request={"action": "revoke", "node_id": node_id},
            operation="revocation",
            ssh_user=ssh_user,
            auth=auth,
        )
        if not directory.exists():
            return
        for path in directory.iterdir():
            if path.name in {
                "base-client.crt",
                "base-client.key",
                "base-client.pending.crt",
                "base-client.pending.key",
                "base-client.active",
                "node.crt",
                ".node.crt.pending",
            } or re.fullmatch(r"base-client-[0-9a-f]{64}\.(?:crt|key)", path.name):
                self.host.remove_file(path)
