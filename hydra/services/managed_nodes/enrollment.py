"""Management identity enrollment and mTLS verification after SSH bootstrap."""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Callable
from typing import Protocol
from pathlib import Path
import time

from hydra.contracts.managed_node_installation import InstallPlan
from hydra.contracts.managed_node_models import NodeDefinition
from hydra.contracts.managed_node_observations import NodeSample
from hydra.core.host import HostBackend
from hydra.services.managed_nodes.client import ManagedNodeClient
from hydra.services.managed_nodes.credentials import ManagementClientFiles, ManagementCredentialStore, SshPasswordChannel
from hydra.services.managed_nodes.identity import validate_certificate_identity
from hydra.services.managed_nodes.ssh import ManagedNodeSSH

_CERT_ROOT = Path("/etc/hydra/managed-node")
_CERT_PATH = _CERT_ROOT / "node.crt"
_RULE_COMMENT = "hydra-managed-node-{}-{}"
_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ManagementStateClient(Protocol):
    def state(self, deadline: float) -> NodeSample: ...


class EnrollmentError(RuntimeError):
    def __init__(self, stage: str, reason: str) -> None:
        self.stage = stage
        self.reason = reason[:160]
        super().__init__(f"{stage}: {self.reason}")


class NodeEnrollmentService:
    def __init__(
        self,
        *,
        ssh: ManagedNodeSSH,
        credentials: ManagementCredentialStore,
        client_factory: Callable[[NodeDefinition, ManagementClientFiles, bytes], ManagementStateClient] | None = None,
    ) -> None:
        self._ssh = ssh
        self._credentials = credentials
        self._client_factory = client_factory or self._default_client

    def provision(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> None:
        certificate = self._credentials.ensure_client_identity(plan.definition.identity_ref)
        server_certificate = self._ssh.provision_management(plan, certificate, auth)
        self._credentials.store_server_certificate(
            plan.definition.identity_ref,
            server_certificate,
            node_id=plan.definition.id,
            address=plan.definition.address,
        )

    def recover_provision(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> str:
        server_certificate = self._ssh.read_public_certificate(plan, auth)
        if server_certificate is None:
            return "retry"
        validate_certificate_identity(
            server_certificate,
            node_id=plan.definition.id,
            role="server",
            address=plan.definition.address,
        )
        current = self._credentials.read_server_certificate(plan.definition.identity_ref)
        if current is None:
            self._credentials.store_server_certificate(
                plan.definition.identity_ref,
                server_certificate,
                node_id=plan.definition.id,
                address=plan.definition.address,
            )
        elif current != server_certificate:
            return "unknown"
        files = self._credentials.client_files(plan.definition.identity_ref)
        try:
            sample = self._client_factory(plan.definition, files, server_certificate).state(time.monotonic() + 10.0)
        except Exception:
            return "unknown"
        return "done" if sample.node_id == plan.definition.id else "unknown"

    def verify(self, plan: InstallPlan) -> NodeSample:
        files = self._credentials.client_files(plan.definition.identity_ref)
        server_certificate = self._credentials.read_server_certificate(plan.definition.identity_ref)
        if server_certificate is None:
            raise EnrollmentError("management-identity", "pinned node certificate is unavailable")
        sample = self._client_factory(plan.definition, files, server_certificate).state(time.monotonic() + 10.0)
        if sample.node_id != plan.definition.id:
            raise EnrollmentError("management-identity", "mTLS response identifies a different node")
        return sample

    @staticmethod
    def _default_client(definition: NodeDefinition, files: ManagementClientFiles, certificate: bytes) -> ManagedNodeClient:
        return ManagedNodeClient(
            host=definition.address,
            port=definition.control_port,
            node_id=definition.id,
            certificate=files.certificate,
            private_key=files.private_key,
            pinned_server_certificate=certificate,
        )


def apply_management_firewall(
    *,
    host: HostBackend,
    source_ip: str,
    control_port: int,
    node_id: str,
) -> None:
    """Allow only the enrolled base address to reach this node's TCP control port."""
    source = ipaddress.ip_address(source_ip)
    if type(control_port) is not int or not 1024 <= control_port <= 65535 or not _NODE_ID.fullmatch(node_id):
        raise ValueError("managed-node firewall request is invalid")
    executable = "iptables" if source.version == 4 else "ip6tables"
    if host.which(executable) is None:
        raise RuntimeError(f"{executable} is unavailable for management source restriction")
    allow_label = _RULE_COMMENT.format(node_id, "allow")
    deny_label = _RULE_COMMENT.format(node_id, "deny")
    allow = ["-p", "tcp", "-s", str(source), "--dport", str(control_port), "-m", "comment", "--comment", allow_label, "-j", "ACCEPT"]
    deny = ["-p", "tcp", "--dport", str(control_port), "-m", "comment", "--comment", deny_label, "-j", "DROP"]
    status = host.run([executable, "-w", "-S", "INPUT"], timeout=10, text=True)
    if status.returncode != 0:
        raise RuntimeError("management firewall INPUT chain is unavailable")
    lines = status.stdout.splitlines()
    expected = {
        allow_label: ["-A", "INPUT", *allow],
        deny_label: ["-A", "INPUT", *deny],
    }
    rules = [(index, shlex.split(line)) for index, line in enumerate(lines)]
    allow_positions = [index for index, tokens in rules if tokens == expected[allow_label]]
    deny_positions = [index for index, tokens in rules if tokens == expected[deny_label]]
    if len(allow_positions) == len(deny_positions) == 1 and allow_positions[0] < deny_positions[0]:
        return
    _delete_managed_rules(host, executable, allow_label, deny_label)
    try:
        _run_firewall(host, executable, ["-I", "INPUT", "1", *deny])
        _run_firewall(host, executable, ["-I", "INPUT", "1", *allow])
    except Exception as exc:
        try:
            _delete_managed_rules(host, executable, allow_label, deny_label)
        except Exception as rollback:
            raise RuntimeError(f"management firewall failed ({exc}); rollback failed ({rollback})") from exc
        raise


def remove_management_firewall(
    *,
    host: HostBackend,
    node_id: str,
    allowed_source_ips: list[str] | tuple[str, ...],
) -> None:
    if not _NODE_ID.fullmatch(node_id) or not allowed_source_ips:
        raise ValueError("managed-node firewall identity is invalid")
    families = {ipaddress.ip_address(value).version for value in allowed_source_ips}
    errors: list[str] = []
    for family in sorted(families):
        executable = "iptables" if family == 4 else "ip6tables"
        if host.which(executable) is None:
            errors.append(f"{executable} is unavailable")
            continue
        try:
            _delete_managed_rules(
                host, executable, _RULE_COMMENT.format(node_id, "allow"),
                _RULE_COMMENT.format(node_id, "deny"),
            )
        except Exception as exc:
            errors.append(str(exc)[:120])
    if errors:
        raise RuntimeError("managed-node firewall cleanup failed: " + "; ".join(errors))


def _delete_managed_rules(host: HostBackend, executable: str, *labels: str) -> None:
    status = host.run([executable, "-w", "-S", "INPUT"], timeout=10, text=True)
    if status.returncode != 0:
        raise RuntimeError("management firewall INPUT chain is unavailable")
    for label in labels:
        for line in reversed(status.stdout.splitlines()):
            tokens = shlex.split(line)
            if "--comment" not in tokens:
                continue
            comment_index = tokens.index("--comment")
            if comment_index + 1 >= len(tokens) or tokens[comment_index + 1] != label:
                continue
            if len(tokens) < 3 or tokens[:2] != ["-A", "INPUT"]:
                raise RuntimeError("management firewall rule has an invalid shape")
            result = host.run([executable, "-w", "-D", "INPUT", *tokens[2:]], timeout=10, text=True)
            if result.returncode != 0:
                raise RuntimeError("managed-node firewall rule removal failed")


def _run_firewall(host: HostBackend, executable: str, args: list[str]) -> None:
    result = host.run([executable, "-w", *args], timeout=10, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"management firewall command failed: {result.stderr[:120]}")


__all__ = ["EnrollmentError", "NodeEnrollmentService", "apply_management_firewall", "remove_management_firewall"]
