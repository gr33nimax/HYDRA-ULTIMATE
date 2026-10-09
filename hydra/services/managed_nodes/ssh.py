"""Pinned OpenSSH preflight, bootstrap and uninstall with fixed command templates."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from hydra.contracts.managed_node_installation import InstallPlan, InstallRequest
from hydra.contracts.managed_node_models import NodeDefinition, Operation
from hydra.core.host import HostBackend
from hydra.core.uninstall import CRON_PATHS, DATA_PATHS, PROGRAM_PATHS, SYSTEM_SERVICES
from hydra.services.managed_nodes.credentials import SshPasswordChannel
from hydra.utils.commands import bounded_reason, redact_text

_REPO_URL = "https://github.com/gr33nimax/HYDRA-ULTIMATE"
_MAX_BOOTSTRAP_BYTES = 2 * 1024 * 1024
_MAX_CERTIFICATE_BYTES = 64 * 1024
_MAX_PROVISION_REQUEST_BYTES = 16 * 1024
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
_PORT = re.compile(r"(?<!\d)(\d{1,5})$")
_REMOTE_OS = (
    "import json,pathlib\n"
    "d={}\n"
    "for line in pathlib.Path('/etc/os-release').read_text().splitlines():\n"
    " if '=' in line:\n"
    "  k,v=line.split('=',1)\n"
    "  d[k]=v.strip('\"')\n"
    "print(json.dumps({'id':d.get('ID',''),'version':d.get('VERSION_ID','')}))\n"
)
_REMOTE_FACTS = "import json,os,pathlib; c=os.environ.get('SSH_CONNECTION','').split(); p=pathlib.Path('/var/lib/hydra/state.json').exists() or pathlib.Path('/opt/hydra/main.py').exists() or pathlib.Path('/etc/systemd/system/hydra-managed-node.service').exists() or pathlib.Path('/usr/local/bin/hydra').exists(); print(json.dumps({'source':c[0] if len(c)==4 else '', 'existing':p}))"
_REMOTE_BOOTSTRAP_STATUS = "import json,pathlib; p=pathlib.Path('/opt/hydra/.hydra-source-revision'); print(json.dumps({'revision':p.read_text().strip() if p.is_file() else '', 'installed':pathlib.Path('/opt/hydra/main.py').is_file()}))"
_REMOTE_UNINSTALL_VERIFY = (
    "import json,pathlib; p="
    + repr([str(path) for path in (*PROGRAM_PATHS, *DATA_PATHS, *CRON_PATHS)]
           + [f"/etc/systemd/system/{service}" for service in SYSTEM_SERVICES])
    + "; print(json.dumps({'clean':not any(pathlib.Path(x).exists() or pathlib.Path(x).is_symlink() for x in p)}))"
)


class SshOperationError(RuntimeError):
    def __init__(self, stage: str, reason: str, *, outcome_unknown: bool) -> None:
        self.stage = stage
        self.reason = _safe(reason)
        self.outcome_unknown = outcome_unknown
        super().__init__(f"{stage}: {self.reason}")


@dataclass(frozen=True)
class SshFacts:
    os_id: str
    os_version: str
    uid: int
    passwordless_sudo: bool
    existing_installation: bool
    source_address: str
    used_ports: frozenset[int]
    host_key_fingerprint: str

    def validate(self) -> None:
        if self.os_id not in {"ubuntu", "debian"}:
            raise ValueError("remote operating system is not supported")
        if type(self.uid) is not int or self.uid < 0 or type(self.passwordless_sudo) is not bool:
            raise ValueError("remote privilege facts are invalid")
        if type(self.existing_installation) is not bool:
            raise ValueError("remote installation fact is invalid")
        ipaddress.ip_address(self.source_address)
        if not isinstance(self.used_ports, frozenset) or any(
            type(port) is not int or not 1 <= port <= 65535 for port in self.used_ports
        ):
            raise ValueError("remote listening-port facts are invalid")
        if not _FINGERPRINT.fullmatch(self.host_key_fingerprint):
            raise ValueError("remote SSH fingerprint is invalid")


class ManagedNodeSSH(Protocol):
    def discover_host_key(self, address: str, port: int) -> str: ...
    def inspect(self, request: InstallRequest, auth: SshPasswordChannel | None) -> SshFacts: ...
    def uninstall_existing(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> None: ...
    def bootstrap(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> None: ...
    def provision_management(
        self, plan: InstallPlan, base_certificate: bytes, auth: SshPasswordChannel | None
    ) -> bytes: ...
    def read_public_certificate(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> bytes | None: ...
    def remove_node(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> None: ...
    def reconcile_install_step(
        self, plan: InstallPlan, operation: Operation, auth: SshPasswordChannel | None
    ) -> Literal["done", "retry", "unknown"]: ...
    def reconcile_remove(
        self, plan: InstallPlan, operation: Operation, auth: SshPasswordChannel | None
    ) -> Literal["done", "retry", "unknown"]: ...


class OpenSshManagedNodeSSH:
    """Use OpenSSH only with an operator-pinned host key and a fixed remote action."""

    def __init__(self, *, host: HostBackend, known_hosts_root: Path) -> None:
        if not known_hosts_root.is_absolute():
            raise ValueError("known_hosts root must be absolute")
        self._host = host
        self._known_hosts_root = known_hosts_root

    def discover_host_key(self, address: str, port: int) -> str:
        if not isinstance(address, str) or not address or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("SSH host and port are invalid")
        scan = self._host.run(
            ["ssh-keyscan", "-p", str(port), "-t", "ed25519,rsa", address],
            timeout=15,
            text=True,
        )
        lines = [line for line in scan.stdout.splitlines() if line and not line.startswith("#")]
        if scan.returncode != 0 or not lines:
            raise SshOperationError("host-key", "SSH host key scan failed", outcome_unknown=False)
        fingerprints = sorted(self._fingerprints(lines))
        if not fingerprints:
            raise SshOperationError("host-key", "SSH host key fingerprint is unavailable", outcome_unknown=False)
        return fingerprints[0]

    def inspect(self, request: InstallRequest, auth: SshPasswordChannel | None) -> SshFacts:
        request.validate()
        fingerprint = self._pin_host_key(request.id, request.address, request.ssh_port, request.host_key_fingerprint)
        temporary_port = next(
            port for port in range(1024, 65536) if port != request.ssh_port and port not in request.protocol_ports()
        )
        definition = NodeDefinition(
            request.id,
            request.name,
            request.address,
            request.ssh_user,
            request.branch,
            "0" * 40,
            request.control_port or temporary_port,
            request.protocols,
            f"managed-node/{request.id}",
            request.ssh_port,
        )
        os_result = self._execute(
            definition, "python3 -c " + shlex.quote(_REMOTE_OS), auth, timeout=15, stage="ssh-preflight"
        )
        facts_result = self._execute(
            definition, "python3 -c " + shlex.quote(_REMOTE_FACTS), auth, timeout=15, stage="ssh-preflight"
        )
        uid_result = self._execute(definition, "id -u", auth, timeout=10, stage="ssh-preflight")
        ports_result = self._execute(definition, "ss -H -lntu", auth, timeout=15, stage="ssh-preflight")
        try:
            os_data = json.loads(os_result.stdout)
            remote_data = json.loads(facts_result.stdout)
            uid = int(uid_result.stdout.strip())
            source = str(ipaddress.ip_address(remote_data["source"]))
            used_ports = _parse_listening_ports(ports_result.stdout)
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SshOperationError("ssh-preflight", "remote facts are incomplete", outcome_unknown=False) from exc
        passwordless_sudo = uid == 0
        if uid != 0:
            sudo_result = self._execute(
                definition, "sudo -n true", auth, timeout=10, stage="ssh-preflight", allow_failure=True
            )
            passwordless_sudo = sudo_result.returncode == 0
        facts = SshFacts(
            str(os_data.get("id", "")),
            str(os_data.get("version", "")),
            uid,
            passwordless_sudo,
            bool(remote_data.get("existing")),
            source,
            frozenset(used_ports),
            fingerprint,
        )
        facts.validate()
        if uid != 0 and not passwordless_sudo:
            raise SshOperationError(
                "ssh-preflight", "non-root SSH user requires passwordless sudo", outcome_unknown=False
            )
        return facts

    def uninstall_existing(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> None:
        command = self.remote_command_for(plan, "uninstall")
        self._remove_management_firewall_if_present(plan, auth)
        result = self._execute(
            plan.definition, command, auth, timeout=300, stage="existing-uninstall", allow_failure=True
        )
        if result.returncode != 0:
            raise SshOperationError(
                "existing-uninstall", bounded_reason(result) or "hydra uninstall --yes failed", outcome_unknown=False
            )
        verified = self._execute(
            plan.definition,
            "python3 -c " + shlex.quote(_REMOTE_UNINSTALL_VERIFY),
            auth,
            timeout=15,
            stage="existing-uninstall-verify",
        )
        if json.loads(verified.stdout).get("clean") is not True:
            raise SshOperationError(
                "existing-uninstall-verify", "HYDRA-owned installation remnants remain", outcome_unknown=True
            )

    def bootstrap(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> None:
        url = f"https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/{plan.definition.revision}/bootstrap.sh"
        try:
            result = self._host.run(["curl", "-fsSL", "--connect-timeout", "15", "--max-time", "120", url], timeout=130)
        except Exception as exc:
            raise SshOperationError("bootstrap-download", _safe(exc), outcome_unknown=False) from exc
        script = result.stdout if isinstance(result.stdout, bytes) else str(result.stdout).encode("utf-8")
        if result.returncode != 0 or not script or len(script) > _MAX_BOOTSTRAP_BYTES:
            raise SshOperationError(
                "bootstrap-download", "pinned bootstrap source is unavailable or too large", outcome_unknown=False
            )
        prefix = "sudo -n " if plan.use_sudo else ""
        env = f"HYDRA_ROLE=node HYDRA_REF={plan.definition.branch} HYDRA_TARGET_REV={plan.definition.revision}"
        command = f"{prefix}env {env} /bin/bash -s"
        self._execute(plan.definition, command, auth, timeout=900, input=script, stage="bootstrap")

    def provision_management(
        self, plan: InstallPlan, base_certificate: bytes, auth: SshPasswordChannel | None
    ) -> bytes:
        request = json.dumps(
            {
                "action": "provision",
                "node_id": plan.definition.id,
                "address": plan.definition.address,
                "control_port": plan.definition.control_port,
                "source_ip": plan.source_address,
                "base_certificate": base_certificate.decode("ascii"),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        if len(request) > _MAX_PROVISION_REQUEST_BYTES:
            raise SshOperationError(
                "management-identity", "provision request exceeds the size limit", outcome_unknown=False
            )
        command = self.remote_command_for(plan, "provision")
        self._execute(plan.definition, command, auth, timeout=60, input=request, stage="management-identity")
        certificate = self.read_public_certificate(plan, auth)
        if certificate is None:
            raise SshOperationError(
                "management-certificate", "public management certificate is unavailable", outcome_unknown=True
            )
        return certificate

    def read_public_certificate(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> bytes | None:
        request = json.dumps(
            {"action": "read-public-certificate", "node_id": plan.definition.id, "address": plan.definition.address},
            separators=(",", ":"),
        ).encode("utf-8")
        result = self._execute(
            plan.definition,
            self.remote_command_for(plan, "read-certificate"),
            auth,
            timeout=20,
            input=request,
            stage="management-certificate",
            allow_failure=True,
        )
        if result.returncode != 0:
            return None
        certificate = (
            result.stdout if isinstance(result.stdout, bytes) else str(result.stdout).encode("ascii", "strict")
        )
        if len(certificate) > _MAX_CERTIFICATE_BYTES or not certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise SshOperationError(
                "management-certificate", "public certificate response is invalid", outcome_unknown=False
            )
        return certificate

    def remove_node(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> None:
        definition = plan.definition
        if self._uninstall_is_clean(plan, auth):
            return
        command = self.remote_command_for(plan, "uninstall")
        self._remove_management_firewall_if_present(plan, auth)
        result = self._execute(definition, command, auth, timeout=300, stage="remote-uninstall", allow_failure=True)
        if result.returncode != 0:
            raise SshOperationError(
                "remote-uninstall", bounded_reason(result) or "hydra uninstall --yes failed", outcome_unknown=False
            )
        if not self._uninstall_is_clean(plan, auth):
            raise SshOperationError(
                "remote-uninstall-verify", "HYDRA-owned installation remnants remain", outcome_unknown=True
            )

    def reconcile_install_step(
        self, plan: InstallPlan, operation: Operation, auth: SshPasswordChannel | None
    ) -> Literal["done", "retry", "unknown"]:
        if operation.active_step == "existing_uninstall":
            present = self._installation_present(plan.definition, auth)
            return "retry" if present else "done"
        if operation.active_step == "bootstrap":
            result = self._execute(
                plan.definition,
                "python3 -c " + shlex.quote(_REMOTE_BOOTSTRAP_STATUS),
                auth,
                timeout=15,
                stage="bootstrap-reconcile",
                allow_failure=True,
            )
            if result.returncode != 0:
                return "unknown"
            try:
                status = json.loads(result.stdout)
            except (TypeError, json.JSONDecodeError):
                return "unknown"
            if status.get("installed") is True and status.get("revision") == plan.definition.revision:
                return "done"
            return "retry" if status.get("installed") is False else "unknown"
        if operation.active_step == "management_identity":
            return "done" if self.read_public_certificate(plan, auth) else "retry"
        if operation.active_step == "management_verified":
            return "retry"
        return "unknown"

    def reconcile_remove(
        self, plan: InstallPlan, operation: Operation, auth: SshPasswordChannel | None
    ) -> Literal["done", "retry", "unknown"]:
        if operation.active_step != "remote_uninstall":
            return "unknown"
        return "done" if self._uninstall_is_clean(plan, auth) else "retry"

    def _uninstall_is_clean(self, plan: InstallPlan, auth: SshPasswordChannel | None) -> bool:
        prefix = "sudo -n " if plan.use_sudo else ""
        verify = prefix + "python3 -c " + shlex.quote(_REMOTE_UNINSTALL_VERIFY)
        result = self._execute(plan.definition, verify, auth, timeout=15, stage="remote-uninstall-verify")
        status = json.loads(result.stdout)
        if not isinstance(status, dict) or type(status.get("clean")) is not bool:
            raise SshOperationError(
                "remote-uninstall-verify", "invalid remote cleanup status", outcome_unknown=True
            )
        return status["clean"]

    @staticmethod
    def remote_command_for(plan: InstallPlan, action: str) -> str:
        prefix = "sudo -n " if plan.use_sudo else ""
        python = "/opt/hydra/.venv/bin/python"
        if action == "uninstall":
            return f"{prefix}/usr/local/bin/hydra uninstall --yes"
        if action == "provision":
            return f"{prefix}{python} -m hydra.entrypoints.managed_node --provision"
        if action == "read-certificate":
            return f"{prefix}{python} -m hydra.entrypoints.managed_node --read-public-certificate"
        if action == "remove-firewall":
            return f"{prefix}{python} -m hydra.entrypoints.managed_node --remove-firewall"
        raise ValueError("unsupported fixed managed-node SSH action")

    def _remove_management_firewall_if_present(
        self,
        plan: InstallPlan,
        auth: SshPasswordChannel | None,
    ) -> None:
        probe = self._execute(
            plan.definition,
            "test -f /opt/hydra/hydra/entrypoints/managed_node.py",
            auth,
            timeout=10,
            stage="management-firewall-probe",
            allow_failure=True,
        )
        if probe.returncode != 0:
            return
        self._execute(
            plan.definition,
            self.remote_command_for(plan, "remove-firewall"),
            auth,
            timeout=20,
            stage="management-firewall-cleanup",
        )

    def _installation_present(self, definition: NodeDefinition, auth: SshPasswordChannel | None) -> bool:
        result = self._execute(
            definition,
            "python3 -c " + shlex.quote(_REMOTE_FACTS),
            auth,
            timeout=15,
            stage="operation-reconcile",
            allow_failure=True,
        )
        if result.returncode != 0:
            raise SshOperationError(
                "operation-reconcile", "could not inspect HYDRA-owned installation", outcome_unknown=True
            )
        return bool(json.loads(result.stdout).get("existing"))

    def _pin_host_key(self, node_id: str, address: str, port: int, expected: str) -> str:
        self._host.ensure_directory(self._known_hosts_root, mode=0o700)
        known_hosts = self._known_hosts_root / node_id
        if known_hosts.is_symlink():
            raise SshOperationError("host-key", "known_hosts file is unsafe", outcome_unknown=False)
        scan = self._host.run(["ssh-keyscan", "-p", str(port), "-t", "ed25519,rsa", address], timeout=15, text=True)
        lines = [line for line in scan.stdout.splitlines() if line and not line.startswith("#")]
        if scan.returncode != 0 or not lines:
            raise SshOperationError("host-key", "SSH host key scan failed", outcome_unknown=False)
        fingerprints = self._fingerprints(lines)
        if expected not in fingerprints:
            raise SshOperationError(
                "host-key", "scanned SSH host key does not match the operator fingerprint", outcome_unknown=False
            )
        if known_hosts.exists():
            existing = self._host.read_bytes(known_hosts, max_bytes=64 * 1024).decode("ascii", "strict").splitlines()
            if expected not in self._fingerprints(existing):
                raise SshOperationError(
                    "host-key",
                    "stored known_hosts identity changed; explicit re-pinning is required",
                    outcome_unknown=False,
                )
        matching = [line for line in lines if self._fingerprints([line]) == {expected}]
        if not matching:
            raise SshOperationError("host-key", "pinned SSH host key is unavailable", outcome_unknown=False)
        self._host.atomic_write(known_hosts, "\n".join(matching) + "\n", mode=0o600, durable=True)
        return expected

    def _fingerprints(self, lines: list[str]) -> set[str]:
        if not lines or any(len(line.split()) != 3 for line in lines):
            raise SshOperationError("host-key", "SSH host key scan has an invalid shape", outcome_unknown=False)
        result = self._host.run(["ssh-keygen", "-lf", "-"], timeout=10, text=True, input="\n".join(lines) + "\n")
        values = set(re.findall(r"SHA256:[A-Za-z0-9+/]{43}", result.stdout))
        if result.returncode != 0 or not values:
            raise SshOperationError("host-key", "SSH fingerprint could not be verified", outcome_unknown=False)
        return values

    def _execute(
        self,
        definition: NodeDefinition,
        remote_command: str,
        auth: SshPasswordChannel | None,
        *,
        timeout: float,
        stage: str,
        input: bytes | None = None,
        allow_failure: bool = False,
    ):
        known_hosts = self._known_hosts_root / definition.id
        args = [
            "ssh",
            "-p",
            str(definition.ssh_port),
            "-l",
            definition.ssh_user,
            "-oStrictHostKeyChecking=yes",
            f"-oUserKnownHostsFile={known_hosts}",
            "-oGlobalKnownHostsFile=/dev/null",
            "-oIdentitiesOnly=yes",
            "-oConnectTimeout=10",
            "-oConnectionAttempts=1",
            "-oNumberOfPasswordPrompts=1",
            "-oLogLevel=ERROR",
            "-oBatchMode=no" if auth is not None else "-oBatchMode=yes",
            definition.address,
            remote_command,
        ]
        environment = auth.environment() if auth is not None else None
        try:
            result = self._host.run(args, timeout=timeout, input=input, env=environment, text=False)
        except Exception as exc:
            raise SshOperationError(
                stage, _safe(exc), outcome_unknown=stage not in {"ssh-preflight", "host-key"}
            ) from exc
        if result.returncode != 0 and not allow_failure:
            raise SshOperationError(
                stage,
                bounded_reason(result) or "SSH operation failed",
                outcome_unknown=stage not in {"ssh-preflight", "host-key"},
            )
        return result


def _parse_listening_ports(output: str | bytes) -> set[int]:
    if isinstance(output, bytes):
        output = output.decode("utf-8", "strict")
    ports: set[int] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5:
            raise ValueError("ss output is incomplete")
        endpoint = fields[4]
        match = _PORT.search(endpoint)
        if match is None:
            raise ValueError("ss returned an invalid local endpoint")
        port = int(match.group(1))
        if not 1 <= port <= 65535:
            raise ValueError("ss returned an invalid listening port")
        ports.add(port)
    return ports


def _safe(value: object) -> str:
    text = redact_text(str(value))
    return "".join(char for char in text if char.isprintable())[:160] or "SSH operation failed"


__all__ = ["ManagedNodeSSH", "OpenSshManagedNodeSSH", "SshFacts", "SshOperationError"]
