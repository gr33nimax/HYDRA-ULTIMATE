"""Installation input and pinned execution-plan contracts."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from hydra.contracts.managed_node_common import _SSH_FINGERPRINT, _identifier, _integer, _text, _unique
from hydra.contracts.managed_node_models import NodeDefinition, ProtocolAssignment


@dataclass(frozen=True)
class InstallRequest:
    id: str
    name: str
    address: str
    ssh_user: str
    branch: str
    protocols: list[ProtocolAssignment]
    host_key_fingerprint: str
    control_port: int | None = None
    ssh_port: int = 22

    def validate(self) -> None:
        _identifier(self.id, "request.id")
        if self.id == "base":
            raise ValueError("request.id 'base' is reserved for the main server")
        _text(self.name, "request.name", maximum=128)
        _text(self.ssh_user, "request.ssh_user", maximum=64)
        try:
            ipaddress.ip_address(self.address)
        except (TypeError, ValueError) as exc:
            raise ValueError("request.address must be an IPv4 or IPv6 address") from exc
        _integer(self.ssh_port, "request.ssh_port", 1, 65535)
        if self.branch not in {"main", "dev"}:
            raise ValueError("request.branch must be main or dev")
        if self.control_port is not None:
            _integer(self.control_port, "request.control_port", 1024, 65535)
            if self.control_port == self.ssh_port:
                raise ValueError("request.control_port must differ from SSH")
        if not isinstance(self.host_key_fingerprint, str) or not _SSH_FINGERPRINT.fullmatch(self.host_key_fingerprint):
            raise ValueError("request.host_key_fingerprint must be an OpenSSH SHA256 fingerprint")
        if not isinstance(self.protocols, list) or any(
            not isinstance(item, ProtocolAssignment) for item in self.protocols
        ):
            raise ValueError("request.protocols must be a list")
        for protocol in self.protocols:
            protocol.validate()
        _unique([item.name for item in self.protocols], "request.protocols")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "id": self.id,
            "name": self.name,
            "address": self.address,
            "ssh_user": self.ssh_user,
            "ssh_port": self.ssh_port,
            "branch": self.branch,
            "protocols": [item.to_document() for item in self.protocols],
            "host_key_fingerprint": self.host_key_fingerprint,
            "control_port": self.control_port,
        }

    @classmethod
    def from_document(cls, raw: object) -> "InstallRequest":
        keys = {
            "id",
            "name",
            "address",
            "ssh_user",
            "ssh_port",
            "branch",
            "protocols",
            "host_key_fingerprint",
            "control_port",
        }
        if not isinstance(raw, dict) or set(raw) != keys or not isinstance(raw["protocols"], list):
            raise ValueError("installation request has an invalid shape")
        item = cls(
            raw["id"],
            raw["name"],
            raw["address"],
            raw["ssh_user"],
            raw["branch"],
            [ProtocolAssignment.from_document(value) for value in raw["protocols"]],
            raw["host_key_fingerprint"],
            raw["control_port"],
            raw["ssh_port"],
        )
        item.validate()
        return item

    def protocol_ports(self) -> set[int]:
        ports: set[int] = set()

        def visit(value: object, key: str = "") -> None:
            if isinstance(value, dict):
                for child_key, child in value.items():
                    visit(child, child_key)
            elif isinstance(value, list):
                for child in value:
                    visit(child, key)
            elif (key == "port" or key.endswith("_port")) and type(value) is int and 1 <= value <= 65535:
                ports.add(value)

        for protocol in self.protocols:
            visit(protocol.parameters)
        return ports


@dataclass(frozen=True)
class InstallPlan:
    definition: NodeDefinition
    existing_installation: bool | None
    steps: list[str]
    warnings: list[str] = field(default_factory=list)
    host_key_fingerprint: str = ""
    source_address: str = ""
    use_sudo: bool = False

    def validate(self) -> None:
        self.definition.validate()
        if self.existing_installation is not None and type(self.existing_installation) is not bool:
            raise ValueError("plan.existing_installation must be a boolean or unknown")
        if self.host_key_fingerprint and not _SSH_FINGERPRINT.fullmatch(self.host_key_fingerprint):
            raise ValueError("plan.host_key_fingerprint is invalid")
        if self.source_address:
            try:
                ipaddress.ip_address(self.source_address)
            except ValueError as exc:
                raise ValueError("plan.source_address must be an IP address") from exc
        if type(self.use_sudo) is not bool:
            raise ValueError("plan.use_sudo must be a boolean")
        for label, values in (("steps", self.steps), ("warnings", self.warnings)):
            if not isinstance(values, list):
                raise ValueError(f"plan.{label} must be a list")
            for index, value in enumerate(values):
                _text(value, f"plan.{label}[{index}]", maximum=256)

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "definition": self.definition.to_document(),
            "existing_installation": self.existing_installation,
            "steps": list(self.steps),
            "warnings": list(self.warnings),
            "host_key_fingerprint": self.host_key_fingerprint,
            "source_address": self.source_address,
            "use_sudo": self.use_sudo,
        }

    @classmethod
    def from_document(cls, raw: object) -> "InstallPlan":
        keys = {
            "definition",
            "existing_installation",
            "steps",
            "warnings",
            "host_key_fingerprint",
            "source_address",
            "use_sudo",
        }
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("installation plan has an invalid shape")
        item = cls(
            NodeDefinition.from_document(raw["definition"]),
            raw["existing_installation"],
            raw["steps"],
            raw["warnings"],
            raw["host_key_fingerprint"],
            raw["source_address"],
            raw["use_sudo"],
        )
        item.validate()
        return item


__all__ = ["InstallPlan", "InstallRequest"]
