"""Dependency-neutral wire and operation contracts for managed nodes v1."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from hydra.contracts.managed_node_common import (
    _ID,
    _OPERATION_STATES,
    _SHA1,
    _SHA256,
    _digest,
    _identifier,
    _integer,
    _mapping,
    _reference,
    _reject_secret_fields,
    _text,
    _unique,
    canonical_digest,
)

MANAGED_NODE_API_VERSION = 1


@dataclass(frozen=True)
class ProtocolAssignment:
    name: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        _identifier(self.name, "protocol.name")
        _mapping(self.parameters, f"protocols.{self.name}.parameters")
        _reject_secret_fields(self.parameters, f"protocols.{self.name}.parameters")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {"name": self.name, "parameters": self.parameters}

    @classmethod
    def from_document(cls, raw: object) -> "ProtocolAssignment":
        if not isinstance(raw, dict) or set(raw) != {"name", "parameters"}:
            raise ValueError("protocol assignment has an invalid shape")
        item = cls(raw["name"], _mapping(raw["parameters"], "protocol.parameters"))
        item.validate()
        return item


@dataclass(frozen=True)
class NodeDefinition:
    id: str
    name: str
    address: str
    ssh_user: str
    branch: str
    revision: str
    control_port: int
    protocols: list[ProtocolAssignment]
    identity_ref: str
    ssh_port: int = 22

    def validate(self) -> None:
        _identifier(self.id, "definition.id")
        if self.id == "base":
            raise ValueError("definition.id 'base' is reserved for the main server")
        _text(self.name, "definition.name", maximum=128)
        _text(self.ssh_user, "definition.ssh_user", maximum=64)
        try:
            ipaddress.ip_address(self.address)
        except (TypeError, ValueError) as exc:
            raise ValueError("definition.address must be an IPv4 or IPv6 address") from exc
        _integer(self.ssh_port, "definition.ssh_port", 1, 65535)
        _integer(self.control_port, "definition.control_port", 1024, 65535)
        if self.control_port == self.ssh_port:
            raise ValueError("definition.control_port must differ from ssh_port")
        if self.branch not in {"main", "dev"}:
            raise ValueError("definition.branch must be main or dev")
        if not isinstance(self.revision, str) or not _SHA1.fullmatch(self.revision):
            raise ValueError("definition.revision must be a full source commit SHA-1")
        _reference(self.identity_ref, "definition.identity_ref")
        if not isinstance(self.protocols, list) or any(
            not isinstance(item, ProtocolAssignment) for item in self.protocols
        ):
            raise ValueError("definition.protocols must be a list of protocol assignments")
        for item in self.protocols:
            item.validate()
        _unique([item.name for item in self.protocols], "definition.protocols")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "id": self.id,
            "name": self.name,
            "address": self.address,
            "ssh_user": self.ssh_user,
            "ssh_port": self.ssh_port,
            "branch": self.branch,
            "revision": self.revision,
            "control_port": self.control_port,
            "protocols": [item.to_document() for item in self.protocols],
            "identity_ref": self.identity_ref,
        }

    @classmethod
    def from_document(cls, raw: object) -> "NodeDefinition":
        keys = {
            "id",
            "name",
            "address",
            "ssh_user",
            "ssh_port",
            "branch",
            "revision",
            "control_port",
            "protocols",
            "identity_ref",
        }
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("node definition has an invalid shape")
        if not isinstance(raw["protocols"], list):
            raise ValueError("definition.protocols must be a list")
        item = cls(
            raw["id"],
            raw["name"],
            raw["address"],
            raw["ssh_user"],
            raw["branch"],
            raw["revision"],
            raw["control_port"],
            [ProtocolAssignment.from_document(value) for value in raw["protocols"]],
            raw["identity_ref"],
            raw["ssh_port"],
        )
        item.validate()
        return item


@dataclass(frozen=True)
class UserAssignment:
    uuid: str
    email: str
    blocked: bool = False
    expiry_date: str = ""
    traffic_limit_gb: float = 0
    disabled_protocols: list[str] = field(default_factory=list)
    reset_epoch: int = 0

    def validate(self) -> None:
        _identifier(self.uuid, "user.uuid")
        _text(self.email, "user.email", maximum=254)
        if type(self.blocked) is not bool:
            raise ValueError("user.blocked must be a boolean")
        if not isinstance(self.expiry_date, str):
            raise ValueError("user.expiry_date must be an ISO date or datetime string")
        if self.expiry_date:
            value = self.expiry_date[:-1] + "+00:00" if self.expiry_date.endswith("Z") else self.expiry_date
            try:
                date.fromisoformat(self.expiry_date)
            except ValueError:
                try:
                    datetime.fromisoformat(value)
                except (TypeError, ValueError) as exc:
                    raise ValueError("user.expiry_date must be an ISO date or datetime string") from exc
        if (
            isinstance(self.traffic_limit_gb, bool)
            or not isinstance(self.traffic_limit_gb, (float, int))
            or self.traffic_limit_gb < 0
        ):
            raise ValueError("user.traffic_limit_gb must be non-negative")
        _integer(self.reset_epoch, "user.reset_epoch")
        if not isinstance(self.disabled_protocols, list) or any(
            not isinstance(name, str) or not name for name in self.disabled_protocols
        ):
            raise ValueError("user.disabled_protocols must be a list of protocol names")
        _unique(self.disabled_protocols, "user.disabled_protocols")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "uuid": self.uuid,
            "email": self.email,
            "blocked": self.blocked,
            "expiry_date": self.expiry_date,
            "traffic_limit_gb": self.traffic_limit_gb,
            "disabled_protocols": list(self.disabled_protocols),
            "reset_epoch": self.reset_epoch,
        }

    @classmethod
    def from_document(cls, raw: object) -> "UserAssignment":
        keys = {"uuid", "email", "blocked", "expiry_date", "traffic_limit_gb", "disabled_protocols", "reset_epoch"}
        if not isinstance(raw, dict) or set(raw) != keys or not isinstance(raw["disabled_protocols"], list):
            raise ValueError("user assignment has an invalid shape")
        item = cls(
            raw["uuid"],
            raw["email"],
            raw["blocked"],
            raw["expiry_date"],
            raw["traffic_limit_gb"],
            raw["disabled_protocols"],
            raw["reset_epoch"],
        )
        item.validate()
        return item


@dataclass(frozen=True)
class CascadeDefinition:
    id: str
    name: str
    entry_id: str
    exit_id: str
    protocols: list[str]

    def validate(self) -> None:
        for name, value in (("id", self.id), ("entry_id", self.entry_id), ("exit_id", self.exit_id)):
            _identifier(value, f"cascade.{name}")
        _text(self.name, "cascade.name", maximum=128)
        if self.entry_id == self.exit_id:
            raise ValueError("cascade participants must be different")
        if not isinstance(self.protocols, list) or any(
            not isinstance(item, str) or not item for item in self.protocols
        ):
            raise ValueError("cascade.protocols must be a list")
        _unique(self.protocols, "cascade.protocols")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "id": self.id,
            "name": self.name,
            "entry_id": self.entry_id,
            "exit_id": self.exit_id,
            "protocols": list(self.protocols),
        }

    @classmethod
    def from_document(cls, raw: object) -> "CascadeDefinition":
        keys = {"id", "name", "entry_id", "exit_id", "protocols"}
        if not isinstance(raw, dict) or set(raw) != keys or not isinstance(raw["protocols"], list):
            raise ValueError("cascade definition has an invalid shape")
        item = cls(raw["id"], raw["name"], raw["entry_id"], raw["exit_id"], raw["protocols"])
        item.validate()
        return item


@dataclass(frozen=True)
class NodeDesired:
    node_id: str
    revision: int
    users: list[UserAssignment]
    protocols: list[ProtocolAssignment]
    cascades: list[CascadeDefinition] = field(default_factory=list)

    def validate(self) -> None:
        _identifier(self.node_id, "desired.node_id")
        _integer(self.revision, "desired.revision")
        for label, values, expected in (
            ("users", self.users, UserAssignment),
            ("protocols", self.protocols, ProtocolAssignment),
            ("cascades", self.cascades, CascadeDefinition),
        ):
            if not isinstance(values, list) or any(not isinstance(item, expected) for item in values):
                raise ValueError(f"desired.{label} has an invalid shape")
            for item in values:
                item.validate()
        _unique([item.uuid for item in self.users], "desired.users")
        _unique([item.name for item in self.protocols], "desired.protocols")
        _unique([item.id for item in self.cascades], "desired.cascades")

    @property
    def users_digest(self) -> str:
        return canonical_digest([user.to_document() for user in sorted(self.users, key=lambda value: value.uuid)])

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_document())

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "node_id": self.node_id,
            "revision": self.revision,
            "users": [item.to_document() for item in self.users],
            "protocols": [item.to_document() for item in self.protocols],
            "cascades": [item.to_document() for item in self.cascades],
        }

    @classmethod
    def from_document(cls, raw: object) -> "NodeDesired":
        keys = {"node_id", "revision", "users", "protocols", "cascades"}
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("node desired document has an invalid shape")
        if any(not isinstance(raw[key], list) for key in ("users", "protocols", "cascades")):
            raise ValueError("node desired collections must be lists")
        item = cls(
            raw["node_id"],
            raw["revision"],
            [UserAssignment.from_document(value) for value in raw["users"]],
            [ProtocolAssignment.from_document(value) for value in raw["protocols"]],
            [CascadeDefinition.from_document(value) for value in raw["cascades"]],
        )
        item.validate()
        return item


@dataclass(frozen=True)
class ApplyReceipt:
    operation_id: str
    desired_revision: int
    desired_digest: str
    runtime_id: str
    users_digest: str
    profiles_digest: str

    def validate(self) -> None:
        _identifier(self.operation_id, "receipt.operation_id")
        _integer(self.desired_revision, "receipt.desired_revision")
        _digest(self.desired_digest, "receipt.desired_digest")
        _identifier(self.runtime_id, "receipt.runtime_id")
        _digest(self.users_digest, "receipt.users_digest")
        _digest(self.profiles_digest, "receipt.profiles_digest")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "operation_id": self.operation_id,
            "desired_revision": self.desired_revision,
            "desired_digest": self.desired_digest,
            "runtime_id": self.runtime_id,
            "users_digest": self.users_digest,
            "profiles_digest": self.profiles_digest,
        }

    @classmethod
    def from_document(cls, raw: object) -> "ApplyReceipt":
        keys = {"operation_id", "desired_revision", "desired_digest", "runtime_id", "users_digest", "profiles_digest"}
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("apply receipt has an invalid shape")
        item = cls(**raw)
        item.validate()
        return item


@dataclass(frozen=True)
class Operation:
    id: str
    kind: str
    target_id: str
    desired_digest: str
    state: str
    completed_steps: list[str] = field(default_factory=list)
    error: dict[str, str] | None = None
    receipt: ApplyReceipt | None = None
    plan: dict[str, Any] | None = None
    remote_removal_confirmed: bool = False
    active_step: str | None = None
    existing_reinstall_confirmed: bool = False

    def validate(self) -> None:
        _identifier(self.id, "operation.id")
        _identifier(self.kind, "operation.kind")
        _identifier(self.target_id, "operation.target_id")
        _digest(self.desired_digest, "operation.desired_digest")
        if self.state not in _OPERATION_STATES:
            raise ValueError("operation.state is invalid")
        if not isinstance(self.completed_steps, list) or any(
            not isinstance(step, str) or not _ID.fullmatch(step) for step in self.completed_steps
        ):
            raise ValueError("operation.completed_steps is invalid")
        _unique(self.completed_steps, "operation.completed_steps")
        if type(self.remote_removal_confirmed) is not bool or type(self.existing_reinstall_confirmed) is not bool:
            raise ValueError("operation confirmation fields must be booleans")
        if self.active_step is not None:
            _identifier(self.active_step, "operation.active_step")
        if self.error is not None:
            error = _mapping(self.error, "operation.error")
            _reject_secret_fields(error, "operation.error")
            if set(error) - {"stage", "reason", "rollback_reason"}:
                raise ValueError("operation.error has unsupported fields")
            for name, value in error.items():
                _text(value, f"operation.error.{name}", maximum=256, empty=True)
        if self.receipt is not None:
            self.receipt.validate()
        if self.plan is not None:
            _mapping(self.plan, "operation.plan")
            _reject_secret_fields(self.plan, "operation.plan")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "id": self.id,
            "kind": self.kind,
            "target_id": self.target_id,
            "desired_digest": self.desired_digest,
            "state": self.state,
            "completed_steps": list(self.completed_steps),
            "error": self.error,
            "receipt": self.receipt.to_document() if self.receipt else None,
            "plan": self.plan,
            "remote_removal_confirmed": self.remote_removal_confirmed,
            "active_step": self.active_step,
            "existing_reinstall_confirmed": self.existing_reinstall_confirmed,
        }

    @classmethod
    def from_document(cls, raw: object) -> "Operation":
        keys = {
            "id",
            "kind",
            "target_id",
            "desired_digest",
            "state",
            "completed_steps",
            "error",
            "receipt",
            "plan",
            "remote_removal_confirmed",
            "active_step",
            "existing_reinstall_confirmed",
        }
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("operation has an invalid shape")
        receipt = ApplyReceipt.from_document(raw["receipt"]) if raw["receipt"] is not None else None
        item = cls(
            raw["id"],
            raw["kind"],
            raw["target_id"],
            raw["desired_digest"],
            raw["state"],
            raw["completed_steps"],
            raw["error"],
            receipt,
            raw["plan"],
            raw["remote_removal_confirmed"],
            raw["active_step"],
            raw["existing_reinstall_confirmed"],
        )
        item.validate()
        return item


__all__ = [
    "MANAGED_NODE_API_VERSION",
    "ApplyReceipt",
    "CascadeDefinition",
    "NodeDefinition",
    "NodeDesired",
    "Operation",
    "ProtocolAssignment",
    "UserAssignment",
    "canonical_digest",
]
