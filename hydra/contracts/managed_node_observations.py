"""Status, diagnostics, profiles, traffic and sync DTOs for managed nodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING
from urllib.parse import urlsplit

from hydra.contracts.managed_node_common import (
    _OUTCOMES,
    _digest,
    _identifier,
    _integer,
    _mapping,
    _text,
    _unique,
    canonical_digest,
)

if TYPE_CHECKING:
    from hydra.contracts.managed_node_models import ApplyReceipt, NodeDefinition, Operation


@dataclass(frozen=True)
class CheckResult:
    kind: str
    target_id: str
    outcome: str
    checked_at: str | None = None
    duration_ms: int | None = None
    stage: str = ""
    reason: str = ""

    def validate(self) -> None:
        _identifier(self.kind, "check.kind")
        _identifier(self.target_id, "check.target_id")
        if self.outcome not in _OUTCOMES:
            raise ValueError("check.outcome is invalid")
        if self.checked_at is not None:
            _text(self.checked_at, "check.checked_at", maximum=64)
        if self.duration_ms is not None:
            _integer(self.duration_ms, "check.duration_ms")
        _text(self.stage, "check.stage", maximum=64, empty=True)
        _text(self.reason, "check.reason", maximum=256, empty=True)

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "kind": self.kind,
            "target_id": self.target_id,
            "outcome": self.outcome,
            "checked_at": self.checked_at,
            "duration_ms": self.duration_ms,
            "stage": self.stage,
            "reason": self.reason,
        }

    @classmethod
    def from_document(cls, raw: object) -> "CheckResult":
        keys = {"kind", "target_id", "outcome", "checked_at", "duration_ms", "stage", "reason"}
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("check result has an invalid shape")
        item = cls(**raw)
        item.validate()
        return item


@dataclass(frozen=True)
class TrafficSample:
    """Cumulative context bytes; counter_epoch identifies a raw-counter lifecycle only."""

    uuid: str
    context_id: str
    kind: str
    reset_epoch: int
    counter_epoch: str
    used_bytes: int

    def validate(self) -> None:
        _identifier(self.uuid, "traffic.uuid")
        _identifier(self.context_id, "traffic.context_id")
        if self.kind not in {"direct", "cascade_entry", "transit", "probe"}:
            raise ValueError("traffic.kind is invalid")
        _integer(self.reset_epoch, "traffic.reset_epoch")
        _identifier(self.counter_epoch, "traffic.counter_epoch")
        _integer(self.used_bytes, "traffic.used_bytes")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "uuid": self.uuid,
            "context_id": self.context_id,
            "kind": self.kind,
            "reset_epoch": self.reset_epoch,
            "counter_epoch": self.counter_epoch,
            "used_bytes": self.used_bytes,
        }

    @classmethod
    def from_document(cls, raw: object) -> "TrafficSample":
        keys = {"uuid", "context_id", "kind", "reset_epoch", "counter_epoch", "used_bytes"}
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("traffic sample has an invalid shape")
        item = cls(**raw)
        item.validate()
        return item


@dataclass(frozen=True)
class NodeSample:
    node_id: str
    receipt: ApplyReceipt | None = None
    runtime: dict[str, Any] = field(default_factory=dict)
    users_applied: int | None = None
    users_digest: str | None = None
    metrics: dict[str, float | int | None] = field(default_factory=dict)
    traffic: list[TrafficSample] = field(default_factory=list)

    def validate(self) -> None:
        from hydra.contracts.managed_node_models import ApplyReceipt

        _identifier(self.node_id, "sample.node_id")
        if self.receipt is not None:
            if not isinstance(self.receipt, ApplyReceipt):
                raise ValueError("sample.receipt has an invalid shape")
            self.receipt.validate()
        _mapping(self.runtime, "sample.runtime")
        if self.users_applied is not None:
            _integer(self.users_applied, "sample.users_applied")
        if self.users_digest is not None:
            _digest(self.users_digest, "sample.users_digest")
        _mapping(self.metrics, "sample.metrics")
        if any(
            value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)))
            for value in self.metrics.values()
        ):
            raise ValueError("sample.metrics values must be numeric or unknown")
        if not isinstance(self.traffic, list) or any(not isinstance(item, TrafficSample) for item in self.traffic):
            raise ValueError("sample.traffic must be a list")
        for sample in self.traffic:
            sample.validate()

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "node_id": self.node_id,
            "receipt": self.receipt.to_document() if self.receipt else None,
            "runtime": self.runtime,
            "users_applied": self.users_applied,
            "users_digest": self.users_digest,
            "metrics": self.metrics,
            "traffic": [item.to_document() for item in self.traffic],
        }

    @classmethod
    def from_document(cls, raw: object) -> "NodeSample":
        from hydra.contracts.managed_node_models import ApplyReceipt

        keys = {"node_id", "receipt", "runtime", "users_applied", "users_digest", "metrics", "traffic"}
        if not isinstance(raw, dict) or set(raw) != keys or not isinstance(raw["traffic"], list):
            raise ValueError("node sample has an invalid shape")
        item = cls(
            raw["node_id"],
            ApplyReceipt.from_document(raw["receipt"]) if raw["receipt"] else None,
            raw["runtime"],
            raw["users_applied"],
            raw["users_digest"],
            raw["metrics"],
            [TrafficSample.from_document(value) for value in raw["traffic"]],
        )
        item.validate()
        return item


@dataclass(frozen=True)
class ConfirmedProfile:
    stable_id: str
    user_uuid: str
    protocol: str
    route_id: str
    links: list[str] = field(default_factory=list)
    client_configs: list[dict[str, Any]] = field(default_factory=list)

    def validate(self) -> None:
        for path, value in (
            ("stable_id", self.stable_id),
            ("user_uuid", self.user_uuid),
            ("protocol", self.protocol),
            ("route_id", self.route_id),
        ):
            _identifier(value, f"profile.{path}")
        if not isinstance(self.links, list):
            raise ValueError("profile.links is invalid")
        for link in self.links:
            if (
                not isinstance(link, str)
                or len(link) > 8192
                or link != link.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in link)
            ):
                raise ValueError("profile.links is invalid")
            try:
                scheme = urlsplit(link).scheme
            except ValueError as exc:
                raise ValueError("profile.links must be absolute URIs") from exc
            if not scheme:
                raise ValueError("profile.links must be absolute URIs")
        if not isinstance(self.client_configs, list) or any(
            not isinstance(config, dict) for config in self.client_configs
        ):
            raise ValueError("profile.client_configs is invalid")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "stable_id": self.stable_id,
            "user_uuid": self.user_uuid,
            "protocol": self.protocol,
            "route_id": self.route_id,
            "links": list(self.links),
            "client_configs": self.client_configs,
        }

    @classmethod
    def from_document(cls, raw: object) -> "ConfirmedProfile":
        keys = {"stable_id", "user_uuid", "protocol", "route_id", "links", "client_configs"}
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("confirmed profile has an invalid shape")
        item = cls(**raw)
        item.validate()
        return item


@dataclass(frozen=True)
class ConfirmedProfiles:
    node_id: str
    receipt: ApplyReceipt
    profiles: list[ConfirmedProfile]
    sha256: str

    def validate(self) -> None:
        from hydra.contracts.managed_node_models import ApplyReceipt

        _identifier(self.node_id, "profiles.node_id")
        if not isinstance(self.receipt, ApplyReceipt):
            raise ValueError("profiles.receipt has an invalid shape")
        self.receipt.validate()
        if not isinstance(self.profiles, list) or any(not isinstance(item, ConfirmedProfile) for item in self.profiles):
            raise ValueError("profiles.profiles is invalid")
        for item in self.profiles:
            item.validate()
        _unique([item.stable_id for item in self.profiles], "profiles.profiles")
        _digest(self.sha256, "profiles.sha256")
        if canonical_digest([item.to_document() for item in self.profiles]) != self.sha256:
            raise ValueError("profiles.sha256 does not match the profile bundle")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "node_id": self.node_id,
            "receipt": self.receipt.to_document(),
            "profiles": [item.to_document() for item in self.profiles],
            "sha256": self.sha256,
        }

    @classmethod
    def from_document(cls, raw: object) -> "ConfirmedProfiles":
        from hydra.contracts.managed_node_models import ApplyReceipt

        keys = {"node_id", "receipt", "profiles", "sha256"}
        if not isinstance(raw, dict) or set(raw) != keys or not isinstance(raw["profiles"], list):
            raise ValueError("confirmed profiles have an invalid shape")
        item = cls(
            raw["node_id"],
            ApplyReceipt.from_document(raw["receipt"]),
            [ConfirmedProfile.from_document(value) for value in raw["profiles"]],
            raw["sha256"],
        )
        item.validate()
        return item


@dataclass(frozen=True)
class NodeView:
    definition: NodeDefinition
    management_check: CheckResult | None = None
    users_applied: int | None = None
    users_total: int | None = None
    sub_state: str = "unknown"
    runtime: dict[str, Any] | None = None
    protocol_checks: dict[str, CheckResult] = field(default_factory=dict)
    metrics: dict[str, float | int | None] = field(default_factory=dict)
    operation: Operation | None = None

    def validate(self) -> None:
        from hydra.contracts.managed_node_models import NodeDefinition, Operation

        if not isinstance(self.definition, NodeDefinition):
            raise ValueError("view.definition has an invalid shape")
        self.definition.validate()
        for result in ([self.management_check] if self.management_check else []) + list(self.protocol_checks.values()):
            if not isinstance(result, CheckResult):
                raise ValueError("view check result has an invalid shape")
            result.validate()
        for value in (self.users_applied, self.users_total):
            if value is not None:
                _integer(value, "view.user_count")
        if self.sub_state not in {"unknown", "sync", "wait", "error"}:
            raise ValueError("view.sub_state is invalid")
        if self.runtime is not None:
            _mapping(self.runtime, "view.runtime")
        if self.operation is not None:
            if not isinstance(self.operation, Operation):
                raise ValueError("view.operation has an invalid shape")
            self.operation.validate()
        _mapping(self.metrics, "view.metrics")


@dataclass(frozen=True)
class DiagnosticReport:
    management: CheckResult
    runtime: CheckResult
    users: CheckResult
    subscription: CheckResult
    protocols: dict[str, dict[str, CheckResult]]


@dataclass(frozen=True)
class SyncReport:
    nodes: dict[str, dict[str, Any]]
    local: str = "ok"
    errors: list[str] = field(default_factory=list)
    pending_operations: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProtocolOption:
    name: str
    supported: bool
    reason: str = ""

    def validate(self) -> None:
        _identifier(self.name, "protocol_option.name")
        if type(self.supported) is not bool:
            raise ValueError("protocol_option.supported must be a boolean")
        _text(self.reason, "protocol_option.reason", maximum=256, empty=True)


__all__ = [
    "CheckResult",
    "ConfirmedProfile",
    "ConfirmedProfiles",
    "DiagnosticReport",
    "NodeSample",
    "NodeView",
    "ProtocolOption",
    "SyncReport",
    "TrafficSample",
]
