"""Typed, operation-bound participant messages for managed-node cascades."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from hydra.contracts.managed_node_models import CascadeDefinition, canonical_digest
from hydra.contracts.managed_node_probe import ProbeMaterial

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROTOCOLS = frozenset({"vless", "anytls"})


@dataclass(frozen=True, repr=False)
class CascadeParticipantRequest:
    operation_id: str
    kind: str
    target_id: str
    plan_digest: str
    plan: dict[str, Any] = field(repr=False)
    participant_id: str
    role: str
    route: CascadeDefinition
    protocol: str

    def validate(self) -> None:
        if not isinstance(self.operation_id, str) or not _ID.fullmatch(self.operation_id):
            raise ValueError("cascade participant operation id is invalid")
        if self.kind not in {"cascade_save", "cascade_remove"}:
            raise ValueError("cascade participant operation kind is invalid")
        if not isinstance(self.target_id, str) or not _ID.fullmatch(self.target_id):
            raise ValueError("cascade participant target is invalid")
        if not isinstance(self.plan_digest, str) or not _SHA256.fullmatch(self.plan_digest):
            raise ValueError("cascade participant plan digest is invalid")
        if not isinstance(self.plan, dict) or set(self.plan) != {"cascade_id", "previous", "cascade"}:
            raise ValueError("cascade participant plan has an invalid shape")
        if canonical_digest(self.plan) != self.plan_digest or self.plan["cascade_id"] != self.target_id:
            raise ValueError("cascade participant plan binding is invalid")
        previous = self.plan["previous"]
        candidate = self.plan["cascade"]
        if self.kind == "cascade_save" and candidate is None:
            raise ValueError("cascade save plan has no candidate")
        if self.kind == "cascade_remove" and candidate is not None:
            raise ValueError("cascade removal plan has a candidate")
        routes = [CascadeDefinition.from_document(item) for item in (previous, candidate) if item is not None]
        if not routes or any(route.id != self.target_id for route in routes):
            raise ValueError("cascade participant plan has no matching route")
        if not isinstance(self.participant_id, str) or not _ID.fullmatch(self.participant_id):
            raise ValueError("cascade participant receiver identity is invalid")
        if self.participant_id not in {item for route in routes for item in (route.entry_id, route.exit_id)}:
            raise ValueError("cascade participant is outside the frozen topology")
        self.route.validate()
        if self.route not in routes:
            raise ValueError("cascade participant route is outside the immutable plan")
        expected_role = "entry" if self.participant_id == self.route.entry_id else "transit"
        if self.role != expected_role:
            raise ValueError("cascade participant role does not match its route")
        if (
            not isinstance(self.protocol, str)
            or self.protocol not in _PROTOCOLS
            or self.protocol not in self.route.protocols
        ):
            raise ValueError("cascade participant protocol does not match its route")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "operation_id": self.operation_id,
            "kind": self.kind,
            "target_id": self.target_id,
            "plan_digest": self.plan_digest,
            "plan": self.plan,
            "participant_id": self.participant_id,
            "role": self.role,
            "route": self.route.to_document(),
            "protocol": self.protocol,
        }

    @classmethod
    def from_document(cls, raw: object) -> "CascadeParticipantRequest":
        keys = {
            "operation_id",
            "kind",
            "target_id",
            "plan_digest",
            "plan",
            "participant_id",
            "role",
            "route",
            "protocol",
        }
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("cascade participant request has an invalid shape")
        value = cls(
            raw["operation_id"],
            raw["kind"],
            raw["target_id"],
            raw["plan_digest"],
            raw["plan"],
            raw["participant_id"],
            raw["role"],
            CascadeDefinition.from_document(raw["route"]),
            raw["protocol"],
        )
        value.validate()
        return value

    def __repr__(self) -> str:
        return "CascadeParticipantRequest(<protected>)"


@dataclass(frozen=True, repr=False)
class CascadeParticipantReceipt:
    operation_id: str
    plan_digest: str
    cascade_id: str
    participant_id: str
    role: str
    protocol: str
    state: str
    engine_identity: str
    config_identity: str
    material_digest: str | None = None

    def validate_for(self, request: CascadeParticipantRequest) -> None:
        request.validate()
        if (
            self.operation_id != request.operation_id
            or self.plan_digest != request.plan_digest
            or self.cascade_id != request.target_id
            or self.participant_id != request.participant_id
            or self.role != request.role
            or self.protocol != request.protocol
            or self.state
            not in {"snapshotted", "prepared", "applied", "rolling_back", "rolled_back", "finalized", "unknown"}
        ):
            raise ValueError("cascade participant receipt is bound to another request")
        for value in (self.engine_identity, self.config_identity):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ValueError("cascade participant receipt context is invalid")
        if self.material_digest is not None and (
            not isinstance(self.material_digest, str) or not _SHA256.fullmatch(self.material_digest)
        ):
            raise ValueError("cascade participant material digest is invalid")
        if request.role == "transit" and self.state == "prepared" and self.material_digest is None:
            raise ValueError("prepared transit receipt has no protected material digest")

    def to_document(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "plan_digest": self.plan_digest,
            "cascade_id": self.cascade_id,
            "participant_id": self.participant_id,
            "role": self.role,
            "protocol": self.protocol,
            "state": self.state,
            "engine_identity": self.engine_identity,
            "config_identity": self.config_identity,
            "material_digest": self.material_digest,
        }

    @classmethod
    def from_document(cls, raw: object) -> "CascadeParticipantReceipt":
        keys = {
            "operation_id",
            "plan_digest",
            "cascade_id",
            "participant_id",
            "role",
            "protocol",
            "state",
            "engine_identity",
            "config_identity",
            "material_digest",
        }
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("cascade participant receipt has an invalid shape")
        return cls(**raw)

    def __repr__(self) -> str:
        return "CascadeParticipantReceipt(<protected>)"


@dataclass(frozen=True, repr=False)
class CascadeParticipantStatus:
    state: str
    receipt: CascadeParticipantReceipt | None = None

    def validate_for(self, request: CascadeParticipantRequest) -> None:
        if self.state not in {"not_applied", "applied", "unknown"}:
            raise ValueError("cascade participant status is invalid")
        if self.state == "applied":
            if self.receipt is None or self.receipt.state != "applied":
                raise ValueError("applied cascade participant status has no receipt")
            self.receipt.validate_for(request)
        elif self.receipt is not None:
            raise ValueError("non-applied cascade participant status has an unexpected receipt")

    def to_document(self) -> dict[str, Any]:
        return {"state": self.state, "receipt": self.receipt.to_document() if self.receipt else None}

    @classmethod
    def from_document(cls, raw: object) -> "CascadeParticipantStatus":
        if not isinstance(raw, dict) or set(raw) != {"state", "receipt"}:
            raise ValueError("cascade participant status has an invalid shape")
        receipt = CascadeParticipantReceipt.from_document(raw["receipt"]) if raw["receipt"] is not None else None
        return cls(raw["state"], receipt)

    def __repr__(self) -> str:
        return "CascadeParticipantStatus(<protected>)"


@dataclass(frozen=True, repr=False)
class CascadeTechnicalMaterial:
    receipt: CascadeParticipantReceipt
    outbound: dict[str, Any] = field(repr=False)

    def validate_for(self, request: CascadeParticipantRequest) -> None:
        self.receipt.validate_for(request)
        if request.role != "transit" or self.receipt.state != "prepared":
            raise ValueError("cascade technical material requires a prepared transit receipt")
        try:
            ProbeMaterial(request.protocol, self.outbound).validate()
        except (TypeError, ValueError) as exc:
            raise ValueError("cascade technical material is invalid") from exc
        if canonical_digest(self.outbound) != self.receipt.material_digest:
            raise ValueError("cascade technical material digest does not match its receipt")

    def to_document(self) -> dict[str, Any]:
        return {"receipt": self.receipt.to_document(), "outbound": self.outbound}

    @classmethod
    def from_document(cls, raw: object) -> "CascadeTechnicalMaterial":
        if not isinstance(raw, dict) or set(raw) != {"receipt", "outbound"} or not isinstance(raw["outbound"], dict):
            raise ValueError("cascade technical material has an invalid shape")
        return cls(CascadeParticipantReceipt.from_document(raw["receipt"]), raw["outbound"])

    def __repr__(self) -> str:
        return "CascadeTechnicalMaterial(<protected>)"


__all__ = ["CascadeParticipantReceipt", "CascadeParticipantRequest", "CascadeTechnicalMaterial"]
