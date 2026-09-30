"""Absolute per-user traffic counters reported by a managed node."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hydra.contracts.node_validation import (
    MAX_USERS_PER_SNAPSHOT,
    NODE_CONTRACT_VERSION,
    _count,
    _fail,
    _identifier,
    _mapping,
    _reject_unknown,
)


@dataclass(frozen=True)
class NodeTrafficUsage:
    """One node-local cumulative counter within a base-owned reset epoch."""

    reset_epoch: int
    used_bytes: int

    def validate(self) -> None:
        _count(self.reset_epoch, label="traffic.reset_epoch", limit=2**63 - 1)
        _count(self.used_bytes, label="traffic.used_bytes", limit=2**63 - 1)

    def to_document(self) -> dict[str, int]:
        self.validate()
        return {"reset_epoch": self.reset_epoch, "used_bytes": self.used_bytes}

    @classmethod
    def from_document(cls, raw: object) -> "NodeTrafficUsage":
        data = _mapping(raw, label="traffic usage")
        _reject_unknown(data, ("reset_epoch", "used_bytes"), label="traffic usage")
        if set(data) != {"reset_epoch", "used_bytes"}:
            raise _fail("traffic usage requires reset_epoch and used_bytes")
        usage = cls(
            reset_epoch=_count(data["reset_epoch"], label="traffic.reset_epoch", limit=2**63 - 1),
            used_bytes=_count(data["used_bytes"], label="traffic.used_bytes", limit=2**63 - 1),
        )
        usage.validate()
        return usage


@dataclass(frozen=True)
class NodeTrafficReport:
    """A restart-safe snapshot; repeated reports never add the same bytes twice."""

    node_id: str
    generation: int
    users: dict[str, NodeTrafficUsage] = field(default_factory=dict)
    contract_version: int = NODE_CONTRACT_VERSION

    def validate(self) -> None:
        _identifier(self.node_id, label="node_id")
        _count(self.generation, label="generation", limit=2**63 - 1)
        if self.contract_version != NODE_CONTRACT_VERSION:
            raise _fail(
                f"contract_version {self.contract_version} is not supported; expected {NODE_CONTRACT_VERSION}",
            )
        if len(self.users) > MAX_USERS_PER_SNAPSHOT:
            raise _fail(f"traffic.users exceeds the supported limit of {MAX_USERS_PER_SNAPSHOT}")
        for user_id, usage in self.users.items():
            _identifier(user_id, label="traffic.users key")
            if not isinstance(usage, NodeTrafficUsage):
                raise _fail(f"traffic.users.{user_id} must be a NodeTrafficUsage")
            usage.validate()

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "contract_version": self.contract_version,
            "node_id": self.node_id,
            "generation": self.generation,
            "users": {
                user_id: usage.to_document()
                for user_id, usage in sorted(self.users.items())
            },
        }

    @classmethod
    def from_document(cls, raw: object) -> "NodeTrafficReport":
        data = _mapping(raw, label="traffic report")
        _reject_unknown(
            data,
            ("contract_version", "node_id", "generation", "users"),
            label="traffic report",
        )
        for required in ("node_id", "generation", "users"):
            if required not in data:
                raise _fail(f"traffic report.{required} is required")
        users = _mapping(data["users"], label="traffic report.users")
        report = cls(
            node_id=_identifier(data["node_id"], label="node_id"),
            generation=_count(data["generation"], label="generation", limit=2**63 - 1),
            users={
                _identifier(user_id, label="traffic.users key"):
                    NodeTrafficUsage.from_document(usage)
                for user_id, usage in users.items()
            },
            contract_version=data.get("contract_version", NODE_CONTRACT_VERSION),
        )
        report.validate()
        return report


__all__ = ["NodeTrafficReport", "NodeTrafficUsage"]
