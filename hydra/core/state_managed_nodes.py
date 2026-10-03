"""Typed v1 namespace for managed-node desired state and durable operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hydra.contracts.managed_node_models import (
    CascadeDefinition,
    NodeDefinition,
    NodeDesired,
    Operation,
)

MANAGED_NODES_FEATURE = "managed_nodes"
MANAGED_NODES_VERSION = 1


@dataclass(frozen=True)
class ManagedNodesState:
    definitions: list[NodeDefinition] = field(default_factory=list)
    cascades: list[CascadeDefinition] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)
    apply_intents: dict[str, NodeDesired] = field(default_factory=dict)

    def validate(self) -> None:
        for collection_name, values, expected, key in (
            ("definitions", self.definitions, NodeDefinition, lambda item: item.id),
            ("cascades", self.cascades, CascadeDefinition, lambda item: item.id),
            ("operations", self.operations, Operation, lambda item: item.id),
        ):
            if not isinstance(values, list) or any(not isinstance(item, expected) for item in values):
                raise ValueError(f"managed_nodes.{collection_name} has an invalid shape")
            seen: set[str] = set()
            for item in values:
                item.validate()
                identity = key(item)
                if identity in seen:
                    raise ValueError(f"managed_nodes.{collection_name} repeats id {identity}")
                seen.add(identity)
        if not isinstance(self.apply_intents, dict):
            raise ValueError("managed_nodes.apply_intents must be an object")
        operations = {item.id: item for item in self.operations}
        for operation_id, desired in self.apply_intents.items():
            operation = operations.get(operation_id)
            if (
                not isinstance(operation_id, str)
                or not isinstance(desired, NodeDesired)
                or operation is None
                or operation.kind not in {"install", "apply"}
                or operation.target_id != desired.node_id
            ):
                raise ValueError("managed_nodes apply intent has no matching install operation")
            desired.validate()

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "version": MANAGED_NODES_VERSION,
            "definitions": [item.to_document() for item in self.definitions],
            "cascades": [item.to_document() for item in self.cascades],
            "operations": [item.to_document() for item in self.operations],
            "apply_intents": {key: value.to_document() for key, value in self.apply_intents.items()},
        }

    @classmethod
    def from_document(cls, raw: object) -> "ManagedNodesState":
        if not isinstance(raw, dict) or set(raw) not in (
            {"version", "definitions", "cascades", "operations"},
            {"version", "definitions", "cascades", "operations", "apply_intents"},
        ):
            raise ValueError("managed_nodes namespace has an invalid shape")
        if type(raw["version"]) is not int or raw["version"] != MANAGED_NODES_VERSION:
            raise ValueError(f"unsupported managed_nodes namespace version: {raw['version']!r}")
        if any(not isinstance(raw[name], list) for name in ("definitions", "cascades", "operations")):
            raise ValueError("managed_nodes collections must be lists")
        intents = raw.get("apply_intents", {})
        if not isinstance(intents, dict):
            raise ValueError("managed_nodes.apply_intents must be an object")
        value = cls(
            [NodeDefinition.from_document(item) for item in raw["definitions"]],
            [CascadeDefinition.from_document(item) for item in raw["cascades"]],
            [Operation.from_document(item) for item in raw["operations"]],
            {key: NodeDesired.from_document(item) for key, item in intents.items()},
        )
        value.validate()
        return value


def managed_nodes_from_extensions(extensions: object) -> ManagedNodesState:
    if not isinstance(extensions, dict):
        raise ValueError("feature_extensions must be an object")
    raw = extensions.get(MANAGED_NODES_FEATURE)
    return ManagedNodesState() if raw is None else ManagedNodesState.from_document(raw)


def validate_managed_nodes_extensions(extensions: object) -> None:
    managed_nodes_from_extensions(extensions)


def store_managed_nodes(extensions: dict[str, Any], state: ManagedNodesState) -> None:
    if not isinstance(extensions, dict):
        raise ValueError("feature_extensions must be an object")
    state.validate()
    extensions[MANAGED_NODES_FEATURE] = state.to_document()


__all__ = [
    "MANAGED_NODES_FEATURE",
    "MANAGED_NODES_VERSION",
    "ManagedNodesState",
    "managed_nodes_from_extensions",
    "store_managed_nodes",
    "validate_managed_nodes_extensions",
]
