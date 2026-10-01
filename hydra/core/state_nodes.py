"""Persisted desired configuration for one managed node.

Desired configuration lives here with only generation/digest references to the
separately protected published-export store. Connectivity, versions, and the last
error remain runtime observations, not operator settings.

Two entry points validate the same rules: :func:`validate_nodes` for the typed
aggregate before it is persisted, and :func:`validate_raw_nodes` for a serialized
document that has not been turned into objects yet. The raw path reports
``ValueError`` so a corrupt file still falls back to its backup instead of
being treated as an unsupported future format.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from hydra.contracts.node_snapshot import NodeProtocolSpec
from hydra.contracts.node_validation import NODE_CONTROL_PORT, checked_node_id, validate_node_id
from hydra.core.configuration_names import validate_configuration_names

MAX_NODE_TEXT = 253
MAX_BRANCH_TEXT = 128
MAX_REVISION_TEXT = 64

# A node is either serving its users or deliberately withdrawn from subscriptions.
# Withdrawal is desired configuration: it must survive a restart and must not be
# undone by the next scheduled sync, so it lives in state instead of a UI flag.
MANAGEMENT_ACTIVE = "active"
MANAGEMENT_WITHDRAWN = "withdrawn"
MANAGEMENT_STATES = (MANAGEMENT_ACTIVE, MANAGEMENT_WITHDRAWN)


def _text(value: object, *, path: str, limit: int = MAX_NODE_TEXT) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a string")
    text = value.strip()
    if len(text) > limit:
        raise ValueError(f"{path} exceeds {limit} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise ValueError(f"{path} contains a control character")
    return text


def _generation(value: object, *, path: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{path} must be a non-negative integer")
    return value


@dataclass
class NodeConfig:
    """Operator's desired definition of one managed node."""

    id: str = ""
    name: str = ""
    region: str = ""
    address: str = ""
    control_port: int = NODE_CONTROL_PORT
    ssh_port: int = 22
    # The account HYDRA logs into for installation and cleanup. It is not a secret and
    # stays in desired configuration; the password never does.
    ssh_user: str = "root"
    control_fingerprint: str = ""
    branch: str = "main"
    revision: str = ""
    # Operator-facing ID shown in menus and subscriptions. The technical ``id`` stays
    # the identity of credentials, exports and traffic accounting, so renaming this
    # never touches trust or accounting.
    display_id: str = ""
    # ``active`` or ``withdrawn``; withdrawn keeps the node managed but stops serving
    # users and client profiles until the operator explicitly restores it.
    management: str = MANAGEMENT_ACTIVE
    generation: int = 0
    # Generation whose client export is published in subscriptions. Until a node
    # confirms an apply this stays behind ``generation``, so a subscription keeps
    # serving the previously confirmed material.
    published_generation: int = 0
    # Hash of the exact desired snapshot assigned to ``generation``.
    desired_digest: str = ""
    published_digest: str = ""
    protocols: dict[str, NodeProtocolSpec] = field(default_factory=dict)
    # "protocol" or "protocol:profile" -> visible subscription name.
    profile_names: dict[str, str] = field(default_factory=dict)

    def validate(self, *, path: str = "node") -> None:
        checked_node_id(self.id, context=f"{path}.id")
        _text(self.name, path=f"{path}.name")
        _text(self.region, path=f"{path}.region")
        _text(self.address, path=f"{path}.address")
        if type(self.control_port) is not int or not 1 <= self.control_port <= 65535:
            raise ValueError(f"{path}.control_port must be 1..65535")
        if type(self.ssh_port) is not int or not 1 <= self.ssh_port <= 65535:
            raise ValueError(f"{path}.ssh_port must be 1..65535")
        _text(self.ssh_user, path=f"{path}.ssh_user", limit=64)
        if not self.ssh_user:
            raise ValueError(f"{path}.ssh_user is required")
        fingerprint = self.control_fingerprint.replace(":", "")
        if fingerprint and not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
            raise ValueError(f"{path}.control_fingerprint must be a SHA-256 fingerprint")
        _text(self.branch, path=f"{path}.branch", limit=MAX_BRANCH_TEXT)
        _text(self.revision, path=f"{path}.revision", limit=MAX_REVISION_TEXT)
        _text(self.display_id, path=f"{path}.display_id")
        if self.management not in MANAGEMENT_STATES:
            raise ValueError(f"{path}.management must be one of {', '.join(MANAGEMENT_STATES)}")
        _generation(self.generation, path=f"{path}.generation")
        _generation(self.published_generation, path=f"{path}.published_generation")
        if self.published_generation > self.generation:
            raise ValueError(f"{path}.published_generation cannot exceed generation")
        if not isinstance(self.desired_digest, str) or (
            self.desired_digest and not re.fullmatch(r"[0-9a-f]{64}", self.desired_digest)
        ):
            raise ValueError(f"{path}.desired_digest must be a lowercase SHA-256 digest")
        if self.generation == 0 and self.desired_digest:
            raise ValueError(f"{path}.desired_digest requires a desired generation")
        if not isinstance(self.published_digest, str) or (
            self.published_digest and not re.fullmatch(r"[0-9a-f]{64}", self.published_digest)
        ):
            raise ValueError(f"{path}.published_digest must be a lowercase SHA-256 digest")
        if self.published_generation == 0 and self.published_digest:
            raise ValueError(f"{path}.published_digest requires a published generation")
        if not isinstance(self.protocols, dict):
            raise ValueError(f"{path}.protocols must be an object")
        for name, spec in self.protocols.items():
            try:
                validate_node_id(name)
                if not isinstance(spec, NodeProtocolSpec):
                    raise ValueError(f"{path}.protocols.{name} must be a protocol spec")
                spec.validate(label=f"{path}.protocols.{name}")
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError(str(exc)) from exc
        validate_configuration_names(self.profile_names, path=f"{path}.profile_names")

    @classmethod
    def from_raw(cls, raw: object, *, path: str) -> "NodeConfig":
        """Build a typed node from a serialized entry, then validate it."""
        if not isinstance(raw, dict):
            raise ValueError(f"{path} must be an object")
        for key in ("protocols", "profile_names"):
            if key in raw and not isinstance(raw[key], dict):
                raise ValueError(f"{path}.{key} must be an object")
        protocols: dict[str, NodeProtocolSpec] = {}
        for name, spec in (raw.get("protocols") or {}).items():
            try:
                protocols[name] = NodeProtocolSpec.from_document(
                    spec,
                    label=f"{path}.{name}",
                )
            except Exception as exc:
                raise ValueError(str(exc)) from exc
        node = cls(
            id=raw.get("id", ""),
            name=raw.get("name", ""),
            region=raw.get("region", ""),
            address=raw.get("address", ""),
            control_port=raw.get("control_port", NODE_CONTROL_PORT),
            ssh_port=raw.get("ssh_port", 22),
            ssh_user=raw.get("ssh_user", "root"),
            control_fingerprint=raw.get("control_fingerprint", ""),
            branch=raw.get("branch", "main"),
            revision=raw.get("revision", ""),
            display_id=raw.get("display_id", ""),
            management=raw.get("management", MANAGEMENT_ACTIVE),
            generation=raw.get("generation", 0),
            published_generation=raw.get("published_generation", 0),
            desired_digest=raw.get("desired_digest", ""),
            published_digest=raw.get("published_digest", ""),
            protocols=protocols,
            profile_names=dict(raw.get("profile_names") or {}),
        )
        node.validate(path=path)
        return node

    @property
    def label(self) -> str:
        """Human-facing ID: the operator's alias, then the name, then the technical id."""
        return self.display_id or self.name or self.id

    @property
    def withdrawn(self) -> bool:
        return self.management == MANAGEMENT_WITHDRAWN

    def snapshot_protocols(self) -> dict[str, NodeProtocolSpec]:
        """Return the protocol specs that travel to the node.

        A withdrawn node must receive an empty runtime, otherwise the next scheduled
        sync would put its users and transports back and silently undo the withdrawal.
        """
        if self.withdrawn:
            return {}
        return dict(self.protocols)


def _reject_duplicate_ids(nodes: list[NodeConfig]) -> None:
    seen: set[str] = set()
    for node in nodes:
        if node.id in seen:
            raise ValueError(f"nodes repeats id {node.id}")
        seen.add(node.id)


def _reject_duplicate_labels(nodes: list[NodeConfig]) -> None:
    """Visible IDs identify a node to the operator, so two nodes cannot share one."""
    seen: dict[str, str] = {}
    for node in nodes:
        label = node.label.casefold()
        other = seen.get(label)
        if other is not None:
            raise ValueError(f"nodes {other} and {node.id} share the visible id {node.label}")
        seen[label] = node.id


def validate_nodes(nodes: object) -> None:
    """Validate the typed aggregate before it is persisted or applied."""
    if not isinstance(nodes, list):
        raise ValueError("state field 'nodes' must be a list")
    for node in nodes:
        if not isinstance(node, NodeConfig):
            raise ValueError("state field 'nodes' must contain node definitions")
        node.validate(path=f"nodes.{node.id or '?'}")
    _reject_duplicate_ids(nodes)
    _reject_duplicate_labels(nodes)


def validate_raw_nodes(value: object) -> None:
    """Validate a serialized node list without persisting anything."""
    if not isinstance(value, list):
        raise ValueError("state field 'nodes' must be a list")
    nodes = [NodeConfig.from_raw(raw, path=f"nodes[{index}]") for index, raw in enumerate(value)]
    _reject_duplicate_ids(nodes)
    _reject_duplicate_labels(nodes)


__all__ = [
    "MANAGEMENT_ACTIVE",
    "MANAGEMENT_STATES",
    "MANAGEMENT_WITHDRAWN",
    "NodeConfig",
    "validate_nodes",
    "validate_raw_nodes",
]
