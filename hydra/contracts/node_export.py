"""Client material a node returns after a successful apply.

The base publishes this into the user's existing subscription, so it must be
complete for every active user the node was given and must stay inside the
sizes a subscription response can carry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hydra.contracts.node_snapshot import NodeDesiredSnapshot
from hydra.contracts.node_validation import (
    MAX_LINKS_PER_PROFILE,
    MAX_NODE_TEXT_LENGTH,
    MAX_PROFILES_PER_USER,
    MAX_SINGBOX_DOCUMENTS_PER_PROFILE,
    MAX_USERS_PER_SNAPSHOT,
    NODE_CONTRACT_VERSION,
    NodeContractError,
    _count,
    _fail,
    _identifier,
    _identity,
    _link,
    _mapping,
    _reject_unknown,
    _text,
)
from hydra.contracts.plugin_config import JsonObject, validate_json_object


@dataclass(frozen=True)
class NodeClientProfile:
    """Client material for one node protocol profile, named by the base later."""

    protocol: str
    profile: str = ""
    links: tuple[str, ...] = ()
    singbox: tuple[JsonObject, ...] = ()

    def validate(self, *, label: str = "profile") -> None:
        _identifier(self.protocol, label=f"{label}.protocol")
        if self.profile:
            _text(self.profile, label=f"{label}.profile")
        if len(self.links) > MAX_LINKS_PER_PROFILE:
            raise _fail(f"{label}.links exceeds the supported limit")
        for index, link in enumerate(self.links):
            _link(link, label=f"{label}.links[{index}]")
        if len(self.singbox) > MAX_SINGBOX_DOCUMENTS_PER_PROFILE:
            raise _fail(f"{label}.singbox exceeds the supported limit")
        for index, document in enumerate(self.singbox):
            validate_json_object(document, path=f"{label}.singbox[{index}]")

    def to_document(self) -> JsonObject:
        self.validate()
        return {
            "protocol": self.protocol,
            "profile": self.profile,
            "links": list(self.links),
            "singbox": [dict(document) for document in self.singbox],
        }

    @classmethod
    def from_document(cls, raw: object, *, label: str = "profile") -> "NodeClientProfile":
        data = _mapping(raw, label=label)
        _reject_unknown(data, ("protocol", "profile", "links", "singbox"), label=label)
        if "protocol" not in data:
            raise _fail(f"{label}.protocol is required")
        raw_links = data.get("links", [])
        raw_singbox = data.get("singbox", [])
        if not isinstance(raw_links, list) or not isinstance(raw_singbox, list):
            raise _fail(f"{label} links and singbox must be lists")
        profile = cls(
            protocol=_identifier(data["protocol"], label=f"{label}.protocol"),
            profile=_text(data.get("profile", ""), label=f"{label}.profile"),
            links=tuple(_link(item, label=f"{label}.links[]") for item in raw_links),
            singbox=tuple(_json_document(item, label=f"{label}.singbox[]") for item in raw_singbox),
        )
        profile.validate(label=label)
        return profile


def _json_document(value: object, *, label: str) -> JsonObject:
    document = _mapping(value, label=label)
    validate_json_object(document, path=label)
    return document


@dataclass(frozen=True)
class NodeClientExportUser:
    """Published client material for exactly one user uuid."""

    uuid: str
    profiles: tuple[NodeClientProfile, ...] = ()

    def validate(self) -> None:
        _identity(self.uuid, label="export user.uuid")
        if len(self.profiles) > MAX_PROFILES_PER_USER:
            raise _fail("export user.profiles exceeds the supported limit")
        seen: set[tuple[str, str]] = set()
        for profile in self.profiles:
            profile.validate()
            key = (profile.protocol, profile.profile)
            if key in seen:
                raise _fail(
                    f"export repeats profile {profile.protocol}/{profile.profile or 'default'}",
                )
            seen.add(key)

    def to_document(self) -> JsonObject:
        self.validate()
        return {
            "uuid": self.uuid,
            "profiles": [profile.to_document() for profile in self.profiles],
        }

    @classmethod
    def from_document(cls, raw: object) -> "NodeClientExportUser":
        data = _mapping(raw, label="export user")
        _reject_unknown(data, ("uuid", "profiles"), label="export user")
        if "uuid" not in data:
            raise _fail("export user.uuid is required")
        raw_profiles = data.get("profiles", [])
        if not isinstance(raw_profiles, list):
            raise _fail("export user.profiles must be a list")
        user = cls(
            uuid=_identity(data["uuid"], label="export user.uuid"),
            profiles=tuple(NodeClientProfile.from_document(item) for item in raw_profiles),
        )
        user.validate()
        return user


@dataclass(frozen=True)
class NodeClientExport:
    """What a node returns after a successful apply; the base publishes it."""

    node_id: str
    generation: int
    users: dict[str, NodeClientExportUser] = field(default_factory=dict)
    contract_version: int = NODE_CONTRACT_VERSION

    def validate(self) -> None:
        _identifier(self.node_id, label="node_id")
        _count(self.generation, label="generation", limit=2**63 - 1)
        if self.contract_version != NODE_CONTRACT_VERSION:
            raise _fail(
                f"contract_version {self.contract_version} is not supported; expected {NODE_CONTRACT_VERSION}",
            )
        if len(self.users) > MAX_USERS_PER_SNAPSHOT:
            raise _fail("export users exceeds the supported limit")
        for key, user in self.users.items():
            if key != user.uuid:
                raise _fail(f"export entry {key} does not match user {user.uuid}")
            user.validate()

    def uuids(self) -> tuple[str, ...]:
        return tuple(self.users)

    def to_document(self) -> JsonObject:
        self.validate()
        return {
            "contract_version": self.contract_version,
            "node_id": self.node_id,
            "generation": self.generation,
            "users": {key: user.to_document() for key, user in self.users.items()},
        }

    @classmethod
    def from_document(cls, raw: object) -> "NodeClientExport":
        data = _mapping(raw, label="export")
        _reject_unknown(
            data,
            ("contract_version", "node_id", "generation", "users"),
            label="export",
        )
        for required in ("node_id", "generation"):
            if required not in data:
                raise _fail(f"export.{required} is required")
        raw_users = _mapping(data.get("users", {}), label="export.users")
        export = cls(
            node_id=_identifier(data["node_id"], label="node_id"),
            generation=data["generation"],
            users={key: NodeClientExportUser.from_document(value) for key, value in raw_users.items()},
            contract_version=data.get("contract_version", NODE_CONTRACT_VERSION),
        )
        export.validate()
        return export


def missing_exported_users(
    snapshot: NodeDesiredSnapshot,
    export: NodeClientExport,
) -> tuple[str, ...]:
    """Return snapshot users whose client material is absent from an export.

    A node must publish material for every active user it was given; a partial
    export would silently drop a working server from someone's subscription.
    Blocked users legitimately have no material.
    """
    snapshot.validate()
    export.validate()
    if snapshot.node_id != export.node_id:
        raise _fail("export does not belong to this node")
    return tuple(
        projection.uuid
        for projection in snapshot.users
        if not projection.blocked and projection.uuid not in export.users
    )


__all__ = [
    "NodeClientExport",
    "NodeClientExportUser",
    "NodeClientProfile",
    "missing_exported_users",
]
