"""Desired state the base sends to one node.

Deliberately absent: locally generated node credentials (the node owns its own
keys), ``installed``/runtime flags, and display names (the base resolves names
when it serves a subscription, so renaming works while a node is unreachable).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from hydra.contracts.node_validation import (
    MAX_NODE_ID_LENGTH,
    MAX_NODE_TEXT_LENGTH,
    MAX_PROTOCOLS_PER_NODE,
    MAX_USERS_PER_SNAPSHOT,
    NODE_CONTRACT_VERSION,
    NodeContractError,
    _count,
    _fail,
    _flag,
    _identifier,
    _identity,
    _mapping,
    _reject_unknown,
    _text,
    validate_node_id,
)
from hydra.contracts.plugin_config import JsonObject, validate_json_object


_NODE_LOCAL_SECRET_MARKERS = (
    "private_key",
    "client_key",
    "server_key",
    "password",
    "secret",
    "token",
    "authorization",
)


def is_node_local_secret_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(marker in normalized for marker in _NODE_LOCAL_SECRET_MARKERS)


# Config a node generates for itself. The desired state owns public parameters, so
# replacing the whole config with the base's copy would delete local material the
# base never sent: AmneziaWG profiles and their generation, or the certificate and
# Reality keypair a plugin prepared. AmneziaWG is the sharp case — its profiles
# carry the paddings that the third generation reads as the header-protection
# nonce, and losing them turns every apply into "Режим 3.1: S3=0 меньше 12".
NODE_LOCAL_MATERIAL_KEYS: dict[str, frozenset[str]] = {
    "amneziawg": frozenset({"profiles", "generation"}),
    "vless": frozenset({"cert_file", "key_file", "reality_private_key", "reality_public_key", "reality_short_id"}),
    "vless_cdn": frozenset(
        {"cert_file", "key_file", "encryption_private_key", "encryption_public_key", "uplink_data_key"}
    ),
    "anytls": frozenset({"cert_file", "key_file"}),
    "trusttunnel": frozenset({"cert_file", "key_file"}),
    "hysteria2": frozenset({"cert_file", "key_file"}),
    "naive": frozenset({"cert_file", "key_file"}),
    "shadowtls": frozenset({"cert_file", "key_file"}),
    "mtproto_zig": frozenset({"cert_file", "key_file", "web_cert_file", "web_key_file"}),
}


def is_node_local_material_key(protocol: str, key: str) -> bool:
    """Whether a node owns this config key and the base must not overwrite it."""
    return key in NODE_LOCAL_MATERIAL_KEYS.get(protocol, frozenset())


def _reject_node_local_secrets(value: object, *, label: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if is_node_local_secret_key(key):
                raise _fail(f"{label}.{key} contains a node-local secret")
            _reject_node_local_secrets(nested, label=f"{label}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_node_local_secrets(nested, label=f"{label}[{index}]")


def _quota(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _fail(f"{label} must be a finite non-negative number")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise _fail(f"{label} must be a finite non-negative number")
    return number


@dataclass(frozen=True)
class NodeUserProjection:
    """The only user fields a node may learn; credentials stay node-local."""

    email: str
    uuid: str
    blocked: bool = False
    expiry_date: str = ""
    disabled_protocols: tuple[str, ...] = ()
    traffic_limit_gb: float = 0.0
    traffic_reset_epoch: int = 0

    def validate(self) -> None:
        _identity(self.email, label="user.email")
        _identity(self.uuid, label="user.uuid")
        _flag(self.blocked, label="user.blocked")
        _quota(self.traffic_limit_gb, label="user.traffic_limit_gb")
        _count(self.traffic_reset_epoch, label="user.traffic_reset_epoch", limit=2**63 - 1)
        if self.expiry_date:
            _text(self.expiry_date, label="user.expiry_date")
        if len(self.disabled_protocols) > MAX_PROTOCOLS_PER_NODE:
            raise _fail("user.disabled_protocols exceeds the supported limit")
        seen: set[str] = set()
        for name in self.disabled_protocols:
            identifier = _identifier(name, label="user.disabled_protocols[]")
            if identifier in seen:
                raise _fail(f"user.disabled_protocols repeats {identifier}")
            seen.add(identifier)

    def to_document(self) -> JsonObject:
        self.validate()
        return {
            "email": self.email,
            "uuid": self.uuid,
            "blocked": self.blocked,
            "expiry_date": self.expiry_date,
            "disabled_protocols": list(self.disabled_protocols),
            "traffic_limit_gb": self.traffic_limit_gb,
            "traffic_reset_epoch": self.traffic_reset_epoch,
        }

    @classmethod
    def from_document(cls, raw: object) -> "NodeUserProjection":
        data = _mapping(raw, label="user")
        _reject_unknown(
            data,
            (
                "email",
                "uuid",
                "blocked",
                "expiry_date",
                "disabled_protocols",
                "traffic_limit_gb",
                "traffic_reset_epoch",
            ),
            label="user",
        )
        for required in ("email", "uuid", "traffic_reset_epoch"):
            if required not in data:
                raise _fail(f"user.{required} is required")
        disabled = data.get("disabled_protocols", [])
        if not isinstance(disabled, list):
            raise _fail("user.disabled_protocols must be a list")
        projection = cls(
            email=_identity(data["email"], label="user.email"),
            uuid=_identity(data["uuid"], label="user.uuid"),
            blocked=_flag(data.get("blocked", False), label="user.blocked"),
            expiry_date=_text(data.get("expiry_date", ""), label="user.expiry_date"),
            disabled_protocols=tuple(_identifier(item, label="user.disabled_protocols[]") for item in disabled),
            traffic_limit_gb=_quota(data.get("traffic_limit_gb", 0), label="user.traffic_limit_gb"),
            traffic_reset_epoch=_count(
                data["traffic_reset_epoch"],
                label="user.traffic_reset_epoch",
                limit=2**63 - 1,
            ),
        )
        projection.validate()
        return projection


@dataclass(frozen=True)
class NodeProtocolSpec:
    """Desired protocol state for one node; ``installed`` stays node-local.

    ``config`` is deliberately annotated with plain types: the state loader
    resolves annotations of persisted dataclasses through ``get_type_hints``,
    which cannot expand the ``PluginConfig`` alias outside its own module.
    JSON safety is enforced by ``validate_json_object`` instead.
    """

    enabled: bool = False
    port: int = 0
    config: dict[str, Any] = field(default_factory=dict)

    def validate(self, *, label: str = "protocol") -> None:
        _flag(self.enabled, label=f"{label}.enabled")
        _count(self.port, label=f"{label}.port", limit=65535)
        validate_json_object(self.config, path=f"{label}.config")
        _reject_node_local_secrets(self.config, label=f"{label}.config")

    def to_document(self) -> JsonObject:
        self.validate()
        return {"enabled": self.enabled, "port": self.port, "config": self.config}

    @classmethod
    def from_document(cls, raw: object, *, label: str = "protocol") -> "NodeProtocolSpec":
        data = _mapping(raw, label=label)
        _reject_unknown(data, ("enabled", "port", "config"), label=label)
        spec = cls(
            enabled=_flag(data.get("enabled", False), label=f"{label}.enabled"),
            port=data.get("port", 0),
            config=data.get("config", {}),
        )
        spec.validate(label=label)
        return spec


@dataclass(frozen=True)
class NodeDesiredSnapshot:
    """Everything a node needs to converge, and nothing it must not receive."""

    node_id: str
    generation: int
    users: tuple[NodeUserProjection, ...] = ()
    protocols: dict[str, NodeProtocolSpec] = field(default_factory=dict)
    contract_version: int = NODE_CONTRACT_VERSION

    def validate(self) -> None:
        _identifier(self.node_id, label="node_id")
        _count(self.generation, label="generation", limit=2**63 - 1)
        if self.contract_version != NODE_CONTRACT_VERSION:
            raise _fail(
                f"contract_version {self.contract_version} is not supported; expected {NODE_CONTRACT_VERSION}",
            )
        if len(self.users) > MAX_USERS_PER_SNAPSHOT:
            raise _fail(f"users exceeds the supported limit of {MAX_USERS_PER_SNAPSHOT}")
        if len(self.protocols) > MAX_PROTOCOLS_PER_NODE:
            raise _fail(
                f"protocols exceeds the supported limit of {MAX_PROTOCOLS_PER_NODE}",
            )
        emails: set[str] = set()
        uuids: set[str] = set()
        for projection in self.users:
            projection.validate()
            if projection.email in emails:
                raise _fail(f"users repeats email {projection.email}")
            if projection.uuid in uuids:
                raise _fail(f"users repeats uuid {projection.uuid}")
            emails.add(projection.email)
            uuids.add(projection.uuid)
        for name, spec in self.protocols.items():
            _identifier(name, label="protocols key")
            spec.validate(label=f"protocols.{name}")

    def to_document(self) -> JsonObject:
        self.validate()
        return {
            "contract_version": self.contract_version,
            "node_id": self.node_id,
            "generation": self.generation,
            "users": [projection.to_document() for projection in self.users],
            "protocols": {name: spec.to_document() for name, spec in self.protocols.items()},
        }

    @classmethod
    def from_document(cls, raw: object) -> "NodeDesiredSnapshot":
        data = _mapping(raw, label="snapshot")
        _reject_unknown(
            data,
            ("contract_version", "node_id", "generation", "users", "protocols"),
            label="snapshot",
        )
        for required in ("node_id", "generation"):
            if required not in data:
                raise _fail(f"snapshot.{required} is required")
        raw_users = data.get("users", [])
        if not isinstance(raw_users, list):
            raise _fail("snapshot.users must be a list")
        raw_protocols = _mapping(data.get("protocols", {}), label="snapshot.protocols")
        snapshot = cls(
            node_id=_identifier(data["node_id"], label="node_id"),
            generation=data["generation"],
            users=tuple(NodeUserProjection.from_document(item) for item in raw_users),
            protocols={
                name: NodeProtocolSpec.from_document(
                    spec,
                    label=f"protocols.{name}",
                )
                for name, spec in raw_protocols.items()
            },
            contract_version=data.get("contract_version", NODE_CONTRACT_VERSION),
        )
        snapshot.validate()
        return snapshot


__all__ = [
    "NODE_LOCAL_MATERIAL_KEYS",
    "NodeDesiredSnapshot",
    "NodeProtocolSpec",
    "NodeUserProjection",
    "is_node_local_material_key",
]
