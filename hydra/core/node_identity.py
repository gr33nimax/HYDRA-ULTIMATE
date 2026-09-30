"""Installation identity of a node managed by a HYDRA base server.

The role of a machine is an installation fact, not a second copy of desired
state: a node runs its own entrypoint and has this identity file, and the
identity file's presence is what keeps the full management surface away. A
malformed identity still counts as a node install — silently falling back to
normal management on a node would be the dangerous failure, so the restricted
surface reports the problem instead.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from hydra.contracts.node_validation import NODE_CONTROL_PORT, NODE_CONTRACT_VERSION, checked_node_id

NODE_ETC_DIR = Path("/etc/hydra/node")
NODE_IDENTITY_FILE = NODE_ETC_DIR / "identity.json"

_IDENTITY_KEYS = (
    "contract_version",
    "node_id",
    "base_url",
    "base_ip",
    "control_port",
    "certificate",
    "private_key",
    "base_ca",
    "base_fingerprint",
)
_ORIGIN = re.compile(r"^https://[A-Za-z0-9._:\-\[\]]+(?::\d{1,5})?$")


@dataclass(frozen=True)
class NodeIdentity:
    """How this node reaches its base and proves who it is."""

    node_id: str
    base_url: str
    certificate: str
    private_key: str
    base_ca: str = ""
    base_fingerprint: str = ""
    base_ip: str = ""
    control_port: int = NODE_CONTROL_PORT
    contract_version: int = NODE_CONTRACT_VERSION

    def validate(self) -> None:
        checked_node_id(self.node_id, context="node_id")
        try:
            ipaddress.ip_address(self.base_ip)
        except ValueError as exc:
            raise ValueError("base_ip must be an IP address") from exc
        if type(self.control_port) is not int or not 1 <= self.control_port <= 65535:
            raise ValueError("control_port must be 1..65535")
        if not _ORIGIN.match(self.base_url or ""):
            raise ValueError("base_url must be an https origin, for example https://base.example.com:8443")
        for label, value in (
            ("certificate", self.certificate),
            ("private_key", self.private_key),
        ):
            _absolute_path(value, label=label)
        _absolute_path(self.base_ca, label="base_ca")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", self.base_fingerprint):
            raise ValueError("base_fingerprint must be a SHA-256 hexadecimal fingerprint")
        if self.contract_version != NODE_CONTRACT_VERSION:
            raise ValueError(
                f"contract_version {self.contract_version} is not supported; expected {NODE_CONTRACT_VERSION}",
            )


def _absolute_path(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an absolute path")
    if not (Path(value).is_absolute() or PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()):
        raise ValueError(f"{label} must be an absolute path")
    if ".." in PurePosixPath(value).parts or ".." in PureWindowsPath(value).parts:
        raise ValueError(f"{label} must not contain '..'")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{label} must not contain control characters")
    return value


def _text(raw: dict, key: str, *, required: bool = True) -> str:
    value = raw.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"node identity {key} must be a string")
    if required and not value:
        raise ValueError(f"node identity is missing: {key}")
    return value


def identity_from_document(raw: object) -> NodeIdentity:
    """Parse a persisted identity document, rejecting anything unexpected."""
    if not isinstance(raw, dict):
        raise ValueError("node identity must be an object")
    unknown = sorted(set(raw) - set(_IDENTITY_KEYS))
    if unknown:
        raise ValueError(f"node identity has unsupported fields: {', '.join(unknown)}")
    identity = NodeIdentity(
        node_id=_text(raw, "node_id"),
        base_url=_text(raw, "base_url"),
        base_ip=_text(raw, "base_ip"),
        control_port=raw.get("control_port", NODE_CONTROL_PORT),
        certificate=_text(raw, "certificate"),
        private_key=_text(raw, "private_key"),
        base_ca=_text(raw, "base_ca"),
        base_fingerprint=_text(raw, "base_fingerprint"),
        contract_version=raw.get("contract_version", NODE_CONTRACT_VERSION),
    )
    identity.validate()
    return identity


def load_node_identity(path: Path | None = None) -> NodeIdentity | None:
    """Read this machine's node identity; ``None`` means it is a base server."""
    source = path or NODE_IDENTITY_FILE
    try:
        text = source.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"could not read node identity {source}: {exc}") from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"node identity {source} is not valid JSON: {exc}") from exc
    return identity_from_document(raw)


def is_node_install() -> bool:
    """Report whether this machine was installed as a managed node."""
    return NODE_IDENTITY_FILE.exists()


__all__ = [
    "NODE_ETC_DIR",
    "NODE_IDENTITY_FILE",
    "NodeIdentity",
    "identity_from_document",
    "is_node_install",
    "load_node_identity",
]
