"""Shared validation primitives for the base ↔ node contracts.

Both directions of the boundary validate with these helpers, so a limit or a
rejected character is defined once. Kept separate from the data types because
the desired snapshot and the returned export are produced by different sides
and change for different reasons.
"""

from __future__ import annotations

import re
from typing import Any

from hydra.contracts.errors import ConfigurationError

NODE_CONTRACT_VERSION = 5
NODE_CONTROL_PORT = 9444
MAX_NODE_BRANCH_LENGTH = 128

_GIT_BRANCH_CHARACTERS = re.compile(r"[A-Za-z0-9._/-]+\Z")
_COMMIT_REVISION = re.compile(r"[0-9a-f]{40}\Z")

MAX_NODE_ID_LENGTH = 64
MAX_NODE_TEXT_LENGTH = 64
MAX_IDENTITY_LENGTH = 254
MAX_USERS_PER_SNAPSHOT = 4096
MAX_PROTOCOLS_PER_NODE = 64
MAX_PROFILES_PER_USER = 64
MAX_LINKS_PER_PROFILE = 32
MAX_LINK_LENGTH = 8192
MAX_SINGBOX_DOCUMENTS_PER_PROFILE = 8
# Transport-level cap for one encoded snapshot/export body.
MAX_NODE_BODY_BYTES = 64 * 1024 * 1024


class NodeContractError(ConfigurationError):
    """A node snapshot or export failed structural validation."""


def _fail(message: str) -> NodeContractError:
    return NodeContractError(message)


def _reject_unknown(
    mapping: dict[str, Any],
    allowed: tuple[str, ...],
    *,
    label: str,
) -> None:
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise _fail(f"{label} has unsupported fields: {', '.join(unknown)}")


def _mapping(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(f"{label} must be an object")
    return value


def _count(value: object, *, label: str, limit: int) -> int:
    if type(value) is not int or value < 0:
        raise _fail(f"{label} must be a non-negative integer")
    if value > limit:
        raise _fail(f"{label} exceeds the supported limit of {limit}")
    return value


def _flag(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise _fail(f"{label} must be a boolean")
    return value


def _identity(value: object, *, label: str) -> str:
    """Accept the operator's own identifiers (email, UUID) without reshaping them."""
    if not isinstance(value, str):
        raise _fail(f"{label} must be a string")
    text = value.strip()
    if not text or len(text) > MAX_IDENTITY_LENGTH:
        raise _fail(f"{label} must be 1..{MAX_IDENTITY_LENGTH} characters")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in text):
        raise _fail(f"{label} contains whitespace or a control character")
    return text


def _text(value: object, *, label: str, limit: int = MAX_NODE_TEXT_LENGTH) -> str:
    if not isinstance(value, str):
        raise _fail(f"{label} must be a string")
    text = value.strip()
    if len(text) > limit:
        raise _fail(f"{label} exceeds {limit} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise _fail(f"{label} contains a control character")
    return text


def _identifier(value: object, *, label: str, limit: int = MAX_NODE_ID_LENGTH) -> str:
    text = _text(value, label=label, limit=limit)
    if not text or not (text[0].isalnum() or text[0] == "_"):
        raise _fail(f"{label} must start with a letter, digit or underscore")
    if any(not (character.isalnum() or character in "._:-@+") for character in text):
        raise _fail(f"{label} contains an unsupported character")
    return text


def _link(value: object, *, label: str) -> str:
    """A share link is one line: a newline here would inject a second entry."""
    if not isinstance(value, str):
        raise _fail(f"{label} must be a string")
    if not value or len(value) > MAX_LINK_LENGTH:
        raise _fail(f"{label} must be 1..{MAX_LINK_LENGTH} characters")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise _fail(f"{label} must be a single line without control characters")
    scheme, separator, remainder = value.partition("://")
    if not separator or not remainder:
        raise _fail(f"{label} must be an absolute URI")
    if (
        not scheme
        or not scheme[0].isalpha()
        or any(not (character.isalnum() or character in "+-.") for character in scheme)
    ):
        raise _fail(f"{label} has an invalid URI scheme")
    return value


def validate_node_id(value: object) -> str:
    """Validate a stable node identifier. Shared by state and wire contracts."""
    return _identifier(value, label="node_id")


def checked_node_id(value: object, *, context: str) -> str:
    """Validate an identifier from persisted or installed data.

    State documents and install files are not wire messages: callers (and the
    backup fallback in the state reader) expect ``ValueError`` there.
    """
    try:
        return validate_node_id(value)
    except NodeContractError as exc:
        raise ValueError(f"{context}: {exc}") from exc


def checked_node_branch(value: object, *, context: str) -> str:
    """Accept only a bounded, shell/systemd-safe Git branch name."""
    if not isinstance(value, str) or len(value) > MAX_NODE_BRANCH_LENGTH:
        raise ValueError(f"{context} is not a safe Git branch name")
    if not _GIT_BRANCH_CHARACTERS.fullmatch(value) or value in {"", "@"}:
        raise ValueError(f"{context} is not a safe Git branch name")
    if value.startswith((".", "/", "-")) or value.endswith((".", "/")):
        raise ValueError(f"{context} is not a safe Git branch name")
    if ".." in value or "//" in value or "@{" in value:
        raise ValueError(f"{context} is not a safe Git branch name")
    if any(part.startswith(".") or part.endswith(".lock") for part in value.split("/")):
        raise ValueError(f"{context} is not a safe Git branch name")
    return value


def checked_node_revision(value: object, *, context: str) -> str:
    """Require the full immutable SHA-1 used by the transactional updater."""
    if not isinstance(value, str) or not _COMMIT_REVISION.fullmatch(value):
        raise ValueError(f"{context} must be a full 40-character commit SHA")
    return value


__all__ = [
    "MAX_NODE_BODY_BYTES",
    "MAX_NODE_BRANCH_LENGTH",
    "NODE_CONTROL_PORT",
    "NODE_CONTRACT_VERSION",
    "NodeContractError",
    "checked_node_branch",
    "checked_node_id",
    "checked_node_revision",
    "validate_node_id",
]
