"""Protected, route-scoped cascade authentication material."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import stat
import struct
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from hydra.core.host import HostBackend
from hydra.core.runtime_users import ProtectedRuntimeUser
from hydra.core.state_models import User

_CASCADE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PARTICIPANT_ID = re.compile(r"^(?:base|[A-Za-z0-9][A-Za-z0-9._-]{0,63})$")
_PROTOCOLS = frozenset({"vless", "anytls"})
_ROLES = frozenset({"entry", "transit", "probe"})
_SECRET_BYTES = 32


@dataclass(frozen=True, repr=False)
class CascadeCredentialTransfer:
    """One explicit, route-scoped secret transfer over the pinned management channel."""

    cascade_id: str = field(repr=False)
    _seed: bytes = field(repr=False)

    def validate(self) -> None:
        if not isinstance(self.cascade_id, str) or not _CASCADE_ID.fullmatch(self.cascade_id):
            raise ValueError("cascade credential transfer scope is invalid")
        if not isinstance(self._seed, bytes) or len(self._seed) != _SECRET_BYTES:
            raise ValueError("cascade credential transfer material is invalid")

    def to_document(self) -> dict[str, str]:
        self.validate()
        return {"cascade_id": self.cascade_id, "seed": base64.b64encode(self._seed).decode("ascii")}

    @classmethod
    def from_document(cls, raw: object) -> "CascadeCredentialTransfer":
        if not isinstance(raw, dict) or set(raw) != {"cascade_id", "seed"} or not isinstance(raw["seed"], str):
            raise ValueError("cascade credential transfer has an invalid shape")
        try:
            seed = base64.b64decode(raw["seed"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("cascade credential transfer material is invalid") from exc
        value = cls(raw["cascade_id"], seed)
        value.validate()
        return value

    def __repr__(self) -> str:
        return "CascadeCredentialTransfer(<protected>)"


@dataclass(frozen=True, repr=False)
class CascadeCredentialScope:
    """An in-memory key handle; neither the seed nor derived subjects repr."""

    cascade_id: str = field(repr=False)
    _seed: bytes = field(repr=False)

    def subject(
        self,
        participant_id: str,
        protocol: str,
        role: str,
        business_user: User,
    ) -> User:
        _validate_scope(self.cascade_id, participant_id, protocol, role)
        if not isinstance(business_user, User):
            raise ValueError("cascade business-user identity is invalid")
        identity = business_user.uuid
        if (
            not isinstance(identity, str)
            or not identity
            or len(identity) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in identity)
        ):
            raise ValueError("cascade business-user identity is invalid")
        parts = (self.cascade_id, participant_id, protocol, role, identity)
        subject_id = bytearray(self._derive(b"auth-id", parts)[:16])
        subject_id[6] = (subject_id[6] & 0x0F) | 0x40
        subject_id[8] = (subject_id[8] & 0x3F) | 0x80
        name = self._derive(b"auth-name", parts).hex()[:32]
        return ProtectedRuntimeUser(
            email=f"cascade-{name}@invalid.hydra",
            uuid=str(uuid.UUID(bytes=bytes(subject_id))),
        )

    def technical_subject(
        self,
        participant_id: str,
        protocol: str,
        role: str,
        operation_id: str,
    ) -> User:
        """Derive operation-only staging identity without any business UUID."""
        _validate_scope(self.cascade_id, participant_id, protocol, "probe")
        if role not in {"entry", "transit"}:
            raise ValueError("cascade technical role is invalid")
        if not isinstance(operation_id, str) or not _CASCADE_ID.fullmatch(operation_id):
            raise ValueError("cascade technical operation identity is invalid")
        parts = (self.cascade_id, participant_id, protocol, "probe", operation_id, role)
        subject_id = bytearray(self._derive(b"technical-auth-id", parts)[:16])
        subject_id[6] = (subject_id[6] & 0x0F) | 0x40
        subject_id[8] = (subject_id[8] & 0x3F) | 0x80
        name = self._derive(b"technical-auth-name", parts).hex()[:32]
        return ProtectedRuntimeUser(
            email=f"cascade-{name}@invalid.hydra",
            uuid=str(uuid.UUID(bytes=bytes(subject_id))),
        )

    def _derive(self, purpose: bytes, parts: tuple[str, ...]) -> bytes:
        payload = bytearray(b"hydra-managed-cascade-credential-v1\x00")
        for value in (purpose.decode("ascii"), *parts):
            encoded = value.encode("utf-8")
            payload.extend(struct.pack(">I", len(encoded)))
            payload.extend(encoded)
        return hmac.new(self._seed, payload, hashlib.sha256).digest()

    def __repr__(self) -> str:
        return "CascadeCredentialScope(<protected>)"


@dataclass
class CascadeCredentialStore:
    """Persist one immutable random seed per validated public cascade ID."""

    host: HostBackend
    root: Path
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.root.is_absolute():
            raise ValueError("cascade credential root must be absolute")

    def prepare(self, cascade_id: str) -> CascadeCredentialScope:
        """Create material only during explicit participant preparation."""
        path = self._path(cascade_id)
        with self._lock:
            self._check_ancestors(path)
            self.host.ensure_directory(self.root, mode=0o700)
            self._check_root_mode()
            if path.is_symlink():
                raise ValueError("cascade credential path is an unsafe symbolic link")
            if not path.exists():
                created = self.host.atomic_create(
                    path,
                    secrets.token_bytes(_SECRET_BYTES),
                    mode=0o600,
                    durable=True,
                )
                if not created:
                    return self.load(cascade_id)
            return self._load_path(cascade_id, path)

    def export_transfer(self, cascade_id: str) -> CascadeCredentialTransfer:
        scope = self.load(cascade_id)
        return CascadeCredentialTransfer(cascade_id, scope._seed)

    def import_transfer(self, transfer: CascadeCredentialTransfer) -> CascadeCredentialScope:
        """Persist an authenticated coordinator transfer without implicit key rotation."""
        if not isinstance(transfer, CascadeCredentialTransfer):
            raise ValueError("cascade credential transfer is invalid")
        transfer.validate()
        path = self._path(transfer.cascade_id)
        with self._lock:
            self._check_ancestors(path)
            self.host.ensure_directory(self.root, mode=0o700)
            self._check_root_mode()
            if path.is_symlink():
                raise ValueError("cascade credential path is an unsafe symbolic link")
            if not path.exists():
                self.host.atomic_create(path, transfer._seed, mode=0o600, durable=True)
            scope = self._load_path(transfer.cascade_id, path)
            if not hmac.compare_digest(scope._seed, transfer._seed):
                raise ValueError("cascade credentials are immutable for this route")
            return scope

    def validate_transfer(self, transfer: CascadeCredentialTransfer) -> CascadeCredentialScope:
        """Check an existing seed without creating or rekeying route credentials."""
        if not isinstance(transfer, CascadeCredentialTransfer):
            raise ValueError("cascade credential transfer is invalid")
        transfer.validate()
        scope = self.load(transfer.cascade_id)
        if not hmac.compare_digest(scope._seed, transfer._seed):
            raise ValueError("cascade credentials are immutable for this route")
        return scope

    def load(self, cascade_id: str) -> CascadeCredentialScope:
        """Read existing material without creating directories or files."""
        path = self._path(cascade_id)
        self._check_ancestors(path)
        if path.is_symlink():
            raise ValueError("cascade credential path is an unsafe symbolic link")
        if not path.is_file():
            raise ValueError("cascade credentials are unavailable")
        self._check_root_mode()
        return self._load_path(cascade_id, path)

    def exists(self, cascade_id: str) -> bool:
        path = self._path(cascade_id)
        self._check_ancestors(path)
        if path.is_symlink():
            raise ValueError("cascade credential path is an unsafe symbolic link")
        return path.is_file()

    def remove(self, cascade_id: str, *, cleanup_confirmed: bool) -> None:
        """Delete only after the caller confirms participant cleanup."""
        if type(cleanup_confirmed) is not bool or not cleanup_confirmed:
            raise ValueError("cascade credentials require confirmed participant cleanup")
        path = self._path(cascade_id)
        self._check_ancestors(path)
        if path.is_symlink():
            raise ValueError("cascade credential path is an unsafe symbolic link")
        self.host.remove_file(path, missing_ok=True)

    def _load_path(self, cascade_id: str, path: Path) -> CascadeCredentialScope:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != _SECRET_BYTES:
            raise ValueError("cascade credential material is malformed")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("cascade credential permissions are unsafe")
        seed = self.host.read_bytes(path, max_bytes=_SECRET_BYTES)
        if len(seed) != _SECRET_BYTES:
            raise ValueError("cascade credential material is malformed")
        return CascadeCredentialScope(cascade_id, seed)

    def _check_root_mode(self) -> None:
        if self.root.is_symlink():
            raise ValueError("cascade credential root is an unsafe symbolic link")
        if not self.root.is_dir():
            raise ValueError("cascade credential root is unavailable")
        if os.name != "nt" and stat.S_IMODE(self.root.stat().st_mode) != 0o700:
            raise ValueError("cascade credential directory permissions are unsafe")

    def _check_ancestors(self, path: Path) -> None:
        for start in (path, self.root):
            current = start
            while current != current.parent:
                if current.is_symlink():
                    raise ValueError("cascade credential path is an unsafe symbolic link")
                current = current.parent
        if not self.root.exists() and path.parent != self.root:
            raise ValueError("cascade credential root is unavailable")

    def _path(self, cascade_id: str) -> Path:
        if not isinstance(cascade_id, str) or not _CASCADE_ID.fullmatch(cascade_id):
            raise ValueError("cascade credential reference is invalid")
        return self.root / f"{cascade_id}.seed"


def _validate_scope(cascade_id: str, participant_id: str, protocol: str, role: str) -> None:
    if not isinstance(cascade_id, str) or not _CASCADE_ID.fullmatch(cascade_id):
        raise ValueError("cascade credential reference is invalid")
    if not isinstance(participant_id, str) or not _PARTICIPANT_ID.fullmatch(participant_id):
        raise ValueError("cascade participant identity is invalid")
    if not isinstance(protocol, str) or protocol not in _PROTOCOLS:
        raise ValueError("cascade credential protocol is unsupported")
    if not isinstance(role, str) or role not in _ROLES:
        raise ValueError("cascade credential role is invalid")


__all__ = ["CascadeCredentialScope", "CascadeCredentialStore"]
