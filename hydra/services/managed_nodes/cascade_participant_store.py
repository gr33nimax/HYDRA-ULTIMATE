"""Protected checksummed participant records and immutable pre-effect snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path
from dataclasses import replace
from typing import Any

from hydra.contracts.managed_node_cascade import CascadeParticipantRequest
from hydra.core.host import HostBackend
from hydra.core.state_managed_nodes import managed_nodes_from_extensions
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.cascade_leases import operation_is_active
from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext

_PHASES = frozenset(
    {"snapshotted", "prepared", "applying", "applied", "recovery_required", "rolling_back", "rolled_back", "finalized"}
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECORD = 1024 * 1024


class CascadeParticipantStore:
    """Use write-once context snapshots and checksummed atomic transaction records."""

    def __init__(self, *, host: HostBackend, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("cascade participant store root must be absolute")
        self._host = host
        self._root = root
        self._lock = threading.RLock()

    def snapshot(
        self,
        request: CascadeParticipantRequest,
        engine: str,
        config: str,
        restore_context: CascadeRestoreContext,
    ) -> dict[str, Any]:
        request.validate()
        if not isinstance(restore_context, CascadeRestoreContext):
            raise ValueError("cascade participant requires a scoped restore context before effects")
        restore_context.validate_for(request)
        _digest(engine, "engine")
        _digest(config, "configuration")
        with self._lock:
            path = self._path(request, ".snapshot")
            request_digest = hashlib.sha256(_encode(request.to_document())).hexdigest()
            record_path = self._path(request, ".json")
            current = self._read_record(record_path)
            if current is not None and (
                current["request"] != request.to_document() or current["phase"] in {"rolled_back", "finalized"}
            ):
                raise ValueError("cascade participant operation is terminal or bound to another request")
            snapshot = self._read_snapshot(path)
            if snapshot is None:
                snapshot = {
                    "request_digest": request_digest,
                    "engine_identity": engine,
                    "config_identity": config,
                    "restore_context": restore_context.to_document(),
                }
                payload = _encode(snapshot)
                wrapped = _encode({"payload": snapshot, "sha256": hashlib.sha256(payload).hexdigest()})
                if len(wrapped) > _MAX_RECORD:
                    raise ValueError("cascade participant snapshot exceeds the size limit")
                self._ensure_root()
                if path.is_symlink():
                    raise ValueError("cascade participant snapshot path is unsafe")
                if not self._host.atomic_create(path, wrapped, mode=0o600, durable=True):
                    snapshot = self._read_snapshot(path)
                    if snapshot is None:
                        raise ValueError("cascade participant snapshot is unavailable")
            if (
                snapshot["request_digest"] != request_digest
                or snapshot["restore_context"] != restore_context.to_document()
            ):
                raise ValueError("cascade participant snapshot is bound to another request or prior context")
            current = self._read_record(record_path)
            if current is None:
                current = {
                    "request": request.to_document(),
                    "phase": "snapshotted",
                    "rollback_requested": False,
                    "before_engine_identity": snapshot["engine_identity"],
                    "before_config_identity": snapshot["config_identity"],
                    "after_engine_identity": None,
                    "after_config_identity": None,
                    "receipt": None,
                    "preparation_receipt": None,
                    "material": None,
                }
                self._write_record(record_path, current, create=True)
            elif current["request"] != request.to_document():
                raise ValueError("cascade participant operation is already bound to another request")
            elif current["phase"] in {"rolled_back", "finalized"}:
                raise ValueError("cascade participant transaction is already terminal")
            elif (
                current["before_engine_identity"] != snapshot["engine_identity"]
                or current["before_config_identity"] != snapshot["config_identity"]
            ):
                raise ValueError("cascade participant snapshot context does not match its receipt")
            return snapshot

    def snapshot_data(self, request: CascadeParticipantRequest) -> dict[str, Any] | None:
        """Read an existing immutable artifact without consulting changed runtime state."""
        request.validate()
        with self._lock:
            snapshot = self._read_snapshot(self._path(request, ".snapshot"))
            if snapshot is None:
                return None
            digest = hashlib.sha256(_encode(request.to_document())).hexdigest()
            if snapshot["request_digest"] != digest:
                raise ValueError("cascade participant snapshot is bound to another request")
            context = CascadeRestoreContext.from_document(snapshot["restore_context"])
            context.validate_for(request)
            return snapshot

    def restore_context(self, request: CascadeParticipantRequest) -> CascadeRestoreContext:
        request.validate()
        with self._lock:
            snapshot = self._read_snapshot(self._path(request, ".snapshot"))
            if snapshot is None:
                raise ValueError("cascade participant restore snapshot is unavailable")
            context = CascadeRestoreContext.from_document(snapshot["restore_context"])
            context.validate_for(request)
            return context

    def restoration_contexts(self, state: AppState) -> tuple[CascadeRestoreContext, ...]:
        """Replace owned scopes for rollback or removal; corrupted evidence fails closed."""
        if not self._root.is_dir():
            return ()
        self._check_ancestors()
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        operations = {operation.id: operation for operation in namespace.operations}
        contexts = []
        for path in self._root.glob("*.json"):
            record = self._read_record(path)
            if record is None:
                continue
            restoring = record["phase"] in {"rolling_back", "recovery_required"} and record["rollback_requested"]
            request = CascadeParticipantRequest.from_document(record["request"])
            removing = (
                request.kind == "cascade_remove"
                and record["phase"] in {"prepared", "applying", "applied", "recovery_required"}
                and not record["rollback_requested"]
            )
            if not restoring and not removing:
                continue
            operation = operations.get(request.operation_id)
            if (
                operation is None
                or not operation_is_active(operation)
                or (operation.kind, operation.target_id, operation.desired_digest, operation.plan)
                != (request.kind, request.target_id, request.plan_digest, request.plan)
            ):
                raise ValueError("cascade rollback restore request is not owned by the current operation")
            if restoring:
                contexts.append(self.restore_context(request))
            else:
                # One participant apply replaces all frozen route protocols, after all snapshots exist.
                contexts.extend(
                    CascadeRestoreContext.empty(replace(request, protocol=protocol))
                    for protocol in request.route.protocols
                )
        return tuple(contexts)

    def record(self, request: CascadeParticipantRequest) -> dict[str, Any] | None:
        request.validate()
        with self._lock:
            value = self._read_record(self._path(request, ".json"))
            if value is not None and value["request"] != request.to_document():
                raise ValueError("cascade participant record scope does not match its request")
            return value

    def update(self, request: CascadeParticipantRequest, *, phase: str, **changes: Any) -> dict[str, Any]:
        if phase not in _PHASES:
            raise ValueError("cascade participant phase is invalid")
        request.validate()
        allowed_changes = {
            "snapshotted": {"receipt"},
            "prepared": {"receipt", "preparation_receipt", "material"},
            "applying": set(),
            "applied": {"after_engine_identity", "after_config_identity", "receipt"},
            "recovery_required": set(),
            "rolling_back": {"rollback_requested"},
            "rolled_back": {"after_engine_identity", "after_config_identity", "receipt", "material"},
            "finalized": {"receipt", "material"},
        }
        if set(changes) - allowed_changes[phase]:
            raise ValueError("cascade participant update attempts to replace immutable evidence")
        with self._lock:
            path = self._path(request, ".json")
            current = self._read_record(path)
            if current is None or current["request"] != request.to_document():
                raise ValueError("cascade participant snapshot is unavailable")
            if current["phase"] == phase and any(
                current.get(key) is not None and current.get(key) != value for key, value in changes.items()
            ):
                raise ValueError("cascade participant evidence is immutable within a transaction phase")
            if not _transition(current["phase"], phase):
                raise ValueError("cascade participant phase transition is invalid")
            updated = dict(current)
            updated.update(changes)
            updated["phase"] = phase
            self._write_record(path, updated)
            return updated

    def request_for(self, operation_id: str, participant_id: str, protocol: str) -> CascadeParticipantRequest | None:
        if not self._root.is_dir():
            return None
        self._check_ancestors()
        for path in self._root.glob("*.json"):
            try:
                record = self._read_record(path)
                if record is None:
                    continue
                request = CascadeParticipantRequest.from_document(record["request"])
                if (
                    request.operation_id == operation_id
                    and request.participant_id == participant_id
                    and request.protocol == protocol
                ):
                    return request
            except (OSError, TypeError, ValueError):
                continue
        return None

    def can_render(self, operation_id: str, protocol: str) -> bool:
        """Return only whether one protocol's operation still owns a renderable overlay."""
        if not isinstance(operation_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", operation_id):
            return False
        self._check_ancestors()
        if not self._root.is_dir():
            return False
        for path in self._root.glob("*.json"):
            try:
                record = self._read_record(path)
            except (OSError, TypeError, ValueError):
                continue
            if (
                record
                and record["request"]["operation_id"] == operation_id
                and record["request"]["protocol"] == protocol
            ):
                return record["phase"] in {"prepared", "applying", "applied"} or (
                    record["phase"] == "recovery_required" and not record["rollback_requested"]
                )
        return False

    def all_terminal(self, operation_id: str, participant_id: str, phase: str) -> bool:
        if phase not in {"rolled_back", "finalized"} or not self._root.is_dir():
            return False
        self._check_ancestors()
        seen = False
        for path in self._root.glob("*.json"):
            try:
                record = self._read_record(path)
                if record is None:
                    continue
                request = CascadeParticipantRequest.from_document(record["request"])
            except (OSError, TypeError, ValueError):
                return False
            if request.operation_id == operation_id and request.participant_id == participant_id:
                seen = True
                if record["phase"] != phase:
                    return False
        return seen

    def remove_snapshot(self, request: CascadeParticipantRequest) -> None:
        request.validate()
        with self._lock:
            path = self._path(request, ".snapshot")
            self._safe_file(path, missing_ok=True)
            self._host.remove_file(path, missing_ok=True)

    def _write_record(self, path: Path, record: dict[str, Any], *, create: bool = False) -> None:
        payload = _encode(record)
        wrapped = _encode({"payload": record, "sha256": hashlib.sha256(payload).hexdigest()})
        if len(wrapped) > _MAX_RECORD:
            raise ValueError("cascade participant record exceeds the size limit")
        self._safe_file(path, missing_ok=True)
        if create:
            if not self._host.atomic_create(path, wrapped, mode=0o600, durable=True):
                existing = self._read_record(path)
                if existing != record:
                    raise ValueError("cascade participant record already exists with different content")
        else:
            self._host.atomic_write(path, wrapped, mode=0o600, durable=True)

    def _read_snapshot(self, path: Path) -> dict[str, Any] | None:
        self._safe_file(path, missing_ok=True)
        if not path.is_file():
            return None
        wrapped = self._read(path)
        if (
            not isinstance(wrapped, dict)
            or set(wrapped) != {"payload", "sha256"}
            or not isinstance(wrapped["payload"], dict)
        ):
            raise ValueError("cascade participant snapshot is malformed")
        snapshot = wrapped["payload"]
        if set(snapshot) != {"request_digest", "engine_identity", "config_identity", "restore_context"}:
            raise ValueError("cascade participant snapshot has an invalid shape")
        if hashlib.sha256(_encode(snapshot)).hexdigest() != wrapped["sha256"]:
            raise ValueError("cascade participant snapshot checksum is invalid")
        for name in ("request_digest", "engine_identity", "config_identity"):
            _digest(snapshot[name], name)
        CascadeRestoreContext.from_document(snapshot["restore_context"])
        return snapshot

    def _read_record(self, path: Path) -> dict[str, Any] | None:
        self._safe_file(path, missing_ok=True)
        if not path.is_file():
            return None
        wrapped = self._read(path)
        if (
            not isinstance(wrapped, dict)
            or set(wrapped) != {"payload", "sha256"}
            or not isinstance(wrapped["payload"], dict)
        ):
            raise ValueError("cascade participant record is malformed")
        if hashlib.sha256(_encode(wrapped["payload"])).hexdigest() != wrapped["sha256"]:
            raise ValueError("cascade participant record checksum is invalid")
        record = wrapped["payload"]
        required = {
            "request",
            "phase",
            "rollback_requested",
            "before_engine_identity",
            "before_config_identity",
            "after_engine_identity",
            "after_config_identity",
            "receipt",
            "preparation_receipt",
            "material",
        }
        if set(record) != required or record["phase"] not in _PHASES or type(record["rollback_requested"]) is not bool:
            raise ValueError("cascade participant record has an invalid shape")
        return record

    def _read(self, path: Path) -> Any:
        self._safe_file(path)
        try:
            return json.loads(self._host.read_bytes(path, max_bytes=_MAX_RECORD).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("cascade participant record is malformed") from exc

    def _ensure_root(self) -> None:
        self._check_ancestors()
        self._host.ensure_directory(self._root, mode=0o700)
        if os.name != "nt" and stat.S_IMODE(self._root.stat().st_mode) != 0o700:
            raise ValueError("cascade participant store permissions are unsafe")

    def _check_ancestors(self) -> None:
        current = self._root
        while current != current.parent:
            if current.is_symlink():
                raise ValueError("cascade participant store path is an unsafe symbolic link")
            current = current.parent
        if self._root.exists() and (
            not self._root.is_dir() or (os.name != "nt" and stat.S_IMODE(self._root.stat().st_mode) != 0o700)
        ):
            raise ValueError("cascade participant store permissions are unsafe")

    def _safe_file(self, path: Path, *, missing_ok: bool = False) -> None:
        self._check_ancestors()
        if path.is_symlink():
            raise ValueError("cascade participant file path is unsafe")
        if not path.exists():
            if missing_ok:
                return
            raise ValueError("cascade participant file is unavailable")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_RECORD:
            raise ValueError("cascade participant file is unsafe or too large")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("cascade participant file permissions are unsafe")

    def _path(self, request: CascadeParticipantRequest, suffix: str) -> Path:
        key = _encode((request.operation_id, request.target_id, request.participant_id, request.protocol)).decode(
            "ascii"
        )
        return self._root / f"{hashlib.sha256(key.encode('ascii')).hexdigest()}{suffix}"


def _transition(current: str, updated: str) -> bool:
    allowed = {
        "snapshotted": {"snapshotted", "prepared", "rolling_back", "rolled_back"},
        "prepared": {"prepared", "applying", "rolling_back", "rolled_back"},
        "applying": {"applying", "applied", "recovery_required", "rolling_back"},
        "applied": {"applied", "rolling_back", "finalized"},
        "recovery_required": {"recovery_required", "rolling_back", "rolled_back"},
        "rolling_back": {"rolling_back", "rolled_back", "recovery_required"},
        "rolled_back": {"rolled_back"},
        "finalized": {"finalized"},
    }
    return updated in allowed[current]


def _digest(value: str, label: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"cascade participant {label} identity is invalid")


def _encode(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


__all__ = ["CascadeParticipantStore"]
