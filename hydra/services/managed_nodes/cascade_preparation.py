"""Durable, operation-bound technical preparation before cascade activation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hydra.contracts.managed_node_models import CascadeDefinition, Operation
from hydra.core.host import HostBackend
from hydra.core.state_managed_nodes import managed_nodes_from_extensions
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.cascade_credentials import (
    CascadeCredentialScope,
    CascadeCredentialStore,
)
from hydra.services.managed_nodes.cascade_leases import (
    assert_cascade_unleased,
    cascade_candidate,
    cascade_participants,
    operation_is_active,
)
from hydra.services.managed_nodes.records import ManagedNodeRecords

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROTOCOLS = frozenset({"vless", "anytls"})


@dataclass(frozen=True)
class CascadePreparationEvidence:
    """Trusted local observations; these are not proof of a working two-hop path."""

    engine_identity: str
    baseline_config_identity: str
    prepared_config_identity: str
    current_config_identity: str

    def validate(self) -> None:
        if not isinstance(self.engine_identity, str) or not _SHA256.fullmatch(self.engine_identity):
            raise ValueError("cascade preparation engine identity is invalid")
        for identity in (self.baseline_config_identity, self.prepared_config_identity, self.current_config_identity):
            if not isinstance(identity, str) or not _SHA256.fullmatch(identity):
                raise ValueError("cascade preparation config identity is invalid")


@dataclass(frozen=True)
class CascadeTechnicalPreparation:
    """A local, transient rendering lease bound to a frozen cascade candidate."""

    route: CascadeDefinition
    protocol: str
    operation_id: str
    plan_digest: str
    participant_id: str
    role: str
    engine_identity: str
    baseline_config_identity: str
    prepared_config_identity: str

    def validate(self) -> None:
        self.route.validate()
        if (
            not isinstance(self.protocol, str)
            or self.protocol not in _PROTOCOLS
            or self.protocol not in self.route.protocols
        ):
            raise ValueError("cascade technical protocol does not match its frozen route")
        if not isinstance(self.operation_id, str) or not _ID.fullmatch(self.operation_id):
            raise ValueError("cascade technical operation identity is invalid")
        if not isinstance(self.plan_digest, str) or not _SHA256.fullmatch(self.plan_digest):
            raise ValueError("cascade technical plan digest is invalid")
        if not isinstance(self.participant_id, str) or self.participant_id not in {
            self.route.entry_id,
            self.route.exit_id,
        }:
            raise ValueError("cascade technical participant is not in the frozen route")
        expected_role = "entry" if self.participant_id == self.route.entry_id else "transit"
        if self.role != expected_role:
            raise ValueError("cascade technical role does not match the authenticated participant")
        if not isinstance(self.engine_identity, str) or not _SHA256.fullmatch(self.engine_identity):
            raise ValueError("cascade technical engine identity is invalid")
        for identity in (self.baseline_config_identity, self.prepared_config_identity):
            if not isinstance(identity, str) or not _SHA256.fullmatch(identity):
                raise ValueError("cascade technical config identity is invalid")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "route": self.route.to_document(),
            "protocol": self.protocol,
            "operation_id": self.operation_id,
            "plan_digest": self.plan_digest,
            "participant_id": self.participant_id,
            "role": self.role,
            "engine_identity": self.engine_identity,
            "baseline_config_identity": self.baseline_config_identity,
            "prepared_config_identity": self.prepared_config_identity,
        }

    @classmethod
    def from_document(cls, raw: object) -> CascadeTechnicalPreparation:
        keys = {
            "route",
            "protocol",
            "operation_id",
            "plan_digest",
            "participant_id",
            "role",
            "engine_identity",
            "baseline_config_identity",
            "prepared_config_identity",
        }
        if not isinstance(raw, dict) or set(raw) != keys:
            raise ValueError("cascade technical preparation has an invalid shape")
        value = cls(
            CascadeDefinition.from_document(raw["route"]),
            raw["protocol"],
            raw["operation_id"],
            raw["plan_digest"],
            raw["participant_id"],
            raw["role"],
            raw["engine_identity"],
            raw["baseline_config_identity"],
            raw["prepared_config_identity"],
        )
        value.validate()
        return value


class CascadePreparationStore:
    """Write-once protected bindings; render reads never create files or directories."""

    def __init__(self, *, host: HostBackend, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("cascade preparation root must be absolute")
        self._host = host
        self._root = root

    def save(self, preparation: CascadeTechnicalPreparation) -> CascadeTechnicalPreparation:
        preparation.validate()
        path = self._path(preparation)
        self._check_ancestors()
        self._host.ensure_directory(self._root, mode=0o700)
        self._check_root()
        encoded = json.dumps(preparation.to_document(), sort_keys=True, separators=(",", ":"))
        if not self._host.atomic_create(path, encoded, mode=0o600, durable=True):
            existing = self.load(
                preparation.operation_id,
                preparation.route.id,
                preparation.participant_id,
                preparation.protocol,
            )
            if existing != preparation:
                raise ValueError("cascade technical preparation is immutable for its operation")
            return existing
        return preparation

    def load(
        self,
        operation_id: str,
        cascade_id: str,
        participant_id: str,
        protocol: str,
    ) -> CascadeTechnicalPreparation:
        path = self._path_parts(operation_id, cascade_id, participant_id, protocol)
        self._check_root()
        if path.is_symlink() or not path.is_file():
            raise ValueError("cascade technical preparation is unavailable")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ValueError("cascade technical preparation permissions are unsafe")
        raw = json.loads(self._host.read_bytes(path, max_bytes=4096).decode("utf-8"))
        preparation = CascadeTechnicalPreparation.from_document(raw)
        if (
            preparation.operation_id != operation_id
            or preparation.route.id != cascade_id
            or preparation.participant_id != participant_id
            or preparation.protocol != protocol
        ):
            raise ValueError("cascade technical preparation scope does not match its file")
        return preparation

    def _path(self, preparation: CascadeTechnicalPreparation) -> Path:
        return self._path_parts(
            preparation.operation_id,
            preparation.route.id,
            preparation.participant_id,
            preparation.protocol,
        )

    def _path_parts(self, operation_id: str, cascade_id: str, participant_id: str, protocol: str) -> Path:
        for value in (operation_id, cascade_id, participant_id):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError("cascade technical preparation reference is invalid")
        if not isinstance(protocol, str) or protocol not in _PROTOCOLS:
            raise ValueError("cascade technical preparation protocol is invalid")
        encoded = json.dumps((operation_id, cascade_id, participant_id, protocol), separators=(",", ":"))
        key = hashlib.sha256(encoded.encode("ascii")).hexdigest()
        return self._root / f"{key}.json"

    def _check_ancestors(self) -> None:
        current = self._root
        while current != current.parent:
            if current.is_symlink():
                raise ValueError("cascade preparation path is an unsafe symbolic link")
            current = current.parent

    def _check_root(self) -> None:
        self._check_ancestors()
        if not self._root.is_dir():
            raise ValueError("cascade preparation store is unavailable")
        if os.name != "nt" and stat.S_IMODE(self._root.stat().st_mode) != 0o700:
            raise ValueError("cascade preparation directory permissions are unsafe")


AuthenticatedParticipantProvider = Callable[[Operation, CascadeDefinition], str | None]
EvidenceProvider = Callable[
    [AppState, Operation, CascadeDefinition, str, str, str, CascadeCredentialScope],
    CascadePreparationEvidence | None,
]


@dataclass
class ManagedNodeCascadePreparationOwner:
    """Mutate staging explicitly and validate it again through a read-only renderer port."""

    records: ManagedNodeRecords
    state_reader: Callable[[], AppState]
    credentials: CascadeCredentialStore
    store: CascadePreparationStore
    participant_id: str
    authenticated_participant: AuthenticatedParticipantProvider | None = None
    evidence_provider: EvidenceProvider | None = None
    renderable_operation: Callable[[str, str], bool] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.participant_id, str) or not _ID.fullmatch(self.participant_id):
            raise ValueError("cascade preparation participant identity is invalid")

    def should_prepare(self, route: CascadeDefinition) -> bool:
        return self.participant_id in {route.entry_id, route.exit_id}

    def prepare(self, operation_id: str, protocol: str) -> CascadeTechnicalPreparation:
        operation = self.records.find_operation(operation_id)
        if operation is None:
            raise KeyError(f"unknown cascade preparation operation {operation_id}")
        state = self.state_reader()
        route = _frozen_candidate(operation, state)
        if not isinstance(protocol, str) or protocol not in route.protocols or protocol not in _PROTOCOLS:
            raise ValueError("cascade preparation protocol is not selected by the frozen route")
        role = _local_role(route, self.participant_id)
        if self.authenticated_participant is None or self.evidence_provider is None:
            raise RuntimeError("authenticated participant and engine/context evidence providers are unavailable")
        try:
            authenticated_id = self.authenticated_participant(operation, route)
        except Exception:
            raise ValueError("authenticated cascade participant validation failed") from None
        if authenticated_id != self.participant_id:
            raise ValueError("authenticated cascade participant does not match the local receiver")
        scope = self.credentials.prepare(route.id)
        try:
            evidence = self.evidence_provider(state, operation, route, protocol, self.participant_id, role, scope)
        except Exception:
            raise RuntimeError("cascade technical preparation evidence provider failed") from None
        if not isinstance(evidence, CascadePreparationEvidence):
            raise RuntimeError("cascade technical preparation evidence is unavailable")
        evidence.validate()
        if evidence.current_config_identity not in {
            evidence.baseline_config_identity,
            evidence.prepared_config_identity,
        }:
            raise ValueError("cascade preparation current config is neither its baseline nor prepared identity")
        preparation = CascadeTechnicalPreparation(
            route,
            protocol,
            operation.id,
            operation.desired_digest,
            self.participant_id,
            role,
            evidence.engine_identity,
            evidence.baseline_config_identity,
            evidence.prepared_config_identity,
        )
        return self.store.save(preparation)

    def preparations_for_render(self, state: AppState) -> tuple[CascadeTechnicalPreparation, ...]:
        authenticated_participant = self.authenticated_participant
        evidence_provider = self.evidence_provider
        if authenticated_participant is None or evidence_provider is None:
            return ()
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        results = []
        for operation in namespace.operations:
            if operation.kind != "cascade_save" or not operation_is_active(operation):
                continue
            try:
                route = _frozen_candidate(operation, state)
            except (TypeError, ValueError):
                continue
            if not self.should_prepare(route):
                continue
            role = _local_role(route, self.participant_id)
            try:
                authenticated_id = authenticated_participant(operation, route)
            except Exception:
                continue
            if authenticated_id != self.participant_id:
                continue
            for protocol in route.protocols:
                if protocol not in _PROTOCOLS:
                    continue
                if self.renderable_operation is not None and not self.renderable_operation(operation.id, protocol):
                    continue
                try:
                    preparation = self.store.load(operation.id, route.id, self.participant_id, protocol)
                    preparation.validate()
                    if (
                        preparation.route != route
                        or preparation.plan_digest != operation.desired_digest
                        or preparation.role != role
                        or self.participant_id not in cascade_participants(operation)
                    ):
                        continue
                    scope = self.credentials.load(route.id)
                    try:
                        evidence = evidence_provider(
                            state, operation, route, protocol, self.participant_id, role, scope
                        )
                    except Exception:
                        continue
                    if not isinstance(evidence, CascadePreparationEvidence):
                        continue
                    evidence.validate()
                    if (
                        evidence.engine_identity != preparation.engine_identity
                        or evidence.baseline_config_identity != preparation.baseline_config_identity
                        or evidence.prepared_config_identity != preparation.prepared_config_identity
                        or evidence.current_config_identity
                        not in {preparation.baseline_config_identity, preparation.prepared_config_identity}
                    ):
                        continue
                    results.append(preparation)
                except (OSError, ValueError):
                    continue
        return tuple(results)


def _frozen_candidate(operation: Operation, state: AppState) -> CascadeDefinition:
    if (
        operation.kind != "cascade_save"
        or not operation_is_active(operation)
        or operation.id not in {item.id for item in managed_nodes_from_extensions(state.feature_extensions).operations}
    ):
        raise ValueError("cascade preparation is not owned by an active frozen operation")
    namespace = managed_nodes_from_extensions(state.feature_extensions)
    namespace_operation = next(item for item in namespace.operations if item.id == operation.id)
    if namespace_operation != operation or not isinstance(operation.plan, dict):
        raise ValueError("cascade preparation operation differs from persisted frozen state")
    if "snapshot" not in operation.completed_steps:
        raise ValueError("cascade preparation requires durable participant snapshots")
    assert_cascade_unleased(namespace, operation)
    route = cascade_candidate(operation)
    if route is None:
        raise ValueError("cascade preparation has no frozen candidate")
    return route


def _local_role(route: CascadeDefinition, participant_id: str) -> str:
    if participant_id == route.entry_id:
        return "entry"
    if participant_id == route.exit_id:
        return "transit"
    raise ValueError("authenticated cascade participant is not in the frozen route")


__all__ = [
    "CascadePreparationEvidence",
    "CascadePreparationStore",
    "CascadeTechnicalPreparation",
    "ManagedNodeCascadePreparationOwner",
]
