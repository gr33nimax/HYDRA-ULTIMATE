"""Base-side desired-state reconciliation and confirmed export publication."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Callable, Literal

from hydra.contracts.node_export import NodeClientExport
from hydra.contracts.node_snapshot import NodeDesiredSnapshot, NodeUserProjection
from hydra.services.node_traffic_accounting import traffic_reset_epoch
from hydra.contracts.node_validation import NODE_CONTRACT_VERSION
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.services.nodes.control_client import NodeControlPort
from hydra.services.nodes.snapshot_store import NodeSnapshotStore

_LOGGER = logging.getLogger(__name__)
_MAX_GENERATION = 2**63 - 1


@dataclass(frozen=True)
class NodeSyncResult:
    node_id: str
    generation: int
    status: Literal["published", "unchanged"]
    sha256: str = ""
    # Protocol -> how many eligible users this export actually serves, plus
    # non-fatal gaps such as a transport whose prerequisites are unmet.
    coverage: dict[str, int] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    # The revision the node reports running, which is the only proof that an update
    # actually landed: the base's own copy is a target, not a fact.
    installed_revision: str = ""


class NodeSnapshotReconciler:
    """Apply a complete node snapshot, then atomically publish its export pointer."""

    def __init__(
        self,
        *,
        state_updater: Callable,
        client_for: Callable[[NodeConfig], NodeControlPort],
        snapshot_store: NodeSnapshotStore,
    ):
        self.state_updater = state_updater
        self.client_for = client_for
        self.snapshot_store = snapshot_store
        self._lock = threading.RLock()

    def refresh(self, node_id: str, *, force: bool = False) -> NodeSyncResult:
        """Reconcile the latest full desired state and publish only a confirmed export."""
        with self._lock:
            node, snapshot = self._reserve_generation(node_id, force=force)
            if snapshot is None:
                return NodeSyncResult(node_id, node.published_generation, "unchanged", node.published_digest)

            client = self.client_for(node)
            health = self._check_health(client, node_id)
            applied = client.apply(snapshot)
            if applied.get("generation") != snapshot.generation or not isinstance(applied.get("already_applied"), bool):
                raise RuntimeError("node did not confirm the requested generation")
            exported = client.export()
            coverage, warnings = self._validate_export(exported, node_id, snapshot.generation, snapshot)
            stored = self.snapshot_store.store(exported)
            previous = self._publish_pointer(
                node_id=node_id,
                generation=snapshot.generation,
                desired_digest=node.desired_digest,
                stored_digest=stored.sha256,
            )
            self._remove_previous(previous, stored)
            return NodeSyncResult(
                node_id,
                snapshot.generation,
                "published",
                stored.sha256,
                coverage,
                tuple(warnings),
                _revision(health),
            )

    def _reserve_generation(
        self,
        node_id: str,
        *,
        force: bool,
    ) -> tuple[NodeConfig, NodeDesiredSnapshot | None]:
        reservation: tuple[NodeConfig, NodeDesiredSnapshot | None] | None = None

        def reserve(state: AppState) -> None:
            nonlocal reservation
            node = self._find_node(state, node_id)
            candidate = self._snapshot(state, node, node.generation)
            desired_digest = self._desired_digest(candidate)
            if not force and node.desired_digest == desired_digest:
                if node.generation > node.published_generation:
                    reservation = (deepcopy(node), candidate)
                    return
                if node.published_digest:
                    reservation = (deepcopy(node), None)
                    return
            if node.generation >= _MAX_GENERATION:
                raise ValueError("node generation limit reached")
            node.generation += 1
            node.desired_digest = desired_digest
            reservation = (deepcopy(node), self._snapshot(state, node, node.generation))

        self.state_updater(reserve)
        if reservation is None:
            raise RuntimeError("node generation reservation did not complete")
        return reservation

    @staticmethod
    def _snapshot(state: AppState, node: NodeConfig, generation: int) -> NodeDesiredSnapshot:
        users = tuple(
            NodeUserProjection(
                email=user.email,
                uuid=user.uuid,
                blocked=user.blocked,
                expiry_date=user.expiry_date,
                disabled_protocols=tuple(user.disabled_protocols),
                traffic_limit_gb=user.traffic_limit_gb,
                traffic_reset_epoch=traffic_reset_epoch(state, user),
            )
            for user in sorted(state.users, key=lambda item: item.uuid)
        )
        snapshot = NodeDesiredSnapshot(
            node_id=node.id,
            generation=generation,
            users=users,
            protocols=node.snapshot_protocols(),
        )
        snapshot.validate()
        return snapshot

    @staticmethod
    def _desired_digest(snapshot: NodeDesiredSnapshot) -> str:
        document = snapshot.to_document()
        document["generation"] = 0
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _find_node(state: AppState, node_id: str) -> NodeConfig:
        for node in state.nodes:
            if node.id == node_id:
                return node
        raise ValueError(f"managed node {node_id} was not found")

    @staticmethod
    def _check_health(client: NodeControlPort, node_id: str) -> dict:
        health = client.health()
        if (
            not isinstance(health.get("ok"), bool)
            or not health["ok"]
            or health.get("node_id") != node_id
            or health.get("contract_version") != NODE_CONTRACT_VERSION
        ):
            raise RuntimeError("node health or contract check failed")
        return health

    @classmethod
    def _validate_export(
        cls,
        exported: NodeClientExport,
        node_id: str,
        generation: int,
        snapshot: NodeDesiredSnapshot,
    ) -> tuple[dict[str, int], list[str]]:
        if not isinstance(exported, NodeClientExport):
            raise RuntimeError("node returned an invalid export")
        exported.validate()
        if exported.node_id != node_id or exported.generation != generation:
            raise RuntimeError("node export does not match the applied generation")
        return cls._coverage(exported, snapshot)

    @staticmethod
    def _coverage(
        exported: NodeClientExport,
        snapshot: NodeDesiredSnapshot,
    ) -> tuple[dict[str, int], list[str]]:
        """Refuse a publication that carries nothing, and describe the rest.

        A published generation is exactly what subscriptions read, so an export with no
        client profiles must never be called published. Partial coverage is a different
        case: one transport whose prerequisites are unmet must not cost the node its
        working profiles, so it is reported as a warning instead of failing the node.
        """
        enabled = tuple(sorted(name for name, spec in snapshot.protocols.items() if spec.enabled))
        eligible = [projection for projection in snapshot.users if not projection.blocked]
        coverage = {name: 0 for name in enabled}
        users_without_profiles = 0
        for projection in eligible:
            exported_user = exported.users.get(projection.uuid)
            served = {profile.protocol for profile in exported_user.profiles} if exported_user else set()
            for name in served & set(enabled):
                coverage[name] += 1
            if not served and set(enabled) - set(projection.disabled_protocols):
                users_without_profiles += 1
        if enabled and eligible and not any(coverage.values()):
            raise RuntimeError("node export contains no client profiles")
        warnings: list[str] = []
        if users_without_profiles:
            warnings.append(f"users_without_profiles={users_without_profiles}")
        uncovered = [
            name
            for name in enabled
            if not coverage[name] and not all(name in projection.disabled_protocols for projection in eligible)
        ]
        if uncovered:
            warnings.append("protocols_without_profiles=" + ",".join(uncovered))
        return coverage, warnings

    def _publish_pointer(
        self,
        *,
        node_id: str,
        generation: int,
        desired_digest: str,
        stored_digest: str,
    ) -> tuple[int, str] | None:
        previous: tuple[int, str] | None = None

        def publish(state: AppState) -> None:
            nonlocal previous
            node = self._find_node(state, node_id)
            current_digest = self._desired_digest(self._snapshot(state, node, generation))
            if (
                node.generation != generation
                or node.desired_digest != desired_digest
                or current_digest != desired_digest
            ):
                raise RuntimeError("desired state changed before export publication")
            if node.published_generation == generation and node.published_digest == stored_digest:
                return
            previous = (node.published_generation, node.published_digest)
            node.published_generation = generation
            node.published_digest = stored_digest

        self.state_updater(publish)
        return previous

    def _remove_previous(self, previous: tuple[int, str] | None, stored) -> None:
        if previous is None:
            return
        generation, digest = previous
        if generation <= 0 or not digest or (generation, digest) == (stored.generation, stored.sha256):
            return
        try:
            self.snapshot_store.delete(stored.node_id, generation, digest)
        except Exception:
            _LOGGER.warning("Old node export cleanup failed; published snapshot remains valid")


def _revision(health: dict) -> str:
    """Read the node's reported revision; an older node without the field is unknown."""
    raw = health.get("revision")
    if not isinstance(raw, str):
        return ""
    return raw[:64] if raw.isprintable() else ""


__all__ = ["NodeSnapshotReconciler", "NodeSyncResult"]
