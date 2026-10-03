"""Protected, revision-independent diagnostics and last-good node samples."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hydra.contracts.managed_node_models import NodeDesired
from hydra.contracts.managed_node_observations import CheckResult, NodeSample
from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.access import assignment_from_user
from hydra.services.managed_nodes.accounting import (
    project_node_counters,
    read_node_counters,
    record_node_counters,
    traffic_reset_epoch,
)

_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class NodeObservation:
    node_id: str
    management: CheckResult
    sample: NodeSample | None = None
    subscription: CheckResult | None = None
    protocols: dict[str, dict[str, CheckResult]] = field(default_factory=dict)
    checked_at: str = ""
    sample_checked_at: str = ""

    def to_document(self) -> dict[str, Any]:
        self.management.validate()
        if self.sample is not None:
            self.sample.validate()
        if self.subscription is not None:
            self.subscription.validate()
        return {
            "version": 1,
            "node_id": self.node_id,
            "management": self.management.to_document(),
            "sample": self.sample.to_document() if self.sample else None,
            "subscription": self.subscription.to_document() if self.subscription else None,
            "protocols": {
                name: {kind: result.to_document() for kind, result in checks.items()}
                for name, checks in self.protocols.items()
            },
            "checked_at": self.checked_at,
            "sample_checked_at": self.sample_checked_at,
        }


class ManagedNodeObservationStore:
    def __init__(self, *, host: HostBackend, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("managed-node observations root must be absolute")
        self._host = host
        self._root = root

    def read(self, node_id: str) -> NodeObservation | None:
        path = self._path(node_id)
        if path.is_symlink() or not path.is_file():
            return None
        try:
            raw = json.loads(self._host.read_bytes(path, max_bytes=_MAX_BYTES).decode("utf-8"))
            if not isinstance(raw, dict) or set(raw) != {"version", "node_id", "management", "sample", "subscription", "protocols", "checked_at", "sample_checked_at"} or raw["version"] != 1 or raw["node_id"] != node_id:
                return None
            protocols = {
                name: {kind: CheckResult.from_document(result) for kind, result in checks.items()}
                for name, checks in raw["protocols"].items()
            }
            observation = NodeObservation(
                node_id=node_id,
                management=CheckResult.from_document(raw["management"]),
                sample=NodeSample.from_document(raw["sample"]) if raw["sample"] is not None else None,
                subscription=CheckResult.from_document(raw["subscription"]) if raw["subscription"] is not None else None,
                protocols=protocols,
                checked_at=raw["checked_at"],
                sample_checked_at=raw["sample_checked_at"],
            )
            if observation.management.target_id != node_id or observation.sample is not None and observation.sample.node_id != node_id:
                return None
            return observation
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None

    def write(self, observation: NodeObservation) -> None:
        if not _NODE_ID.fullmatch(observation.node_id):
            raise ValueError("managed-node observation identity is invalid")
        path = self._path(observation.node_id)
        if self._root.is_symlink() or path.is_symlink():
            raise ValueError("managed-node observation path is unsafe")
        self._host.ensure_directory(self._root, mode=0o700)
        payload = json.dumps(observation.to_document(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(payload.encode()) > _MAX_BYTES:
            raise ValueError("managed-node observation exceeds the size limit")
        self._host.atomic_write(path, payload, mode=0o600, durable=True)

    def checked_at(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _path(self, node_id: str) -> Path:
        if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
            raise ValueError("managed-node observation identity is invalid")
        return self._root / f"{node_id}.json"


class ManagedNodeObservationProvider:
    """Separate read-only status projection from explicit sync accounting writes."""

    def __init__(
        self, *, node_id: str, records, runtime, protocols,
        state_reader: Callable[[], AppState],
        state_updater: Callable[[Callable[[AppState], Any]], tuple[AppState, Any]] | None = None,
        mutation_lock: Callable[[], AbstractContextManager[None]] | None = None,
    ) -> None:
        self._node_id = node_id
        self._records = records
        self._runtime = runtime
        self._protocols = protocols
        self._state_reader = state_reader
        self._state_updater = state_updater
        self._mutation_lock = mutation_lock

    def read(self) -> NodeSample:
        return self._sample(commit_accounting=False)

    def read_with_state(self) -> tuple[NodeSample, AppState]:
        state = self._state_reader()
        return self._sample(commit_accounting=False, state=state), state

    def sync_sample(self) -> NodeSample:
        if self._state_updater is None or self._mutation_lock is None:
            raise RuntimeError("managed-node accounting sync is unavailable")
        with self._mutation_lock():
            return self._sample(commit_accounting=True)

    def _sample(self, *, commit_accounting: bool, state: AppState | None = None) -> NodeSample:
        if state is None:
            state = self._state_reader()
        runtime = self._runtime.observe()
        runtime_id = runtime.get("runtime_id")
        traffic = []
        if runtime.get("engine_active") is True and isinstance(runtime_id, str) and runtime_id:
            counters = read_node_counters(state, protocols=self._protocols)
            if counters:
                if commit_accounting:
                    updater = self._state_updater
                    if updater is None:
                        raise RuntimeError("managed-node accounting sync is unavailable")
                    updated_state, traffic = updater(
                        lambda latest: record_node_counters(latest, counters, runtime_id=runtime_id)
                    )
                    if not isinstance(updated_state, AppState):
                        raise TypeError("managed-node accounting update returned invalid state")
                    state = updated_state
                else:
                    traffic = project_node_counters(state, counters, runtime_id=runtime_id)
        runtime["protocols"] = self._protocol_facts(state)
        receipt = self._current_receipt(state, runtime)
        return NodeSample(
            self._node_id, receipt, runtime,
            len(state.users) if receipt else None,
            receipt.users_digest if receipt else None,
            self._runtime.metrics(), traffic,
        )

    def _protocol_facts(self, state: AppState) -> dict[str, dict[str, bool]]:
        facts = {}
        for name, desired in state.protocols.items():
            if not desired.enabled:
                continue
            try:
                health = self._protocols.health(state, name)
                configured = bool(getattr(health, "healthy", health))
            except Exception:
                configured = False
            facts[name] = {"configured": configured}
        return facts

    def _current_receipt(self, state: AppState, runtime: dict[str, Any]):
        if runtime.get("engine_active") is not True:
            return None
        operation = next((
            item for item in reversed(self._records.list_operations())
            if item.kind == "apply" and item.target_id == self._node_id
            and item.state == "succeeded" and item.receipt is not None
        ), None)
        if operation is None or operation.plan is None:
            return None
        expected = NodeDesired.from_document(operation.plan)
        actual_users = [
            assignment_from_user(user, reset_epoch=traffic_reset_epoch(state, user))
            for user in state.users
        ]
        actual_digest = NodeDesired(
            self._node_id, expected.revision, actual_users,
            expected.protocols, expected.cascades,
        ).users_digest
        current_protocols = {name for name, plugin in state.protocols.items() if plugin.enabled}
        expected_protocols = {item.name for item in expected.protocols}
        config_matches = current_protocols == expected_protocols and all(
            state.protocols.get(item.name) is not None
            and all(state.protocols[item.name].config.get(key) == value for key, value in item.parameters.items())
            for item in expected.protocols
        )
        receipt = operation.receipt
        if (
            receipt.desired_digest == expected.digest
            and receipt.runtime_id == runtime.get("apply_generation")
            and receipt.users_digest == actual_digest
            and config_matches
        ):
            return receipt
        return None


__all__ = ["ManagedNodeObservationProvider", "ManagedNodeObservationStore", "NodeObservation"]
