"""Build read-only managed-node cards from revision-independent observations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from hydra.contracts.managed_node_observations import NodeView
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.desired import build_node_desired
from hydra.services.managed_nodes.observations import ManagedNodeObservationStore
from hydra.services.managed_nodes.records import ManagedNodeRecords


class ManagedNodeStatusService:
    def __init__(
        self,
        *,
        records: ManagedNodeRecords,
        observations: ManagedNodeObservationStore,
        state_reader: Callable[[], AppState],
        stale_after_seconds: int = 600,
    ) -> None:
        self._records = records
        self._observations = observations
        self._state_reader = state_reader
        self._stale_after = stale_after_seconds

    def list(self) -> list[NodeView]:
        state = self._state_reader()
        operations = self._records.list_operations()
        views = []
        for definition in self._records.list_definitions():
            related = [item for item in operations if item.target_id == definition.id]
            latest = related[-1] if related else None
            observation = self._observations.read(definition.id)
            sample = observation.sample if observation else None
            management = observation.management if observation and self._fresh(observation.checked_at) else None
            runtime: dict[str, Any] | None = None
            if sample is not None:
                runtime = dict(sample.runtime)
                runtime["observed_at"] = observation.sample_checked_at if observation is not None else ""
            protocol_checks = {}
            if observation is not None:
                for name, checks in observation.protocols.items():
                    result = checks.get("connection")
                    if result is None or result.outcome == "not_applicable":
                        result = checks.get("configuration")
                    if result is not None:
                        protocol_checks[name] = result
            sub_state = self._subscription_state(definition, state, related, observation)
            views.append(NodeView(
                definition=definition,
                management_check=management,
                users_applied=sample.users_applied if sample else None,
                users_total=len(state.users),
                sub_state=sub_state,
                runtime=runtime,
                protocol_checks=protocol_checks,
                metrics=dict(sample.metrics) if sample else {},
                operation=latest,
            ))
        return views

    def _subscription_state(self, definition, state, operations, observation) -> str:
        latest = operations[-1] if operations else None
        if latest is not None and latest.state in {"pending", "running", "recovery_required"}:
            return "wait"
        if latest is not None and latest.state == "failed":
            return "error"
        if observation is None or observation.sample is None:
            return "unknown"
        if observation.subscription is not None and observation.subscription.outcome == "error":
            return "error"
        sample = observation.sample
        receipt = sample.receipt
        if receipt is None or receipt.runtime_id != sample.runtime.get("apply_generation"):
            return "wait"
        try:
            desired = build_node_desired(definition, state, self._records)
        except (ValueError, KeyError):
            return "error"
        if receipt.desired_digest != desired.digest:
            return "wait"
        if observation.subscription is not None and observation.subscription.outcome == "ok":
            return "sync"
        return "wait"

    def _fresh(self, checked_at: str) -> bool:
        try:
            timestamp = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - timestamp).total_seconds()
            return 0 <= age <= self._stale_after
        except (TypeError, ValueError):
            return False


__all__ = ["ManagedNodeStatusService"]
