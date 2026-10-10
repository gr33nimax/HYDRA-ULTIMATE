"""Five-minute and targeted managed-node sync with per-node durable apply IDs."""

from __future__ import annotations

import secrets
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable
from typing import Any

from hydra.contracts.managed_node_models import NodeDesired
from hydra.contracts.managed_node_observations import CheckResult, DiagnosticReport, NodeSample, SyncReport
from hydra.core.state_models import AppState
from hydra.services.security_intel import lookup_ip
from hydra.services.managed_nodes.accounting import apply_traffic_samples
from hydra.services.managed_nodes.checks import ManagedNodeCheckService
from hydra.services.managed_nodes.client import ManagedNodeError
from hydra.services.managed_nodes.desired import build_node_desired
from hydra.services.managed_nodes.observations import ManagedNodeObservationStore, NodeObservation
from hydra.services.managed_nodes.profile_store import ManagedNodeProfileStore
from hydra.services.managed_nodes.profiles import expected_profile_pairs, expected_profile_users
from hydra.services.managed_nodes.records import ManagedNodeRecords
from hydra.services.managed_nodes.sync_operations import (
    ManagedNodeSyncOperations,
    bounded_error,
    notify_progress,
)


class ManagedNodeSyncService:
    def __init__(
        self,
        *,
        records: ManagedNodeRecords,
        state_reader: Callable[[], AppState],
        state_updater: Callable,
        client_factory: Callable[[Any], Any],
        profile_store: ManagedNodeProfileStore,
        observations: ManagedNodeObservationStore,
        checks: ManagedNodeCheckService,
        local_user_sync: Callable[[], tuple[AppState, dict[str, str], list[str]]],
        operation_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
        max_parallel_nodes: int = 4,
        apply_timeout_seconds: float = 60.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if type(max_parallel_nodes) is not int or not 1 <= max_parallel_nodes <= 8:
            raise ValueError("managed-node sync concurrency must be 1..8")
        if (
            isinstance(apply_timeout_seconds, bool)
            or not isinstance(apply_timeout_seconds, (int, float))
            or not math.isfinite(apply_timeout_seconds)
            or not 0 < apply_timeout_seconds <= 300
        ):
            raise ValueError("managed-node apply timeout must be finite and in (0, 300] seconds")
        self._apply_timeout = float(apply_timeout_seconds)
        self._clock = monotonic
        self._records = records
        self._state_reader = state_reader
        self._state_updater = state_updater
        self._client_factory = client_factory
        self._profile_store = profile_store
        self._observations = observations
        self._checks = checks
        self._local_user_sync = local_user_sync
        self._apply_operations = ManagedNodeSyncOperations(
            records=records,
            observations=observations,
            operation_id_factory=operation_id_factory,
            monotonic=monotonic,
            sleep=sleep,
        )
        self._parallel = max_parallel_nodes
        self._locks_guard = threading.Lock()
        self._node_locks: dict[str, threading.Lock] = {}

    def sync(self, node_id: str | None = None, progress=None) -> SyncReport:
        selected = self._select_nodes(node_id)
        samples, errors = self._collect(selected)
        if node_id is None:
            _state, _blocked, local_failures = self._local_user_sync()
        else:
            local_failures = []
        results = self._reconcile(selected, samples, progress=progress, deep=True)
        node_errors = [value["error"] for value in results.values() if value.get("status") == "failed"]
        return SyncReport(
            nodes=results,
            local="error" if local_failures else "ok",
            errors=[*local_failures, *errors, *node_errors],
            pending_operations=[
                str(value["operation_id"])
                for value in results.values()
                if value.get("status") == "pending" and value.get("operation_id")
            ],
        )

    def run_cycle(self, local_sync: Callable[[], tuple[AppState, dict[str, str], list[str]]]):
        """Poll node counters, let base policy block users, then deliver latest state."""
        selected = self._select_nodes(None)
        samples, errors = self._collect(selected)
        state, blocked, local_failures = local_sync()
        results = self._reconcile(selected, samples, progress=None, deep=True)
        errors.extend(value["error"] for value in results.values() if value.get("status") == "failed")
        return self._state_reader(), blocked, [*local_failures, *errors]

    def check(self, node_id: str, *, deep: bool, progress=None) -> DiagnosticReport:
        definition = self._records.find_definition(node_id)
        if definition is None:
            raise KeyError(f"unknown managed node {node_id}")
        lock = self._lock_for(node_id)
        if not lock.acquire(timeout=10):
            raise RuntimeError("managed-node operation is still running")
        try:
            return self._checks.check(node_id, deep=deep)
        finally:
            lock.release()

    def _select_nodes(self, node_id: str | None) -> list[Any]:
        definitions = self._records.list_definitions()
        if node_id is None:
            return definitions
        definition = next((item for item in definitions if item.id == node_id), None)
        if definition is None:
            raise KeyError(f"unknown managed node {node_id}")
        return [definition]

    def _collect(self, definitions: list[Any]) -> tuple[dict[str, NodeSample], list[str]]:
        samples: dict[str, NodeSample] = {}
        errors: list[str] = []
        if not definitions:
            return samples, errors
        with ThreadPoolExecutor(
            max_workers=min(self._parallel, len(definitions)), thread_name_prefix="managed-node-sample"
        ) as pool:
            futures = {pool.submit(self._collect_one, definition): definition for definition in definitions}
            for future in as_completed(futures):
                definition = futures[future]
                try:
                    sample, error = future.result()
                except Exception as exc:
                    sample, error = None, bounded_error(exc)
                if sample is not None:
                    samples[definition.id] = sample
                if error:
                    errors.append(f"node {definition.id}: {error}")
        return samples, errors

    def _collect_one(self, definition) -> tuple[NodeSample | None, str]:
        started = time.monotonic()
        checked_at = self._observations.checked_at()
        try:
            sample = self._client_factory(definition).sync_sample(time.monotonic() + 10.0)
            if not isinstance(sample, NodeSample) or sample.node_id != definition.id:
                raise ValueError("management response identifies another node")
            management = CheckResult(
                "management", definition.id, "ok", checked_at, int((time.monotonic() - started) * 1000), "http", ""
            )
            self._state_updater(lambda state: apply_traffic_samples(state, definition.id, sample.traffic))
            previous = self._observations.read(definition.id)
            self._observations.write(
                NodeObservation(
                    definition.id,
                    management,
                    sample,
                    previous.subscription if previous else None,
                    previous.protocols if previous else {},
                    checked_at,
                    checked_at,
                )
            )
            # Warm the shared geography cache outside subscription request handling.
            lookup_ip(definition.address)
            return sample, ""
        except ManagedNodeError as exc:
            reason = bounded_error(exc.reason)
            management = CheckResult(
                "management",
                definition.id,
                "error",
                checked_at,
                int((time.monotonic() - started) * 1000),
                exc.stage,
                reason,
            )
            self._store_failure(definition.id, management)
            return None, reason
        except Exception as exc:
            reason = bounded_error(exc)
            management = CheckResult(
                "management",
                definition.id,
                "error",
                checked_at,
                int((time.monotonic() - started) * 1000),
                "validation",
                reason,
            )
            self._store_failure(definition.id, management)
            return None, reason

    def _reconcile(self, definitions, samples, *, progress, deep: bool) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(
            max_workers=min(self._parallel, max(1, len(definitions))), thread_name_prefix="managed-node-sync"
        ) as pool:
            futures = {
                pool.submit(self._sync_one, definition, samples.get(definition.id), progress, deep): definition
                for definition in definitions
            }
            for future in as_completed(futures):
                definition = futures[future]
                try:
                    results[definition.id] = future.result()
                except Exception as exc:
                    results[definition.id] = {"status": "failed", "error": bounded_error(exc)}
        return results

    def _sync_one(self, definition, sample: NodeSample | None, progress, deep: bool) -> dict[str, Any]:
        lock = self._lock_for(definition.id)
        if not lock.acquire(timeout=10):
            return {"status": "pending", "error": "managed-node operation is still running"}
        try:
            if sample is None:
                return {"status": "failed", "error": "management response is unavailable"}
            client = self._client_factory(definition)
            deadline = self._clock() + self._apply_timeout
            while True:
                desired = build_node_desired(definition, self._state_reader(), self._records)
                operation = self._apply_operations.operation_for(definition.id, desired)
                if operation is None:
                    receipt = sample.receipt
                    if (
                        receipt
                        and receipt.desired_digest == desired.digest
                        and receipt.runtime_id == sample.runtime.get("apply_generation")
                        and sample.runtime.get("engine_active") is True
                    ):
                        report = self._checks.evaluate(definition.id, sample, desired=desired, deep=deep)
                        self._store_report(definition.id, report, sample)
                        return {"status": "ok", "users_digest": receipt.users_digest}
                    operation = self._apply_operations.new_operation(definition.id, desired)
                apply_desired = self._apply_operations.operation_desired(operation, desired)
                result, error = self._apply_operations.remote_apply(
                    client, definition.id, operation, apply_desired, deadline=deadline, progress=progress
                )
                if error:
                    status = (
                        "pending"
                        if result is None or result.state in {"pending", "running", "recovery_required"}
                        else "failed"
                    )
                    return {"status": status, "operation_id": operation.id, "error": error}
                if result is None or result.state != "succeeded" or result.receipt is None:
                    return {"status": "pending", "operation_id": operation.id, "users_digest": sample.users_digest}
                receipt = result.receipt
                if (
                    receipt.operation_id != operation.id
                    or receipt.desired_digest != apply_desired.digest
                    or receipt.users_digest != apply_desired.users_digest
                ):
                    self._apply_operations.mark_failed(
                        operation.id, "apply receipt does not match the submitted desired state"
                    )
                    return {"status": "failed", "operation_id": operation.id, "error": "apply receipt mismatch"}
                try:
                    confirmed_sample = client.state(min(deadline, self._clock() + 10.0))
                    if (
                        not isinstance(confirmed_sample, NodeSample)
                        or confirmed_sample.node_id != definition.id
                        or confirmed_sample.receipt != receipt
                        or confirmed_sample.runtime.get("apply_generation") != receipt.runtime_id
                        or confirmed_sample.runtime.get("engine_active") is not True
                    ):
                        raise ValueError("remote runtime does not confirm the apply receipt")
                    bundle = client.profiles(min(deadline, self._clock() + 10.0))
                    if bundle.node_id != definition.id or bundle.receipt != receipt:
                        raise ValueError("confirmed profile response does not match the apply receipt")
                    _validate_profile_coverage(bundle, apply_desired)
                    expected_users = expected_profile_users(
                        expected_profile_pairs(apply_desired.users, apply_desired.protocols)
                    )
                    self._profile_store.commit(bundle, expected_users=expected_users)
                except Exception as exc:
                    self._apply_operations.mark_pending(operation.id, bounded_error(exc))
                    return {"status": "pending", "operation_id": operation.id, "error": bounded_error(exc)}
                self._apply_operations.complete_operation(operation.id, receipt)
                notify_progress(progress, operation.id, "apply", "succeeded")
                sample = confirmed_sample
                desired = build_node_desired(definition, self._state_reader(), self._records)
                if apply_desired.digest != desired.digest:
                    continue
                report = self._checks.evaluate(definition.id, sample, desired=desired, deep=deep)
                self._store_report(definition.id, report, sample)
                return {"status": "ok", "operation_id": operation.id, "users_digest": receipt.users_digest}
        finally:
            lock.release()

    def _store_failure(self, node_id: str, management: CheckResult) -> None:
        previous = self._observations.read(node_id)
        self._observations.write(
            NodeObservation(
                node_id,
                management,
                previous.sample if previous else None,
                previous.subscription if previous else None,
                previous.protocols if previous else {},
                self._observations.checked_at(),
                previous.sample_checked_at if previous else "",
            )
        )

    def _store_report(self, node_id: str, report: DiagnosticReport, sample: NodeSample) -> None:
        checked_at = self._observations.checked_at()
        self._observations.write(
            NodeObservation(
                node_id,
                report.management,
                sample,
                report.subscription,
                report.protocols,
                checked_at,
                checked_at,
            )
        )

    def _lock_for(self, node_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._node_locks.setdefault(node_id, threading.Lock())


def _validate_profile_coverage(bundle, desired: NodeDesired) -> None:
    expected = expected_profile_pairs(desired.users, desired.protocols)
    actual = {(item.user_uuid, item.protocol) for item in bundle.profiles}
    if actual != expected:
        raise ValueError("confirmed profile bundle does not cover the desired users and protocols")


__all__ = ["ManagedNodeSyncService"]
