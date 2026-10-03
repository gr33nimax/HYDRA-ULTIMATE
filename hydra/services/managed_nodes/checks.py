"""Truthful management, runtime, user, SUB and native-client diagnostics."""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from hydra.contracts.managed_node_observations import CheckResult, DiagnosticReport, NodeSample
from hydra.contracts.managed_node_probe import ProbeMaterials
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.client import ManagedNodeError
from hydra.services.managed_nodes.desired import build_node_desired
from hydra.services.managed_nodes.observations import ManagedNodeObservationStore, NodeObservation
from hydra.services.managed_nodes.profile_store import ManagedNodeProfileStore
from hydra.services.managed_nodes.profiles import expected_profile_pairs
from hydra.services.managed_nodes.probe_clients import ManagedNodeProbeClient
from hydra.services.managed_nodes.records import ManagedNodeRecords

_SUPPORTED_PROBES = {"vless", "anytls"}


class ManagedNodeCheckService:
    def __init__(
        self,
        *,
        records: ManagedNodeRecords,
        state_reader: Callable[[], AppState],
        client_factory: Callable[[Any], Any],
        profile_store: ManagedNodeProfileStore,
        observations: ManagedNodeObservationStore,
        probe_client: ManagedNodeProbeClient,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._records = records
        self._state_reader = state_reader
        self._client_factory = client_factory
        self._profile_store = profile_store
        self._observations = observations
        self._probe_client = probe_client
        self._clock = clock

    def check(self, node_id: str, *, deep: bool) -> DiagnosticReport:
        definition = self._records.find_definition(node_id)
        if definition is None:
            raise KeyError(f"unknown managed node {node_id}")
        previous = self._observations.read(node_id)
        started = time.monotonic()
        sample: NodeSample | None = None
        management: CheckResult
        try:
            response = self._client_factory(definition).state(time.monotonic() + 10.0)
            if not isinstance(response, NodeSample) or response.node_id != node_id:
                raise ValueError("management response identifies another node")
            sample = response
            management = self._result("management", node_id, "ok", started, "http", "")
        except ManagedNodeError as exc:
            management = self._result("management", node_id, "error", started, exc.stage, exc.reason)
        except Exception as exc:
            management = self._result("management", node_id, "error", started, "validation", _safe_reason(exc))

        state = self._state_reader()
        desired = build_node_desired(definition, state, self._records)
        if sample is None:
            report = self._unknown_report(node_id, management)
            stored = NodeObservation(
                node_id, management, previous.sample if previous else None,
                previous.subscription if previous else None,
                previous.protocols if previous else {},
                self._observations.checked_at(),
                previous.sample_checked_at if previous else "",
            )
        else:
            report = self.evaluate(node_id, sample, desired=desired, deep=deep)
            checked_at = self._observations.checked_at()
            stored = NodeObservation(
                node_id, report.management, sample, report.subscription,
                report.protocols, checked_at, checked_at,
            )
        self._observations.write(stored)
        return report

    def evaluate(
        self,
        node_id: str,
        sample: NodeSample,
        *,
        desired=None,
        deep: bool,
    ) -> DiagnosticReport:
        checked_at = self._clock().isoformat()
        started = time.monotonic()
        state = self._state_reader()
        definition = self._records.find_definition(node_id)
        if definition is None:
            raise KeyError(f"unknown managed node {node_id}")
        expected = desired or build_node_desired(definition, state, self._records)
        management = self._result("management", node_id, "ok", started, "http", "", checked_at)
        active = sample.runtime.get("engine_active") is True
        runtime = self._result(
            "runtime", node_id, "ok" if active else "error", started,
            "runtime", "" if active else "Sing-Box runtime is not confirmed", checked_at,
        )
        receipt = sample.receipt
        receipt_current = bool(
            receipt and active and sample.runtime.get("apply_generation") == receipt.runtime_id
            and receipt.desired_digest == expected.digest
        )
        users_ok = bool(
            receipt_current and sample.users_digest == expected.users_digest
            and sample.users_applied == len(expected.users)
        )
        users = self._result(
            "users", node_id, "ok" if users_ok else "error", started, "apply_receipt",
            "" if users_ok else "applied user identities or restrictions differ from the base", checked_at,
        )
        subscription = self._subscription_result(node_id, expected, receipt, checked_at)
        protocol_checks: dict[str, dict[str, CheckResult]] = {}
        probe_materials = None
        probe_deadline = time.monotonic() + 10.0
        if deep and receipt_current:
            try:
                probe_materials = self._client_factory(definition).probe_materials(probe_deadline)
                if probe_materials.node_id != node_id or probe_materials.receipt != receipt:
                    probe_materials = None
            except Exception:
                probe_materials = None
        for assignment in expected.protocols:
            facts = sample.runtime.get("protocols", {})
            configured = facts.get(assignment.name) if isinstance(facts, dict) else None
            configuration_ok = isinstance(configured, dict) and configured.get("configured") is True
            configuration = self._result(
                "configuration", node_id,
                "ok" if configuration_ok else "error", started, "runtime_configuration",
                "" if configuration_ok else "configured inbound is not confirmed", checked_at,
            )
            connection = self._connection_result(
                definition, assignment, probe_materials, deep, probe_deadline, checked_at,
            )
            protocol_checks[assignment.name] = {"configuration": configuration, "connection": connection}
        return DiagnosticReport(management, runtime, users, subscription, protocol_checks)

    def _subscription_result(self, node_id: str, desired, receipt, checked_at: str) -> CheckResult:
        if receipt is None:
            return CheckResult("subscription", node_id, "unknown", checked_at, stage="receipt", reason="no committed apply receipt")
        bundle = self._profile_store.read(node_id, receipt_is_committed=self._receipt_committed)
        if bundle is None or bundle.receipt != receipt:
            return CheckResult("subscription", node_id, "error", checked_at, stage="profiles", reason="no confirmed profile bundle matches the applied receipt")
        expected = expected_profile_pairs(desired.users, desired.protocols)
        actual = {(item.user_uuid, item.protocol) for item in bundle.profiles}
        ok = actual == expected
        return CheckResult("subscription", node_id, "ok" if ok else "error", checked_at, stage="coverage", reason="" if ok else "confirmed profiles do not cover current users and protocols")

    def _connection_result(self, definition, assignment, materials: ProbeMaterials | None, deep: bool, deadline: float, checked_at: str) -> CheckResult:
        node_id, protocol = definition.id, assignment.name
        if protocol not in _SUPPORTED_PROBES:
            return CheckResult("connection", node_id, "not_applicable", checked_at, stage="capability", reason="no compatible native client is declared")
        if not deep:
            return CheckResult("connection", node_id, "unknown", checked_at, stage="depth", reason="deep protocol check was not requested")
        if materials is None:
            return CheckResult("connection", node_id, "unknown", checked_at, stage="probe_material", reason="current technical probe material is unavailable")
        material = next((item for item in materials.materials if item.protocol == protocol), None)
        if material is None:
            return CheckResult("connection", node_id, "unknown", checked_at, stage="probe_material", reason="current technical probe material is missing")
        endpoint = material.client_config
        expected_port = assignment.parameters.get("port")
        try:
            server = endpoint.get("server")
            bound_to_node = isinstance(server, str) and ipaddress.ip_address(server) == ipaddress.ip_address(definition.address)
        except (TypeError, ValueError):
            bound_to_node = False
        if not bound_to_node or type(expected_port) is not int or endpoint.get("server_port") != expected_port:
            return CheckResult("connection", node_id, "unknown", checked_at, stage="endpoint_binding", reason="client endpoint is not bound to the enrolled node")
        return self._probe_client.probe_client(material, node_id=node_id, deadline=deadline)

    def _receipt_committed(self, bundle) -> bool:
        operation = self._records.find_operation(bundle.receipt.operation_id)
        return bool(operation and operation.state == "succeeded" and operation.receipt == bundle.receipt)

    def _unknown_report(self, node_id: str, management: CheckResult) -> DiagnosticReport:
        unknown = lambda kind: CheckResult(kind, node_id, "unknown", management.checked_at, stage="management", reason="management response is unavailable")
        definition = self._records.find_definition(node_id)
        if definition is None:
            raise KeyError(f"unknown managed node {node_id}")
        desired = build_node_desired(definition, self._state_reader(), self._records)
        protocols = {
            assignment.name: {
                "configuration": unknown("configuration"),
                "connection": self._connection_result(definition, assignment, None, True, time.monotonic() + 1, management.checked_at or ""),
            }
            for assignment in desired.protocols
        }
        return DiagnosticReport(management, unknown("runtime"), unknown("users"), unknown("subscription"), protocols)

    @staticmethod
    def _result(kind: str, node_id: str, outcome: str, started: float, stage: str, reason: str, checked_at: str | None = None) -> CheckResult:
        return CheckResult(kind, node_id, outcome, checked_at or datetime.now(timezone.utc).isoformat(), max(0, int((time.monotonic() - started) * 1000)), stage, reason[:256])


def _safe_reason(error: Exception) -> str:
    return "management response could not be validated" if isinstance(error, ValueError) else type(error).__name__


__all__ = ["ManagedNodeCheckService"]
