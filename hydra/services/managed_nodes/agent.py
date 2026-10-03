"""Bounded v1 management API dispatch over injected local operation providers."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from hydra.contracts.managed_node_cascade import (
    CascadeParticipantReceipt,
    CascadeParticipantRequest,
    CascadeParticipantStatus,
    CascadeTechnicalMaterial,
)
from hydra.contracts.managed_node_models import NodeDesired, Operation
from hydra.contracts.managed_node_observations import ConfirmedProfiles, NodeSample
from hydra.contracts.managed_node_probe import ProbeMaterials
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialTransfer
from hydra.services.managed_nodes.cascade_participant import ManagedNodeCascadeParticipant
from hydra.utils.commands import redact_text

_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SECRET = re.compile(r"(?i)(password|token|secret|private[_-]?key|authorization|askpass|cookie)")


class ManagedNodeProviders(Protocol):
    def state(self) -> NodeSample: ...
    def sync_sample(self) -> NodeSample: ...
    def submit(self, operation_id: str, desired: NodeDesired) -> Operation: ...
    def operation(self, operation_id: str) -> Operation | None: ...
    def profiles(self) -> ConfirmedProfiles: ...


@dataclass(frozen=True)
class DispatchResult:
    status: int
    document: dict[str, Any]


class ManagedNodeAgent:
    """Serve only bounded state/apply/result/profile operations, never shell or files."""

    def __init__(
        self,
        *,
        node_id: str,
        state_provider: Callable[[], NodeSample],
        submit_provider: Callable[[str, NodeDesired], Operation] | None,
        sync_sample_provider: Callable[[], NodeSample] | None = None,
        operation_provider: Callable[[str], Operation | None],
        profiles_provider: Callable[[], ConfirmedProfiles | None] | None,
        probe_materials_provider: Callable[[], ProbeMaterials] | None = None,
        cascade_participant: ManagedNodeCascadeParticipant | None = None,
    ) -> None:
        if not _OPERATION_ID.fullmatch(node_id):
            raise ValueError("managed-node agent id is invalid")
        self.node_id = node_id
        self._state = state_provider
        self._sync_sample = sync_sample_provider
        self._submit = submit_provider
        self._operation = operation_provider
        self._profiles = profiles_provider
        self._probe_materials = probe_materials_provider
        self._cascade_participant = cascade_participant

    def dispatch(self, method: str, path: str, payload: object = None) -> DispatchResult:
        try:
            if method == "GET" and path == "/v1/state":
                sample = self._state()
                if not isinstance(sample, NodeSample) or sample.node_id != self.node_id:
                    raise ValueError("state provider returned a different node identity")
                document = sample.to_document()
                _reject_private_fields(document)
                return DispatchResult(200, document)
            if method == "POST" and path == "/v1/sync/sample":
                if payload != {}:
                    return self._error(400, "invalid_request", "http", "sync sample request has an invalid shape")
                if self._sync_sample is None:
                    return self._error(503, "unsupported", "application", "sync accounting is not wired")
                sample = self._sync_sample()
                if not isinstance(sample, NodeSample) or sample.node_id != self.node_id:
                    raise ValueError("sync sample provider returned a different node identity")
                document = sample.to_document()
                _reject_private_fields(document)
                return DispatchResult(200, document)
            if method == "POST" and path == "/v1/apply":
                if self._submit is None:
                    return self._error(503, "unsupported", "application", "node apply owner is not wired")
                return self._apply(payload)
            operation_match = re.fullmatch(r"/v1/operations/([A-Za-z0-9][A-Za-z0-9._-]{0,63})", path)
            if method == "GET" and operation_match:
                operation = self._operation(operation_match.group(1))
                if operation is None:
                    return self._error(404, "not_found", "http", "operation was not found")
                if operation.id != operation_match.group(1) or operation.target_id != self.node_id:
                    raise ValueError("operation provider returned a different identity")
                document = operation.to_document()
                _reject_private_fields(document)
                return DispatchResult(200, document)
            if method == "GET" and path == "/v1/profiles":
                if self._profiles is None:
                    return self._error(503, "unsupported", "application", "confirmed profiles are not available")
                profiles = self._profiles()
                if profiles is None:
                    return self._error(
                        503, "profiles_unavailable", "application", "confirmed profiles are not available"
                    )
                if not isinstance(profiles, ConfirmedProfiles) or profiles.node_id != self.node_id:
                    raise ValueError("profiles provider returned a different node identity")
                # Personal client material is intentionally available only on this mTLS path.
                return DispatchResult(200, profiles.to_document())
            if method == "GET" and path == "/v1/probe-material":
                if self._probe_materials is None:
                    return self._error(
                        503, "probe_unavailable", "application", "technical probe material is unavailable"
                    )
                materials = self._probe_materials()
                if not isinstance(materials, ProbeMaterials) or materials.node_id != self.node_id:
                    raise ValueError("probe material provider returned a different node identity")
                return DispatchResult(200, materials.to_document())
            if method == "POST" and path.startswith("/v1/cascades/"):
                return self._cascade(path, payload)
            return self._error(404, "not_found", "http", "management endpoint was not found")
        except (TypeError, ValueError, KeyError) as exc:
            return self._error(400, "invalid_request", "http", _safe_reason(exc))
        except Exception as exc:
            return self._error(500, "operation_failed", "application", _safe_reason(exc))

    def _cascade(self, path: str, payload: object) -> DispatchResult:
        owner = self._cascade_participant
        if owner is None:
            return self._error(503, "cascade_unavailable", "application", "cascade participant owner is unavailable")
        try:
            if path == "/v1/cascades/snapshot":
                request = _cascade_request(payload, {"request"})
                receipt = owner.ensure_snapshot(request)
                return DispatchResult(200, receipt.to_document())
            if path == "/v1/cascades/prepare":
                if not isinstance(payload, dict) or set(payload) != {"request", "credential_transfer", "material"}:
                    return self._error(
                        400, "invalid_request", "http", "cascade preparation request has an invalid shape"
                    )
                request = CascadeParticipantRequest.from_document(payload["request"])
                transfer = CascadeCredentialTransfer.from_document(payload["credential_transfer"])
                material = (
                    CascadeTechnicalMaterial.from_document(payload["material"])
                    if payload["material"] is not None
                    else None
                )
                receipt = owner.prepare(request, transfer, material)
                return DispatchResult(200, receipt.to_document())
            if path == "/v1/cascades/material":
                request = _cascade_request(payload, {"request"})
                material = owner.technical_material(request)
                return DispatchResult(200, material.to_document())
            if path == "/v1/cascades/status":
                request = _cascade_request(payload, {"request"})
                status, receipt = owner.query(request)
                result = CascadeParticipantStatus(status, receipt)
                result.validate_for(request)
                return DispatchResult(200, result.to_document())
            if path == "/v1/cascades/apply":
                request = _cascade_request(payload, {"request"})
                receipt = owner.apply(request)
                return DispatchResult(200, receipt.to_document())
            if path == "/v1/cascades/rollback":
                request = _cascade_request(payload, {"request"})
                receipt = owner.rollback(request)
                return DispatchResult(200, receipt.to_document())
            if path == "/v1/cascades/finalize":
                if not isinstance(payload, dict) or set(payload) != {"request", "commit_digest"}:
                    return self._error(400, "invalid_request", "http", "cascade finalize request has an invalid shape")
                request = CascadeParticipantRequest.from_document(payload["request"])
                receipt = owner.finalize(request, payload["commit_digest"])
                return DispatchResult(200, receipt.to_document())
        except (TypeError, ValueError, KeyError) as exc:
            return self._error(400, "invalid_request", "cascade", _safe_reason(exc))
        except Exception as exc:
            return self._error(500, "operation_failed", "cascade", _safe_reason(exc))
        return self._error(404, "not_found", "http", "cascade management endpoint was not found")

    def _apply(self, payload: object) -> DispatchResult:
        submit = self._submit
        if submit is None:
            return self._error(503, "unsupported", "application", "node apply owner is not wired")
        if not isinstance(payload, dict) or set(payload) != {"operation_id", "desired"}:
            return self._error(400, "invalid_request", "http", "apply request has an invalid shape")
        operation_id = payload["operation_id"]
        if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
            return self._error(400, "invalid_request", "http", "operation id is invalid")
        desired = NodeDesired.from_document(payload["desired"])
        if desired.node_id != self.node_id:
            return self._error(400, "invalid_request", "validation", "desired node identity does not match")
        operation = submit(operation_id, desired)
        if not isinstance(operation, Operation):
            raise TypeError("apply provider returned an invalid operation")
        if (
            operation.id != operation_id
            or operation.target_id != self.node_id
            or operation.desired_digest != desired.digest
            or operation.kind != "apply"
        ):
            raise ValueError("apply provider returned a mismatched operation receipt")
        document = operation.to_document()
        _reject_private_fields(document)
        return DispatchResult(200, document)

    @staticmethod
    def _error(status: int, kind: str, stage: str, reason: str) -> DispatchResult:
        return DispatchResult(
            status,
            {"error": {"kind": kind, "stage": stage, "reason": _safe_reason(reason)}},
        )


def _cascade_request(payload: object, keys: set[str]) -> CascadeParticipantRequest:
    if not isinstance(payload, dict) or set(payload) != keys:
        raise ValueError("cascade participant request has an invalid shape")
    return CascadeParticipantRequest.from_document(payload["request"])


def _reject_private_fields(document: object) -> None:
    if isinstance(document, dict):
        for key, value in document.items():
            if _SECRET.search(key):
                raise ValueError("management status contains a forbidden secret field")
            _reject_private_fields(value)
    elif isinstance(document, list):
        for value in document:
            _reject_private_fields(value)


def _safe_reason(value: object) -> str:
    text = redact_text(str(value))
    printable = "".join(character for character in text if character.isprintable())
    return printable[:160] or "management operation failed"


__all__ = ["DispatchResult", "ManagedNodeAgent", "ManagedNodeProviders"]
