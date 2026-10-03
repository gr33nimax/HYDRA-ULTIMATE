"""Deadline-aware client for the pinned managed-node HTTPS v1 contract."""

from __future__ import annotations

import ipaddress
import json
import math
import socket
import ssl
import time
from pathlib import Path
from typing import Any, Callable, TypeVar

from hydra.contracts.managed_node_cascade import (
    CascadeParticipantReceipt,
    CascadeParticipantRequest,
    CascadeParticipantStatus,
    CascadeTechnicalMaterial,
)
from hydra.contracts.managed_node_models import NodeDefinition, NodeDesired, Operation
from hydra.contracts.managed_node_observations import ConfirmedProfiles, NodeSample
from hydra.contracts.managed_node_probe import ProbeMaterials
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialTransfer
from hydra.services.managed_nodes.identity import (
    CertificateIdentityError,
    certificate_fingerprint,
    validate_certificate_identity,
)
from hydra.utils.commands import redact_text

T = TypeVar("T")
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024


class ManagedNodeError(RuntimeError):
    """A management request failed in a public, stage-aware phase."""

    def __init__(self, kind: str, stage: str, reason: str) -> None:
        self.kind = kind
        self.stage = stage
        self.reason = _reason(reason)
        super().__init__(f"{kind} during {stage}: {self.reason}")


class ManagedNodeClient:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        node_id: str,
        certificate: Path,
        private_key: Path,
        pinned_server_certificate: bytes,
    ) -> None:
        try:
            self.host = str(ipaddress.ip_address(host))
        except (TypeError, ValueError) as exc:
            raise ValueError("managed-node management host must be an IP address") from exc
        if type(port) is not int or not 1 <= port <= 65535 or port == 22:
            raise ValueError("managed-node management port is invalid")
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("managed-node id is required")
        if not pinned_server_certificate:
            raise ValueError("pinned management server certificate is required")
        self.port = port
        self.node_id = node_id
        self.certificate = Path(certificate)
        self.private_key = Path(private_key)
        self._pin = certificate_fingerprint(pinned_server_certificate)
        try:
            ca_data = pinned_server_certificate.decode("ascii")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cadata=ca_data)
            context.load_cert_chain(str(self.certificate), str(self.private_key))
        except (UnicodeDecodeError, OSError, ssl.SSLError, ValueError) as exc:
            raise ValueError("management TLS credentials are invalid") from exc
        self._tls = context

    def state(self, deadline: float) -> NodeSample:
        return self._request("GET", "/v1/state", None, deadline, NodeSample.from_document)

    def sync_sample(self, deadline: float) -> NodeSample:
        return self._request("POST", "/v1/sync/sample", {}, deadline, NodeSample.from_document)

    def submit(self, operation_id: str, desired: NodeDesired, deadline: float) -> Operation:
        desired.validate()
        if desired.node_id != self.node_id:
            raise ValueError("desired node identity does not match this client")
        if not isinstance(operation_id, str) or not operation_id or len(operation_id) > 64:
            raise ValueError("operation id is invalid")
        return self._request(
            "POST",
            "/v1/apply",
            {"operation_id": operation_id, "desired": desired.to_document()},
            deadline,
            Operation.from_document,
        )

    def operation(self, operation_id: str, deadline: float) -> Operation:
        if (
            not isinstance(operation_id, str)
            or not operation_id
            or len(operation_id) > 64
            or any(
                char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in operation_id
            )
        ):
            raise ValueError("operation id is invalid")
        return self._request("GET", f"/v1/operations/{operation_id}", None, deadline, Operation.from_document)

    def profiles(self, deadline: float) -> ConfirmedProfiles:
        return self._request("GET", "/v1/profiles", None, deadline, ConfirmedProfiles.from_document)

    def probe_materials(self, deadline: float) -> ProbeMaterials:
        return self._request("GET", "/v1/probe-material", None, deadline, ProbeMaterials.from_document)

    def cascade_snapshot(self, request: CascadeParticipantRequest, deadline: float) -> CascadeParticipantReceipt:
        return self._cascade_receipt("snapshot", request, deadline)

    def cascade_prepare(
        self,
        request: CascadeParticipantRequest,
        transfer: CascadeCredentialTransfer,
        material: CascadeTechnicalMaterial | None,
        deadline: float,
    ) -> CascadeParticipantReceipt:
        request.validate()
        transfer.validate()
        if transfer.cascade_id != request.target_id:
            raise ValueError("cascade credential transfer does not match the request route")
        if request.kind != "cascade_save":
            raise ValueError("cascade technical preparation requires a save operation")
        if request.role == "entry":
            if material is None:
                raise ValueError("entry participant requires authenticated transit material")
            transit_request = CascadeParticipantRequest(
                request.operation_id,
                request.kind,
                request.target_id,
                request.plan_digest,
                request.plan,
                request.route.exit_id,
                "transit",
                request.route,
                request.protocol,
            )
            material.validate_for(transit_request)
        elif material is not None:
            raise ValueError("transit preparation must not contain peer material")
        payload = {
            "request": request.to_document(),
            "credential_transfer": transfer.to_document(),
            "material": material.to_document() if material is not None else None,
        }
        return self._request(
            "POST",
            "/v1/cascades/prepare",
            payload,
            deadline,
            lambda raw: _cascade_receipt(raw, request),
        )

    def cascade_material(self, request: CascadeParticipantRequest, deadline: float) -> CascadeTechnicalMaterial:
        request.validate()
        material = self._request(
            "POST",
            "/v1/cascades/material",
            {"request": request.to_document()},
            deadline,
            CascadeTechnicalMaterial.from_document,
        )
        material.validate_for(request)
        return material

    def cascade_status(self, request: CascadeParticipantRequest, deadline: float) -> CascadeParticipantStatus:
        request.validate()
        status = self._request(
            "POST",
            "/v1/cascades/status",
            {"request": request.to_document()},
            deadline,
            CascadeParticipantStatus.from_document,
        )
        status.validate_for(request)
        return status

    def cascade_apply(self, request: CascadeParticipantRequest, deadline: float) -> CascadeParticipantReceipt:
        return self._cascade_receipt("apply", request, deadline)

    def cascade_rollback(self, request: CascadeParticipantRequest, deadline: float) -> CascadeParticipantReceipt:
        return self._cascade_receipt("rollback", request, deadline)

    def cascade_finalize(
        self,
        request: CascadeParticipantRequest,
        commit_digest: str,
        deadline: float,
    ) -> CascadeParticipantReceipt:
        if (
            not isinstance(commit_digest, str)
            or len(commit_digest) != 64
            or any(char not in "0123456789abcdef" for char in commit_digest)
        ):
            raise ValueError("cascade coordinator commit digest is invalid")
        return self._request(
            "POST",
            "/v1/cascades/finalize",
            {"request": request.to_document(), "commit_digest": commit_digest},
            deadline,
            lambda raw: _cascade_receipt(raw, request),
        )

    def _cascade_receipt(
        self, action: str, request: CascadeParticipantRequest, deadline: float
    ) -> CascadeParticipantReceipt:
        request.validate()
        result = self._request(
            "POST",
            f"/v1/cascades/{action}",
            {"request": request.to_document()},
            deadline,
            lambda raw: _cascade_receipt(raw, request),
        )
        return result

    def _request(
        self,
        method: str,
        path: str,
        payload: object,
        deadline: float,
        decode: Callable[[object], T],
    ) -> T:
        body = b"" if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise ManagedNodeError("request_too_large", "validation", "request exceeds the size limit")
        raw = self._connect(deadline)
        secure: ssl.SSLSocket | None = None
        try:
            secure = self._tls.wrap_socket(raw, server_hostname=None, do_handshake_on_connect=False)
            secure.settimeout(_remaining(deadline, "tls"))
            try:
                secure.do_handshake()
            except (OSError, ssl.SSLError, TimeoutError) as exc:
                raise ManagedNodeError("tls_failed", "tls", str(exc)) from exc
            peer = secure.getpeercert(binary_form=True)
            if peer is None:
                raise ManagedNodeError("identity_missing", "tls", "server certificate was not presented")
            try:
                validate_certificate_identity(
                    peer,
                    node_id=self.node_id,
                    role="server",
                    address=self.host,
                    expected_fingerprint=self._pin,
                )
            except CertificateIdentityError as exc:
                raise ManagedNodeError("identity_mismatch", "tls", str(exc)) from exc
            request = (
                f"{method} {path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
                f"Connection: close\r\nAccept: application/json\r\n"
            )
            if payload is not None:
                request += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            secure.sendall(request.encode("ascii") + b"\r\n" + body)
            status, response = _read_response(secure, deadline)
            if status != 200:
                error = response.get("error", {}) if isinstance(response, dict) else {}
                kind = error.get("kind", "http_error") if isinstance(error, dict) else "http_error"
                stage = error.get("stage", "http") if isinstance(error, dict) else "http"
                reason = (
                    error.get("reason", f"HTTP status {status}") if isinstance(error, dict) else f"HTTP status {status}"
                )
                raise ManagedNodeError(str(kind), str(stage), str(reason))
            try:
                return decode(response)
            except (TypeError, ValueError, KeyError) as exc:
                raise ManagedNodeError("invalid_response", "validation", str(exc)) from exc
        except ManagedNodeError:
            raise
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            raise ManagedNodeError("http_failed", "http", str(exc)) from exc
        finally:
            try:
                if secure is not None:
                    secure.close()
                else:
                    raw.close()
            except OSError:
                pass

    def _connect(self, deadline: float) -> socket.socket:
        timeout = _remaining(deadline, "tcp")
        try:
            return socket.create_connection((self.host, self.port), timeout=timeout)
        except (OSError, TimeoutError) as exc:
            raise ManagedNodeError("tcp_failed", "tcp", str(exc)) from exc


def client_from_credentials(
    credentials,
    definition: NodeDefinition,
    files=None,
    server_certificate: bytes | None = None,
) -> ManagedNodeClient:
    files = files or credentials.client_files(definition.identity_ref)
    certificate = server_certificate or credentials.read_server_certificate(definition.identity_ref)
    if certificate is None:
        raise RuntimeError("pinned managed-node certificate is unavailable")
    return ManagedNodeClient(
        host=definition.address,
        port=definition.control_port,
        node_id=definition.id,
        certificate=files.certificate,
        private_key=files.private_key,
        pinned_server_certificate=certificate,
    )


def _remaining(deadline: float, stage: str) -> float:
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
        raise ManagedNodeError("invalid_deadline", stage, "absolute monotonic deadline is invalid")
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        raise ManagedNodeError("timeout", stage, "request deadline expired")
    return remaining


def _read_response(connection: ssl.SSLSocket, deadline: float) -> tuple[int, object]:
    data = bytearray()
    marker = b"\r\n\r\n"
    while marker not in data:
        connection.settimeout(_remaining(deadline, "http"))
        chunk = connection.recv(4096)
        if not chunk:
            raise ManagedNodeError("invalid_http", "http", "response ended before headers")
        data.extend(chunk)
        if len(data) > MAX_HEADER_BYTES:
            raise ManagedNodeError("invalid_http", "http", "response headers exceed the size limit")
    boundary = data.index(marker) + len(marker)
    header_bytes, buffered = bytes(data[:boundary]), bytearray(data[boundary:])
    try:
        lines = header_bytes[:-4].decode("ascii").split("\r\n")
        parts = lines[0].split(" ", 2)
        if len(parts) != 3 or not parts[0].startswith("HTTP/1."):
            raise ValueError
        status = int(parts[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            lowered = name.casefold().strip()
            if not separator or not lowered or lowered in headers:
                raise ValueError
            headers[lowered] = value.strip()
        if "transfer-encoding" in headers or "content-length" not in headers:
            raise ValueError
        length = int(headers["content-length"])
        if length < 0 or length > MAX_RESPONSE_BYTES:
            raise ValueError
    except (UnicodeDecodeError, ValueError) as exc:
        raise ManagedNodeError("invalid_http", "http", "response headers are invalid") from exc
    if len(buffered) > length:
        raise ManagedNodeError("invalid_http", "http", "response has trailing bytes")
    while len(buffered) < length:
        connection.settimeout(_remaining(deadline, "http"))
        chunk = connection.recv(min(65536, length - len(buffered)))
        if not chunk:
            raise ManagedNodeError("invalid_http", "http", "response body is incomplete")
        buffered.extend(chunk)
    try:
        response = json.loads(bytes(buffered).decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ManagedNodeError("invalid_http", "http", "response is not valid JSON") from exc
    return status, response


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _cascade_receipt(raw: object, request: CascadeParticipantRequest) -> CascadeParticipantReceipt:
    receipt = CascadeParticipantReceipt.from_document(raw)
    receipt.validate_for(request)
    return receipt


def _reason(value: str) -> str:
    printable = "".join(char for char in redact_text(value) if char.isprintable())
    return printable[:160] or "management request failed"


__all__ = ["ManagedNodeClient", "ManagedNodeError"]
