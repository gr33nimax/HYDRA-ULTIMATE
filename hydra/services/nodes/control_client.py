"""Bounded HTTPS client for one node's mutually authenticated control API."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from hydra.contracts.node_export import NodeClientExport
from hydra.contracts.node_snapshot import NodeDesiredSnapshot
from hydra.contracts.node_traffic import NodeTrafficReport
from hydra.contracts.node_validation import MAX_NODE_BODY_BYTES


class NodeControlError(RuntimeError):
    """A control request failed or the peer was not the expected node."""


class NodeControlPort(Protocol):
    """Transport-neutral shape required by node orchestration services."""

    def health(self) -> dict: ...
    def diagnostics(self) -> dict: ...
    def apply(self, snapshot: NodeDesiredSnapshot) -> dict: ...
    def export(self) -> NodeClientExport: ...
    def traffic_report(self) -> NodeTrafficReport: ...
    def upgrade(self, *, branch: str, revision: str) -> dict: ...


@dataclass(frozen=True)
class NodeControlClient:
    host: str
    port: int
    node_id: str
    ca_file: Path
    certificate: Path
    private_key: Path
    timeout: float = 10.0
    server_fingerprint: str = ""

    def __post_init__(self) -> None:
        if self.server_fingerprint:
            normalized = self.server_fingerprint.replace(":", "")
            if len(normalized) != 64 or any(character not in "0123456789abcdefABCDEF" for character in normalized):
                raise ValueError("server_fingerprint must be a SHA-256 hexadecimal fingerprint")

    def _context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(self.ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.certificate), str(self.private_key))
        return context

    def _request(self, method: str, path: str, payload: object | None = None) -> dict:
        if (method, path) not in {
            ("GET", "/health"),
            ("GET", "/diagnostics"),
            ("GET", "/export"),
            ("GET", "/traffic"),
            ("POST", "/apply"),
            ("POST", "/upgrade"),
        }:
            raise ValueError("unsupported node control operation")
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_NODE_BODY_BYTES:
                raise NodeControlError("control request exceeds the supported size")
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection(
            self.host,
            self.port,
            context=self._context(),
            timeout=self.timeout,
        )
        try:
            connection.connect()
            if self.server_fingerprint:
                peer = connection.sock.getpeercert(binary_form=True) if connection.sock else None
                if not peer:
                    raise NodeControlError("node certificate is missing")
                actual = hashlib.sha256(peer).hexdigest()
                expected = self.server_fingerprint.replace(":", "").casefold()
                if not hmac.compare_digest(actual, expected):
                    raise NodeControlError("node certificate fingerprint does not match")
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(MAX_NODE_BODY_BYTES + 1)
            if len(data) > MAX_NODE_BODY_BYTES:
                raise NodeControlError("control response exceeds the supported size")
            try:
                result = json.loads(data)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise NodeControlError("node returned an invalid control response") from exc
            if not isinstance(result, dict):
                raise NodeControlError("node returned an invalid control response")
            if response.status < 200 or response.status >= 300:
                message = result.get("error")
                reason = result.get("reason")
                detail = str(message) if isinstance(message, str) else "node control request failed"
                if isinstance(reason, str) and reason.strip():
                    detail = f"{detail}: {reason.strip()[:512]}"
                raise NodeControlError(detail)
            peer_id = result.get("node_id")
            if peer_id is not None and peer_id != self.node_id:
                raise NodeControlError("control response node_id does not match the configured node")
            return result
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise NodeControlError(f"node control request failed ({exc.__class__.__name__})") from exc
        finally:
            connection.close()

    def health(self) -> dict:
        return self._request("GET", "/health")

    def diagnostics(self) -> dict:
        return self._request("GET", "/diagnostics")

    def apply(self, snapshot: NodeDesiredSnapshot) -> dict:
        snapshot.validate()
        if snapshot.node_id != self.node_id:
            raise NodeControlError("snapshot node_id does not match the configured node")
        return self._request("POST", "/apply", snapshot.to_document())

    def export(self) -> NodeClientExport:
        return NodeClientExport.from_document(self._request("GET", "/export"))

    def traffic_report(self) -> NodeTrafficReport:
        return NodeTrafficReport.from_document(self._request("GET", "/traffic"))

    def upgrade(self, *, branch: str, revision: str) -> dict:
        return self._request("POST", "/upgrade", {"branch": branch, "revision": revision})


__all__ = ["NodeControlClient", "NodeControlError", "NodeControlPort"]
