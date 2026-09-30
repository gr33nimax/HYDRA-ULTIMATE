"""Bounded mutually-authenticated HTTPS transport for the node agent."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol, cast

from hydra.contracts.node_export import NodeClientExport
from hydra.contracts.node_snapshot import NodeDesiredSnapshot
from hydra.contracts.node_traffic import NodeTrafficReport
from hydra.contracts.node_validation import (
    MAX_NODE_BODY_BYTES,
    NODE_CONTROL_PORT,
    NODE_CONTRACT_VERSION,
    checked_node_branch,
    checked_node_revision,
)
from hydra.core.node_identity import NodeIdentity
from hydra.utils.commands import redact_text

MAX_NODE_UPGRADE_BODY_BYTES = 1024


class NodeControlOperations(Protocol):
    node_id: str

    def current_generation(self) -> int: ...
    def apply(self, snapshot: NodeDesiredSnapshot) -> object: ...
    def export(self) -> NodeClientExport: ...
    def traffic_report(self) -> NodeTrafficReport: ...
    def diagnostics(self) -> dict[str, object]: ...
    def installed_revision(self) -> str: ...
    def schedule_upgrade(self, *, branch: str, revision: str) -> dict[str, object]: ...


def _allowed_base_ip(identity: NodeIdentity) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    identity.validate()
    return ipaddress.ip_address(identity.base_ip)


def _json_bytes(payload: object) -> bytes:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_NODE_BODY_BYTES:
        raise ValueError("control response exceeds the supported size")
    return body


def _server_context(identity: NodeIdentity) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(identity.certificate, identity.private_key)
    context.load_verify_locations(cafile=identity.base_ca)
    return context


class _NodeControlHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def _control_server(self) -> _NodeControlServer:
        return cast(_NodeControlServer, self.server)

    def _require_pinned_base(self) -> bool:
        identity = self._control_server.identity
        peer = self.connection.getpeercert(binary_form=True)
        actual = hashlib.sha256(peer or b"").hexdigest()
        if peer and hmac.compare_digest(actual, identity.base_fingerprint.casefold()):
            return True
        self._send(403, {"error": "base certificate fingerprint mismatch"})
        return False

    def log_message(self, format, *args):
        del format, args

    def _send(self, status: int, payload: object) -> None:
        try:
            body = _json_bytes(payload)
        except (TypeError, ValueError):
            status, body = 500, b'{"error":"invalid control response"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _read_json(self, *, max_bytes: int = MAX_NODE_BODY_BYTES) -> object:
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("transfer encoding is not supported")
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if size < 0 or size > max_bytes:
            raise OverflowError("request body exceeds the supported size")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("application/json is required")
        try:
            return json.loads(self.rfile.read(size))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("request body is not valid JSON") from exc

    def do_GET(self):
        if not self._require_pinned_base():
            return
        server = self._control_server
        identity, operations = server.identity, server.operations
        if self.path == "/health":
            try:
                revision = str(operations.installed_revision() or "")[:64]
            except Exception:
                revision = ""
            self._send(
                200,
                {
                    "ok": True,
                    "node_id": identity.node_id,
                    "generation": operations.current_generation(),
                    "contract_version": NODE_CONTRACT_VERSION,
                    "revision": revision,
                },
            )
            return
        if self.path == "/diagnostics":
            raw = operations.diagnostics()
            message = raw.get("last_error", "")
            safe_error = redact_text(str(message))[:2048] if message else ""
            self._send(
                200,
                {
                    "node_id": identity.node_id,
                    "generation": operations.current_generation(),
                    "last_error": safe_error,
                },
            )
            return
        if self.path == "/traffic":
            try:
                report = operations.traffic_report()
                report.validate()
                if report.node_id != identity.node_id or report.generation != operations.current_generation():
                    raise ValueError("traffic report is not current")
                self._send(200, report.to_document())
            except Exception:
                self._send(409, {"error": "traffic report is not current"})
            return
        if self.path == "/export":
            try:
                exported = operations.export()
                exported.validate()
                if exported.node_id != identity.node_id:
                    raise ValueError("export node_id mismatch")
                if exported.generation != operations.current_generation():
                    raise ValueError("export generation mismatch")
                self._send(200, exported.to_document())
            except Exception:
                self._send(409, {"error": "export is not current"})
            return
        self._send(404, {"error": "not found"})

    def _handle_upgrade(self) -> None:
        try:
            payload = self._read_json(max_bytes=MAX_NODE_UPGRADE_BODY_BYTES)
            if not isinstance(payload, dict) or set(payload) != {"branch", "revision"}:
                raise ValueError("invalid upgrade request shape")
            branch = checked_node_branch(payload["branch"], context="branch")
            revision = checked_node_revision(payload["revision"], context="revision")
        except OverflowError:
            self._send(413, {"error": "request body exceeds the supported size"})
            return
        except Exception:
            self._send(400, {"error": "invalid upgrade request"})
            return

        try:
            result = self._control_server.operations.schedule_upgrade(
                branch=branch,
                revision=revision,
            )
            if not isinstance(result, dict):
                raise TypeError("upgrade scheduler returned an invalid response")
        except Exception:
            self._send(500, {"error": "node upgrade could not be scheduled"})
            return
        self._send(202, result)

    def do_POST(self):
        if not self._require_pinned_base():
            return
        if self.path == "/upgrade":
            self._handle_upgrade()
            return
        if self.path != "/apply":
            self._send(404, {"error": "not found"})
            return
        try:
            snapshot = NodeDesiredSnapshot.from_document(self._read_json())
        except OverflowError:
            self._send(413, {"error": "request body exceeds the supported size"})
            return
        except Exception:
            self._send(400, {"error": "invalid snapshot"})
            return

        server = self._control_server
        identity, operations = server.identity, server.operations
        if snapshot.node_id != identity.node_id:
            self._send(409, {"error": "snapshot node_id does not match this node"})
            return
        current = operations.current_generation()
        if snapshot.generation < current:
            self._send(409, {"error": "stale generation"})
            return
        if snapshot.generation == current:
            self._send(
                200,
                {
                    "ok": True,
                    "node_id": identity.node_id,
                    "generation": current,
                    "already_applied": True,
                },
            )
            return
        try:
            result = operations.apply(snapshot)
            if (isinstance(result, bool) and not result) or operations.current_generation() != snapshot.generation:
                self._send(409, {"error": "snapshot was not committed"})
                return
        except Exception as exc:
            # The peer is the pinned base over mutual TLS, and the reason is what turns
            # "snapshot apply failed" into something an operator can act on. It is
            # bounded and redacted like every other diagnostic.
            reason = redact_text(str(exc))[:512] or exc.__class__.__name__
            self._send(500, {"error": "snapshot apply failed", "stage": "apply", "reason": reason})
            return
        self._send(
            200,
            {
                "ok": True,
                "node_id": identity.node_id,
                "generation": snapshot.generation,
                "already_applied": False,
            },
        )


class _NodeControlServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, identity: NodeIdentity, operations: NodeControlOperations):
        self.identity = identity
        self.operations = operations
        self.allowed_base_ip = _allowed_base_ip(identity)
        super().__init__(address, _NodeControlHandler)

    def verify_request(self, request, client_address):
        try:
            peer = ipaddress.ip_address(str(client_address[0]))
            if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
                peer = peer.ipv4_mapped
            return peer == self.allowed_base_ip
        except ValueError:
            return False


def create_control_server(
    identity: NodeIdentity,
    operations: NodeControlOperations,
    *,
    host: str = "0.0.0.0",
    port: int = NODE_CONTROL_PORT,
) -> ThreadingHTTPServer:
    """Build an mTLS server; it refuses to bind without a complete identity."""
    if operations.node_id != identity.node_id:
        raise ValueError("control operations do not match node identity")
    server = _NodeControlServer((host, port), identity, operations)
    try:
        server.socket = _server_context(identity).wrap_socket(server.socket, server_side=True)
    except Exception:
        server.server_close()
        raise
    return server


__all__ = ["NodeControlOperations", "create_control_server"]
