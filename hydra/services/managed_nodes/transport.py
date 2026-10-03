"""Bounded concurrent TLS/HTTP transport for the managed-node v1 agent."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from hydra.contracts.managed_node_models import MANAGED_NODE_API_VERSION
from hydra.services.managed_nodes.agent import ManagedNodeAgent
from hydra.services.managed_nodes.identity import (
    CertificateIdentityError,
    ManagementIdentity,
    certificate_fingerprint,
    validate_certificate_identity,
)

MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_REQUEST_LINE_BYTES = 4096
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


@dataclass(frozen=True)
class HttpRequest:
    method: str
    path: str
    payload: object = None


class _HttpFailure(ValueError):
    def __init__(self, status: int, reason: str) -> None:
        self.status = status
        super().__init__(reason)


def _server_context(identity: ManagementIdentity) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(identity.certificate_path), str(identity.private_key_path))
    context.load_verify_locations(cafile=str(identity.trusted_client_certificate_path))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class ManagedNodeServer:
    """Accept source-pinned mTLS requests on a bounded fixed worker pool."""

    def __init__(
        self,
        identity: ManagementIdentity,
        agent: ManagedNodeAgent,
        *,
        bind_host: str = "0.0.0.0",
        max_workers: int = 8,
        request_timeout: float = 5.0,
    ) -> None:
        if type(max_workers) is not int or not 2 <= max_workers <= 64:
            raise ValueError("management worker limit must be 2..64")
        if isinstance(request_timeout, bool) or not isinstance(request_timeout, (int, float)) or not 0.1 <= request_timeout <= 30:
            raise ValueError("management request timeout must be 0.1..30 seconds")
        self.identity = identity
        self.agent = agent
        self.bind_host = bind_host
        self.max_workers = max_workers
        self.request_timeout = float(request_timeout)
        self._allowed_sources = {ipaddress.ip_address(item) for item in identity.allowed_source_ips}
        self._tls = _server_context(identity)
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._workers = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="managed-node-http")
        self._slots = threading.BoundedSemaphore(max_workers)
        self._stopping = threading.Event()
        self._active_lock = threading.Lock()
        self._active_workers = 0

    @property
    def port(self) -> int:
        if self._listener is None:
            raise RuntimeError("managed-node server has not been started")
        return int(self._listener.getsockname()[1])

    @property
    def certificate_bytes(self) -> bytes:
        return self.identity.certificate_path.read_bytes()

    @property
    def active_workers(self) -> int:
        with self._active_lock:
            return self._active_workers

    def start(self) -> "ManagedNodeServer":
        if self._listener is not None:
            raise RuntimeError("managed-node server is already running")
        listener = socket.socket(socket.AF_INET6 if ":" in self.bind_host else socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind_host, self.identity.control_port))
        listener.listen(self.max_workers)
        listener.settimeout(0.2)
        self._listener = listener
        self._accept_thread = threading.Thread(target=self._accept, name="managed-node-accept", daemon=True)
        self._accept_thread.start()
        return self

    def _accept(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stopping.is_set():
            try:
                connection, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._source_allowed(address[0]) or not self._slots.acquire(blocking=False):
                connection.close()
                continue
            with self._active_lock:
                self._active_workers += 1
            try:
                future = self._workers.submit(self._serve, connection)
                future.add_done_callback(lambda _completed: self._worker_done())
            except RuntimeError:
                connection.close()

    def _source_allowed(self, address: str) -> bool:
        try:
            peer = ipaddress.ip_address(address)
        except ValueError:
            return False
        return peer in self._allowed_sources

    def _serve(self, connection: socket.socket) -> None:
        secure: ssl.SSLSocket | None = None
        try:
            connection.settimeout(self.request_timeout)
            secure = self._tls.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
            secure.settimeout(self.request_timeout)
            secure.do_handshake()
            peer = secure.getpeercert(binary_form=True)
            if peer is None:
                return
            try:
                validate_certificate_identity(
                    peer,
                    node_id="base",
                    role="client",
                    expected_fingerprint=self.identity.trusted_client_fingerprint,
                )
            except CertificateIdentityError:
                return
            try:
                request = _read_request(secure)
                result = self.agent.dispatch(request.method, request.path, request.payload)
                _send_response(secure, result.status, result.document)
            except _HttpFailure as exc:
                _send_response(secure, exc.status, {"error": {"kind": "invalid_http", "stage": "http", "reason": str(exc)[:160]}})
            except (OSError, ssl.SSLError, TimeoutError):
                return
        except (OSError, ssl.SSLError, TimeoutError):
            return
        finally:
            try:
                if secure is not None:
                    secure.close()
                else:
                    connection.close()
            except OSError:
                pass

    def _worker_done(self) -> None:
        with self._active_lock:
            self._active_workers -= 1
        self._slots.release()

    def close(self) -> None:
        self._stopping.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        thread, self._accept_thread = self._accept_thread, None
        if thread is not None:
            thread.join(timeout=1.0)
        self._workers.shutdown(wait=True, cancel_futures=True)

    def __enter__(self) -> "ManagedNodeServer":
        return self.start()

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


def _read_request(connection: ssl.SSLSocket) -> HttpRequest:
    header_bytes, buffered_body = _read_until(connection, b"\r\n\r\n", MAX_HEADER_BYTES)
    lines = header_bytes[:-4].split(b"\r\n")
    if not lines or len(lines[0]) > MAX_REQUEST_LINE_BYTES:
        raise _HttpFailure(400, "request line is invalid")
    try:
        request_line = lines[0].decode("ascii")
        method, path, version = request_line.split(" ")
        if version != "HTTP/1.1" or method not in {"GET", "POST"}:
            raise ValueError
        if not path.startswith("/") or any(ord(char) < 33 or ord(char) > 126 for char in path):
            raise ValueError
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            decoded_name = name.decode("ascii").strip()
            decoded_value = value.decode("ascii").strip()
            if not separator or not _HEADER_NAME.fullmatch(decoded_name) or decoded_name.casefold() in headers:
                raise ValueError
            headers[decoded_name.casefold()] = decoded_value
    except (UnicodeDecodeError, ValueError) as exc:
        raise _HttpFailure(400, "request headers are invalid") from exc
    if "host" not in headers or "transfer-encoding" in headers:
        raise _HttpFailure(400, "request framing is invalid")
    raw_length = headers.get("content-length", "0")
    if not raw_length.isascii() or not raw_length.isdigit():
        raise _HttpFailure(400, "request content length is invalid")
    length = int(raw_length)
    if length > MAX_REQUEST_BYTES:
        raise _HttpFailure(413, "request body exceeds the size limit")
    if method == "GET" and length != 0:
        raise _HttpFailure(400, "GET request must not contain a body")
    if method == "POST" and headers.get("content-type", "").split(";", 1)[0].strip().casefold() != "application/json":
        raise _HttpFailure(415, "request content type must be application/json")
    body = _read_exact(connection, length, buffered_body)
    if not body:
        payload = None
    else:
        try:
            payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise _HttpFailure(400, "request body is not valid JSON") from exc
    return HttpRequest(method, path, payload)


def _read_until(connection: socket.socket, marker: bytes, limit: int) -> tuple[bytes, bytes]:
    data = bytearray()
    while marker not in data:
        chunk = connection.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            raise _HttpFailure(400, "request ended before complete headers")
        data.extend(chunk)
        if len(data) > limit:
            raise _HttpFailure(431, "request headers exceed the size limit")
    end = data.index(marker) + len(marker)
    return bytes(data[:end]), bytes(data[end:])


def _read_exact(connection: socket.socket, size: int, initial: bytes = b"") -> bytes:
    if len(initial) > size:
        raise _HttpFailure(400, "request has trailing bytes")
    chunks = bytearray(initial)
    while len(chunks) < size:
        chunk = connection.recv(min(65536, size - len(chunks)))
        if not chunk:
            raise _HttpFailure(400, "request body is incomplete")
        chunks.extend(chunk)
    return bytes(chunks)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _send_response(connection: ssl.SSLSocket, status: int, document: object) -> None:
    try:
        body = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError):
        status, body = 500, b'{"error":{"kind":"serialization","stage":"http","reason":"response serialization failed"}}'
    if len(body) > MAX_RESPONSE_BYTES:
        status, body = 413, b'{"error":{"kind":"response_too_large","stage":"http","reason":"response exceeds the size limit"}}'
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 413: "Payload Too Large", 415: "Unsupported Media Type", 431: "Request Header Fields Too Large", 500: "Internal Server Error"}.get(status, "Error")
    header = f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\nX-Hydra-API-Version: {MANAGED_NODE_API_VERSION}\r\n\r\n".encode("ascii")
    connection.sendall(header + body)


__all__ = ["HttpRequest", "ManagedNodeServer"]
