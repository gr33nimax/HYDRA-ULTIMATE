"""Authenticated readiness probe for the mtproto.zig WEB bridge.

A plain HTTPS fetch only shows that *something* answers on port 443. The relay's
real readiness signal is the one upstream itself checks: fetch the bridge page
with a capability derived from a real user secret, read the short-lived bridge
token out of the page metadata, perform the authenticated same-origin WebSocket
upgrade, send the mandatory protocol HELLO and require the relay's WELCOME.

Wire format (upstream ``src/web/frame.zig`` and ``src/web/relay.zig``):

* every bridge frame is ``kind | stream(3) | length(4) | payload``;
* ``hello = 0x10`` is client→relay with payload ``01`` and **must be the first
  frame the client sends** — the relay answers anything else with a protocol
  error and never welcoms the session;
* ``welcome = 0x11`` is relay→client, empty, and must be the first frame sent.

Everything here is read-only and bounded: one absolute deadline covers the whole
probe and every response has a hard size limit.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import socket
import ssl
import struct
import time
from html.parser import HTMLParser
from typing import Any

from .constants import WEB_WS_PATH

PROBE_TIMEOUT_SECONDS = 8.0
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_FRAME_BYTES = 1024 * 1024 + 8
MAX_FRAMES = 16
READ_CHUNK_BYTES = 4096
BRIDGE_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Bridge frame kinds and WebSocket opcodes used by the upgrade handshake.
FRAME_HELLO = 0x10
FRAME_WELCOME = 0x11
HELLO_PROTOCOL_VERSION = b"\x01"
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

DEADLINE_REASON = "проверка WEB-моста превысила отведённое время"


class ProbeError(Exception):
    """One bounded readiness-probe failure with an operator-readable reason."""


def probe_bridge(
    domain: str,
    *,
    capability: str,
    address: str = "127.0.0.1",
    port: int = 443,
    ws_path: str = WEB_WS_PATH,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> tuple[bool, str]:
    """Prove the whole WEB path: certificate, route, bridge page and upgrade.

    The probe speaks to the local frontend with the public hostname, so the
    certificate chain and the hostname are verified against the real CA. One
    absolute deadline covers the page fetch and the WebSocket handshake.
    """
    normalized = str(domain or "").strip().lower().rstrip(".")
    if not normalized:
        return False, "домен WEB-релея не задан"
    if not BRIDGE_TOKEN.fullmatch(str(capability or "")):
        return False, "capability WEB-моста не построен"
    deadline = _now() + timeout
    try:
        token = _page_token(normalized, capability, address, port, ws_path, deadline)
        _upgrade_websocket(normalized, token, address, port, ws_path, deadline)
    except ProbeError as exc:
        return False, str(exc)
    except (OSError, ValueError) as exc:
        # ssl.SSLError is an OSError subclass, so one branch keeps the reason clear.
        return False, f"{exc.__class__.__name__}: {exc}" if str(exc) else exc.__class__.__name__
    return True, ""


def hello_frame() -> bytes:
    """The client's first bridge frame: HELLO on stream 0 declaring protocol v1."""
    return _bridge_frame(FRAME_HELLO, HELLO_PROTOCOL_VERSION)


def welcome_frame() -> bytes:
    """The relay's first bridge frame: WELCOME on stream 0 with an empty payload."""
    return _bridge_frame(FRAME_WELCOME)


def _bridge_frame(kind: int, payload: bytes = b"", stream: int = 0) -> bytes:
    """Serialize one bridge frame exactly as upstream does."""
    return bytes([kind]) + stream.to_bytes(3, "big") + struct.pack(">I", len(payload)) + payload


def _page_token(
    domain: str,
    capability: str,
    address: str,
    port: int,
    ws_path: str,
    deadline: float,
) -> str:
    """Fetch the bridge page and read its authenticated bridge token."""
    request = f"GET /?bridge={capability} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
    with _tls_connection(domain, address, port, deadline) as tls:
        tls.sendall(request)
        status, _headers, body = _read_http_response(_Reader(tls, deadline))
    if status != 200:
        raise ProbeError(f"страница WEB-моста вернула HTTP {status}")
    return _BridgeMetadata.parse(body.decode("utf-8", errors="replace"), ws_path)


def _upgrade_websocket(
    domain: str,
    token: str,
    address: str,
    port: int,
    ws_path: str,
    deadline: float,
) -> None:
    """Perform the authenticated upgrade, greet the relay and require WELCOME."""
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    protocol = f"tproxy-v1.{token}"
    request = (
        f"GET {ws_path} HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
        f"Origin: https://{domain}\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Protocol: {protocol}\r\n\r\n"
    ).encode()
    with _tls_connection(domain, address, port, deadline) as tls:
        reader = _Reader(tls, deadline)
        tls.sendall(request)
        status, headers = _read_upgrade_response(reader)
        if status != 101:
            raise ProbeError(f"WebSocket-апгрейд отклонён (HTTP {status})")
        _require_upgrade_headers(headers, key, protocol)
        # The relay never welcoms a session that has not spoken first.
        _send_ws_frame(tls, hello_frame(), opcode=OPCODE_BINARY)
        if _read_frame(reader) != welcome_frame():
            raise ProbeError("WebSocket-апгрейд не подтверждён: мост не прислал WELCOME после HELLO")


def _require_upgrade_headers(headers: dict[str, str], key: str, protocol: str) -> None:
    """Verify the handshake echo; RFC 6455 §4.2.2 fixes SHA-1 for this check only."""
    accept_digest = hashlib.new("sha1", f"{key}{WEBSOCKET_GUID}".encode()).digest()
    if headers.get("sec-websocket-accept") != base64.b64encode(accept_digest).decode():
        raise ProbeError("WebSocket-апгрейд не подтверждён: неверный Sec-WebSocket-Accept")
    if headers.get("sec-websocket-protocol") != protocol:
        raise ProbeError("WebSocket-апгрейд не подтверждён: неверный Sec-WebSocket-Protocol")
    if headers.get("upgrade", "").lower() != "websocket":
        raise ProbeError("WebSocket-апгрейд не подтверждён: нет Upgrade: websocket")
    if "upgrade" not in [part.strip() for part in headers.get("connection", "").lower().split(",")]:
        raise ProbeError("WebSocket-апгрейд не подтверждён: нет Connection: Upgrade")


def _tls_connection(domain: str, address: str, port: int, deadline: float):
    """Open a verified TLS connection to the local frontend for one hostname."""
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection((address, port), timeout=_remaining(deadline))
    try:
        return context.wrap_socket(raw, server_hostname=domain)
    except Exception:
        raw.close()
        raise


class _Reader:
    """Bounded socket reader that never loses bytes past a header terminator."""

    def __init__(self, sock: Any, deadline: float) -> None:
        self._sock = sock
        self._deadline = deadline
        self._buffer = bytearray()

    def read_until(self, marker: bytes, limit: int) -> bytes:
        """Return everything up to and including ``marker``, keeping the rest."""
        while marker not in self._buffer:
            if len(self._buffer) >= limit:
                raise ProbeError("ответ WEB-моста превысил допустимый размер заголовков")
            self._fill(min(READ_CHUNK_BYTES, limit - len(self._buffer)))
        end = self._buffer.index(marker) + len(marker)
        head = bytes(self._buffer[:end])
        del self._buffer[:end]
        return head

    def read_exact(self, length: int) -> bytes:
        while len(self._buffer) < length:
            self._fill(length - len(self._buffer))
        chunk = bytes(self._buffer[:length])
        del self._buffer[:length]
        return chunk

    def drain(self, limit: int) -> bytes:
        """Read the remaining payload until the peer closes or ``limit`` is hit."""
        body = bytearray(self._buffer)
        del self._buffer[:]
        while True:
            if len(body) > limit:
                raise ProbeError("ответ WEB-моста слишком большой")
            try:
                chunk = self._sock.recv(READ_CHUNK_BYTES)
            except OSError as exc:
                raise ProbeError(f"ответ WEB-моста оборвался: {exc}") from exc
            if not chunk:
                return bytes(body)
            body.extend(chunk)

    def _fill(self, size: int) -> None:
        self._sock.settimeout(_remaining(self._deadline))
        chunk = self._sock.recv(max(1, size))
        if not chunk:
            raise ProbeError("соединение с WEB-мостом закрылось до конца ответа")
        self._buffer.extend(chunk)


def _read_http_response(reader: _Reader) -> tuple[int, dict[str, str], bytes]:
    """Read a bounded HTTP response, including the bridge page body."""
    status, headers = _parse_head(reader.read_until(b"\r\n\r\n", MAX_HEADER_BYTES))
    body = reader.drain(MAX_PAGE_BYTES + 1)
    if len(body) > MAX_PAGE_BYTES:
        raise ProbeError("страница WEB-моста слишком большая")
    return status, headers, body


def _read_upgrade_response(reader: _Reader) -> tuple[int, dict[str, str]]:
    """Read only the upgrade response head; the rest is a WebSocket stream."""
    return _parse_head(reader.read_until(b"\r\n\r\n", MAX_HEADER_BYTES))


def _parse_head(raw: bytes) -> tuple[int, dict[str, str]]:
    """Parse a status line and headers, rejecting duplicates and garbage."""
    try:
        lines = raw.decode("ascii").split("\r\n")
    except UnicodeDecodeError as exc:
        raise ProbeError("ответ WEB-моста не читается как ASCII") from exc
    parts = lines[0].split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProbeError("ответ WEB-моста не содержит HTTP-статуса")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ProbeError("заголовок ответа WEB-моста испорчен")
        name, value = line.split(":", 1)
        name = name.strip().lower()
        if name in headers:
            raise ProbeError(f"заголовок ответа WEB-моста повторяется: {name}")
        headers[name] = value.strip()
    return int(parts[1]), headers


def _read_frame(reader: _Reader) -> bytes:
    """Read one server frame, answering pings until a binary frame arrives."""
    for _ in range(MAX_FRAMES):
        first, second = reader.read_exact(2)
        if first & 0x70 or not first & 0x80 or second & 0x80:
            raise ProbeError("кадр WebSocket от WEB-моста испорчен")
        length = second & 0x7F
        if length == 126:
            length = struct.unpack(">H", reader.read_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", reader.read_exact(8))[0]
        opcode = first & 0x0F
        if length > MAX_FRAME_BYTES or (opcode >= OPCODE_CLOSE and length > 125):
            raise ProbeError("кадр WebSocket от WEB-моста слишком большой")
        payload = reader.read_exact(length)
        if opcode == OPCODE_PING:
            _send_ws_frame(reader._sock, payload, opcode=OPCODE_PONG)
            continue
        if opcode == OPCODE_PONG:
            continue
        if opcode == OPCODE_BINARY:
            return payload
        raise ProbeError("WebSocket-апгрейд не подтверждён: мост закрыл соединение")
    raise ProbeError("WebSocket-апгрейд не подтверждён: мост не ответил данными")


def _send_ws_frame(sock: Any, payload: bytes, *, opcode: int) -> None:
    """Send one masked client frame, as RFC 6455 requires from the client side."""
    mask = secrets.token_bytes(4)
    length = len(payload)
    header = bytes([0x80 | opcode, 0x80 | length]) if length < 126 else b"\x82\xfe" + struct.pack(">H", length)
    sock.sendall(header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))


def _remaining(deadline: float) -> float:
    """Return the time left in the probe budget, refusing to overrun it."""
    left = deadline - _now()
    if left <= 0:
        raise ProbeError(DEADLINE_REASON)
    return left


def _now() -> float:
    return time.monotonic()


class _BridgeMetadata(HTMLParser):
    """Read the bridge token and WebSocket path out of the relay page."""

    def __init__(self) -> None:
        super().__init__()
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta":
            return
        values = dict(attrs)
        name = values.get("name")
        if name not in ("tproxy-token", "tproxy-ws-path"):
            return
        if name in self.values:
            raise ProbeError("страница WEB-моста содержит повторяющиеся метаданные")
        self.values[name] = values.get("content") or ""

    @classmethod
    def parse(cls, page: str, ws_path: str) -> str:
        """Return the authenticated bridge token, or fail closed."""
        metadata = cls()
        metadata.feed(page)
        token = metadata.values.get("tproxy-token", "")
        path = metadata.values.get("tproxy-ws-path", "")
        if not BRIDGE_TOKEN.fullmatch(token) or path != ws_path:
            raise ProbeError("страница WEB-моста не отдала авторизованные метаданные моста")
        return token


__all__ = ["hello_frame", "probe_bridge", "welcome_frame"]
