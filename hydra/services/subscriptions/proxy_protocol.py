"""PROXY protocol v2 support for the subscription listener.

Behind the TLS multiplexer the subscription server accepts every request from
loopback, so the client address it would otherwise record is the proxy's. Caddy
prefixes such connections with a PROXY v2 header carrying the original peer.
"""
from __future__ import annotations

import socket
import struct


SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
HEADER_LENGTH = 16
_FAMILY_TCP4 = 0x11
_FAMILY_TCP6 = 0x21
_COMMAND_PROXY = 0x21
_ADDRESS_SIZES = {_FAMILY_TCP4: 12, _FAMILY_TCP6: 36}


def looks_like_proxy_header(connection: socket.socket) -> bool:
    """Peek at the stream to see whether a PROXY v2 header is waiting."""
    try:
        prefix = connection.recv(len(SIGNATURE), socket.MSG_PEEK)
    except (OSError, ValueError):
        return False
    return bool(prefix) and SIGNATURE.startswith(prefix)


def _read_exactly(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = connection.recv(remaining)
        if not chunk:
            raise OSError("truncated PROXY header")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_source_address(
    connection: socket.socket,
) -> tuple[str, int] | None:
    """Consume a PROXY v2 header and return the original client address.

    Returns ``None`` when the stream carries no header, when the connection was
    made locally (``LOCAL`` command, e.g. a health check) or when the address
    family is not TCP over IP.
    """
    if not looks_like_proxy_header(connection):
        return None
    header = _read_exactly(connection, HEADER_LENGTH)
    command = header[12]
    family = header[13]
    length = struct.unpack("!H", header[14:16])[0]
    payload = _read_exactly(connection, length) if length else b""
    if command != _COMMAND_PROXY:
        return None
    size = _ADDRESS_SIZES.get(family)
    if size is None or len(payload) < size:
        return None
    if family == _FAMILY_TCP4:
        source = socket.inet_ntop(socket.AF_INET, payload[0:4])
        port = struct.unpack("!H", payload[8:10])[0]
    else:
        source = socket.inet_ntop(socket.AF_INET6, payload[0:16])
        port = struct.unpack("!H", payload[32:34])[0]
    return source, port


__all__ = [
    "HEADER_LENGTH",
    "SIGNATURE",
    "looks_like_proxy_header",
    "read_source_address",
]
