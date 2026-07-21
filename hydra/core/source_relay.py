"""Exact source attribution relay for Caddy-proxied TCP protocols.

Caddy sends PROXY v2 to this loopback-only relay.  The relay removes the
header before forwarding bytes to a protocol backend and records the outbound
socket port.  Protocol logs expose that port, allowing AntiDPI to recover the
original peer without timing-based correlation.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import selectors
import socket
import struct
import threading
import time
from pathlib import Path

MAP_FILE = Path("/run/hydra-source-relay/mappings.jsonl")
PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
MAX_PROXY_PAYLOAD = 512
MAPPING_TTL = 300.0
MAX_MAP_BYTES = 8 * 1024 * 1024
MAX_CONNECTIONS = 2048


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed in PROXY v2 header")
        data.extend(chunk)
    return bytes(data)


def read_proxy_v2(sock: socket.socket) -> tuple[str, int]:
    """Read one required PROXY v2 header and return its source endpoint."""
    header = _recv_exact(sock, 16)
    if header[:12] != PROXY_V2_SIGNATURE or header[12] >> 4 != 2:
        raise ValueError("missing PROXY v2 header")
    command = header[12] & 0x0F
    family = header[13] >> 4
    transport = header[13] & 0x0F
    length = struct.unpack("!H", header[14:16])[0]
    if command != 1 or transport != 1 or length > MAX_PROXY_PAYLOAD:
        raise ValueError("unsupported PROXY v2 command")
    payload = _recv_exact(sock, length)
    if family == 1 and length >= 12:
        return socket.inet_ntop(socket.AF_INET, payload[:4]), struct.unpack("!H", payload[8:10])[0]
    if family == 2 and length >= 36:
        return socket.inet_ntop(socket.AF_INET6, payload[:16]), struct.unpack("!H", payload[32:34])[0]
    raise ValueError("unsupported PROXY v2 address family")


_map_lock = threading.Lock()


def record_mapping(protocol: str, backend_port: int, relay_source_port: int,
                   source_ip: str, source_port: int) -> None:
    record = {
        "at": time.time(), "protocol": protocol, "backend_port": backend_port,
        "relay_source_port": relay_source_port,
        "source_ip": ipaddress.ip_address(source_ip).compressed,
        "source_port": int(source_port),
    }
    MAP_FILE.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, separators=(",", ":")) + "\n"
    with _map_lock:
        try:
            if MAP_FILE.stat().st_size > MAX_MAP_BYTES:
                retained = MAP_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-4096:]
                MAP_FILE.write_text("\n".join(retained) + "\n", encoding="utf-8")
        except OSError:
            pass
        with MAP_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
        try:
            MAP_FILE.chmod(0o640)
        except OSError:
            pass


def resolve_mapping(protocol: str, relay_source_port: int, *, now: float | None = None,
                    path: Path | None = None) -> str | None:
    """Resolve the newest non-expired exact protocol/source-port mapping."""
    mapping_path = path or MAP_FILE
    timestamp = time.time() if now is None else now
    try:
        # The runtime file is bounded by service startup and normally tiny.
        lines = mapping_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines[-8192:]):
        try:
            item = json.loads(line)
            if str(item.get("protocol")) != str(protocol):
                continue
            if int(item.get("relay_source_port", 0)) != int(relay_source_port):
                continue
            if timestamp - float(item.get("at", 0)) > MAPPING_TTL:
                return None
            return ipaddress.ip_address(item.get("source_ip", "")).compressed
        except (TypeError, ValueError):
            continue
    return None


def resolve_recent_unique_source(protocol: str, *, now: float | None = None,
                                 window: float = 2.0,
                                 path: Path | None = None) -> str | None:
    """Resolve a source only when all very recent mappings agree on one IP.

    Some native protocol errors omit the peer endpoint entirely.  A short,
    ambiguity-safe lookup lets AntiDPI attribute those errors during a single
    test/connection without ever selecting an arbitrary concurrent peer.
    """
    mapping_path = path or MAP_FILE
    timestamp = time.time() if now is None else now
    sources: set[str] = set()
    try:
        lines = mapping_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines[-8192:]):
        try:
            item = json.loads(line)
            age = timestamp - float(item.get("at", 0))
            if age > window:
                break
            if age < -1 or str(item.get("protocol")) != str(protocol):
                continue
            sources.add(ipaddress.ip_address(item.get("source_ip", "")).compressed)
            if len(sources) > 1:
                return None
        except (TypeError, ValueError):
            continue
    return next(iter(sources), None)


def _pipe(client: socket.socket, backend: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    selector.register(client, selectors.EVENT_READ, backend)
    selector.register(backend, selectors.EVENT_READ, client)
    try:
        while True:
            ready = selector.select(timeout=120)
            if not ready:
                return
            for key, _ in ready:
                chunk = key.fileobj.recv(65536)
                if not chunk:
                    return
                key.data.sendall(chunk)
    finally:
        selector.close()


def _handle(client: socket.socket, protocol: str, backend_port: int) -> None:
    backend = None
    try:
        client.settimeout(5)
        source_ip, source_port = read_proxy_v2(client)
        backend = socket.create_connection(("127.0.0.1", backend_port), timeout=5)
        relay_port = backend.getsockname()[1]
        record_mapping(protocol, backend_port, relay_port, source_ip, source_port)
        client.settimeout(None)
        backend.settimeout(None)
        _pipe(client, backend)
    except (OSError, ValueError, ConnectionError):
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass
        if backend is not None:
            try:
                backend.close()
            except OSError:
                pass


_connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)


def _handle_guarded(client: socket.socket, protocol: str, backend_port: int) -> None:
    try:
        _handle(client, protocol, backend_port)
    finally:
        _connection_slots.release()


def _open_listener(listen_port: int) -> socket.socket:
    # Caddy dials the explicit IPv4 loopback address from its generated config.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", listen_port))
        listener.listen(256)
        return listener
    except Exception:
        listener.close()
        raise


def _serve(listener: socket.socket, protocol: str, backend_port: int) -> None:
    while True:
        client, peer = listener.accept()
        if not ipaddress.ip_address(peer[0]).is_loopback:
            client.close()
            continue
        if not _connection_slots.acquire(blocking=False):
            client.close()
            continue
        threading.Thread(
            target=_handle_guarded, args=(client, protocol, backend_port), daemon=True,
        ).start()


def run(routes: list[tuple[str, int, int]]) -> None:
    MAP_FILE.parent.mkdir(parents=True, exist_ok=True)
    MAP_FILE.write_text("", encoding="utf-8")
    listeners = []
    try:
        listeners = [_open_listener(route[1]) for route in routes]
    except Exception:
        for listener in listeners:
            listener.close()
        raise
    threads = []
    for listener, (protocol, _listen_port, backend_port) in zip(listeners, routes):
        thread = threading.Thread(
            target=_serve, args=(listener, protocol, backend_port), daemon=True,
        )
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--route", action="append", default=[], metavar="PROTO:LISTEN:BACKEND")
    args = parser.parse_args(argv)
    routes = []
    for raw in args.route:
        protocol, listen, backend = raw.split(":", 2)
        routes.append((protocol, int(listen), int(backend)))
    if not routes:
        parser.error("at least one --route is required")
    run(routes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
