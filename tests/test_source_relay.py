import json
import socket
import struct
import threading
from unittest.mock import patch

from hydra.core.source_relay import (
    PROXY_V2_SIGNATURE, _handle, read_proxy_v2, resolve_mapping,
    resolve_recent_unique_source,
)
from hydra.plugins.antidpi.agent import (
    _resolve_relay_source, _resolve_unattributed_relay_source,
)


def _header(source: str, destination: str, source_port: int, destination_port: int) -> bytes:
    family = socket.AF_INET6 if ":" in source else socket.AF_INET
    packed = (
        socket.inet_pton(family, source) + socket.inet_pton(family, destination)
        + struct.pack("!HH", source_port, destination_port)
    )
    family_byte = 0x21 if family == socket.AF_INET6 else 0x11
    return PROXY_V2_SIGNATURE + bytes((0x21, family_byte)) + struct.pack("!H", len(packed)) + packed


def test_proxy_v2_ipv4_and_ipv6_are_parsed():
    for source, destination in (("198.51.100.8", "192.0.2.1"), ("2001:db8::8", "2001:db8::1")):
        left, right = socket.socketpair()
        try:
            right.sendall(_header(source, destination, 43123, 443))
            assert read_proxy_v2(left) == (source, 43123)
        finally:
            left.close()
            right.close()


def test_exact_mapping_resolves_parallel_connections(tmp_path):
    path = tmp_path / "map.jsonl"
    records = [
        {"at": 100, "protocol": "anytls", "relay_source_port": 32001, "source_ip": "198.51.100.1"},
        {"at": 100, "protocol": "anytls", "relay_source_port": 32002, "source_ip": "198.51.100.2"},
        {"at": 100, "protocol": "shadowtls", "relay_source_port": 32001, "source_ip": "198.51.100.3"},
    ]
    path.write_text("\n".join(json.dumps(item) for item in records), encoding="utf-8")
    assert resolve_mapping("anytls", 32001, now=101, path=path) == "198.51.100.1"
    assert resolve_mapping("anytls", 32002, now=101, path=path) == "198.51.100.2"
    assert resolve_mapping("shadowtls", 32001, now=101, path=path) == "198.51.100.3"


def test_recent_source_resolution_requires_unambiguous_external_ip(tmp_path):
    path = tmp_path / "map.jsonl"
    path.write_text(json.dumps({
        "at": 100, "protocol": "shadowtls", "source_ip": "198.51.100.3",
    }) + "\n", encoding="utf-8")
    assert resolve_recent_unique_source("shadowtls", now=101, path=path) == "198.51.100.3"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "at": 101, "protocol": "shadowtls", "source_ip": "198.51.100.4",
        }) + "\n")
    assert resolve_recent_unique_source("shadowtls", now=101, path=path) is None


def test_agent_replaces_only_exact_loopback_source():
    event = ("127.0.0.1", {"protocol": "anytls", "kind": "auth_failure", "peer_port": 32001})
    with patch("hydra.core.source_relay.resolve_mapping", return_value="203.0.113.9"):
        resolved = _resolve_relay_source(event)
    assert resolved[0] == "203.0.113.9"
    assert resolved[1]["source"] == "caddy-source-relay"
    assert resolved[1]["relay_peer_port"] == 32001


def test_agent_resolves_endpoint_free_native_error_only_when_unique():
    details = {"protocol": "shadowtls", "kind": "auth_failure", "source": "journal"}
    with patch("hydra.core.source_relay.resolve_recent_unique_source", return_value="203.0.113.10"):
        resolved = _resolve_unattributed_relay_source(details)
    assert resolved == (
        "203.0.113.10",
        {
            "protocol": "shadowtls", "kind": "auth_failure",
            "source": "caddy-source-relay", "attribution": "unique-recent-source",
        },
    )


def test_relay_strips_header_and_records_backend_peer_port(tmp_path):
    backend_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend_listener.bind(("127.0.0.1", 0))
    backend_listener.listen(1)
    client_side, caddy_side = socket.socketpair()
    mapping = tmp_path / "mappings.jsonl"
    with patch("hydra.core.source_relay.MAP_FILE", mapping):
        worker = threading.Thread(
            target=_handle,
            args=(client_side, "anytls", backend_listener.getsockname()[1]),
        )
        worker.start()
        caddy_side.sendall(_header("198.51.100.42", "192.0.2.1", 45123, 443) + b"native-probe")
        backend, peer = backend_listener.accept()
        assert backend.recv(64) == b"native-probe"
        assert resolve_mapping("anytls", peer[1], path=mapping) == "198.51.100.42"
        backend.sendall(b"reply")
        assert caddy_side.recv(64) == b"reply"
        backend.close()
        caddy_side.close()
        worker.join(timeout=2)
    backend_listener.close()
