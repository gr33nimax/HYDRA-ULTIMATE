from __future__ import annotations

import socket
import ssl
import time
from pathlib import Path

import pytest

from hydra.contracts.managed_node_models import Operation
from hydra.contracts.managed_node_observations import NodeSample
from hydra.services.managed_nodes.agent import ManagedNodeAgent
from hydra.services.managed_nodes.client import ManagedNodeClient, ManagedNodeError
from hydra.services.managed_nodes.identity import (
    ManagementIdentity,
    certificate_fingerprint,
    create_certificate_pair,
)
from hydra.services.managed_nodes.transport import ManagedNodeServer


def write_pair(root: Path, name: str, identity: str, role: str):
    cert, key = create_certificate_pair(identity, role=role, address="127.0.0.1" if role == "server" else None)
    cert_path, key_path = root / f"{name}.crt", root / f"{name}.key"
    cert_path.write_bytes(cert)
    key_path.write_bytes(key)
    return cert, cert_path, key_path


def loopback(tmp_path: Path, *, max_workers: int = 4):
    client_cert, client_certificate, client_key = write_pair(tmp_path, "base", "base", "client")
    server_cert, server_certificate, server_key = write_pair(tmp_path, "node", "de-1", "server")
    node_identity = ManagementIdentity(
        "de-1",
        "127.0.0.1",
        0,
        server_certificate,
        server_key,
        tmp_path / "base.crt",
        certificate_fingerprint(client_cert),
        ("127.0.0.1",),
    )
    node_identity.trusted_client_certificate_path.write_bytes(client_cert)
    agent = ManagedNodeAgent(
        node_id="de-1",
        state_provider=lambda: NodeSample("de-1", users_applied=0, users_digest="a" * 64),
        submit_provider=lambda operation_id, desired: Operation(
            operation_id,
            "apply",
            "de-1",
            desired.digest,
            "succeeded",
        ),
        operation_provider=lambda operation_id: None,
        profiles_provider=lambda: pytest.fail("profiles provider not expected"),
    )
    server = ManagedNodeServer(
        node_identity, agent, bind_host="127.0.0.1", max_workers=max_workers, request_timeout=0.5
    )
    server.start()
    client = ManagedNodeClient(
        host="127.0.0.1",
        port=server.port,
        node_id="de-1",
        certificate=client_certificate,
        private_key=client_key,
        pinned_server_certificate=server_cert,
    )
    return server, client, client_cert, client_certificate, client_key, server_cert, server_certificate, server_key


def test_real_loopback_mtls_v1_state_and_apply_and_reject_wrong_client(tmp_path: Path):
    server, client, *_rest = loopback(tmp_path)
    try:
        state = client.state(time.monotonic() + 3)
        assert state.node_id == "de-1" and state.users_applied == 0
        from hydra.contracts.managed_node_models import NodeDesired

        desired = NodeDesired("de-1", 1, [], [])
        result = client.submit("apply-1", desired, time.monotonic() + 3)
        assert result.id == "apply-1" and result.state == "succeeded"

        intruder_cert, intruder_certificate, intruder_key = write_pair(tmp_path, "intruder", "intruder", "client")
        wrong = ManagedNodeClient(
            host="127.0.0.1",
            port=server.port,
            node_id="de-1",
            certificate=intruder_certificate,
            private_key=intruder_key,
            pinned_server_certificate=server.certificate_bytes,
        )
        with pytest.raises(ManagedNodeError) as rejected:
            wrong.state(time.monotonic() + 2)
        assert rejected.value.stage in {"tls", "http"}
        assert intruder_cert

        wrong_server_cert, _wrong_certificate, _wrong_key = write_pair(tmp_path, "wrong-node", "de-1", "server")
        wrong_pin = ManagedNodeClient(
            host="127.0.0.1",
            port=server.port,
            node_id="de-1",
            certificate=client.certificate,
            private_key=client.private_key,
            pinned_server_certificate=wrong_server_cert,
        )
        with pytest.raises(ManagedNodeError) as tls:
            wrong_pin.state(time.monotonic() + 2)
        assert tls.value.stage == "tls"
    finally:
        server.close()


def test_server_checks_source_ip_and_rejects_a_missing_client_certificate(tmp_path: Path):
    server, client, *_rest = loopback(tmp_path)
    port = server.port
    assert server._source_allowed("127.0.0.1")
    assert not server._source_allowed("127.0.0.2")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=server.certificate_bytes.decode())
    context.check_hostname = False
    raw = socket.create_connection(("127.0.0.1", server.port), timeout=1)
    rejected = False
    try:
        try:
            connection = context.wrap_socket(raw, server_hostname=None)
        except ssl.SSLError:
            rejected = True
        else:
            connection.settimeout(1)
            try:
                connection.sendall(b"GET /v1/state HTTP/1.1\r\nHost: node\r\n\r\n")
                rejected = connection.recv(1) == b""
            except (OSError, ssl.SSLError):
                rejected = True
            finally:
                connection.close()
    finally:
        raw.close()
        server.close()
    assert rejected

    with pytest.raises(ValueError, match="invalid"):
        ManagedNodeClient(
            host="127.0.0.1",
            port=port,
            node_id="de-1",
            certificate=client.certificate,
            private_key=client.private_key,
            pinned_server_certificate=b"not a certificate",
        )


def test_idle_tcp_and_partial_http_do_not_block_other_state_requests(tmp_path: Path):
    server, client, _cert, client_certificate, client_key, *_rest = loopback(tmp_path, max_workers=3)
    idle = socket.create_connection(("127.0.0.1", server.port), timeout=1)
    partial = socket.create_connection(("127.0.0.1", server.port), timeout=1)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=server.certificate_bytes.decode())
    context.check_hostname = False
    context.load_cert_chain(str(client_certificate), str(client_key))
    partial_tls = context.wrap_socket(partial, server_hostname=None)
    partial_tls.sendall(
        b"POST /v1/apply HTTP/1.1\r\nHost: node\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{}"
    )
    try:
        assert client.state(time.monotonic() + 2).node_id == "de-1"
    finally:
        idle.close()
        partial_tls.close()
        server.close()


def test_request_saturation_is_bounded_and_tcp_tls_http_errors_keep_their_phase(tmp_path: Path):
    server, client, *_rest = loopback(tmp_path, max_workers=2)
    sockets = [socket.create_connection(("127.0.0.1", server.port), timeout=1) for _ in range(12)]
    try:
        time.sleep(0.1)
        assert server.active_workers <= 2
        closed = ManagedNodeClient(
            host="127.0.0.1",
            port=1,
            node_id="de-1",
            certificate=client.certificate,
            private_key=client.private_key,
            pinned_server_certificate=server.certificate_bytes,
        )
        with pytest.raises(ManagedNodeError) as tcp:
            closed.state(time.monotonic() + 1)
        assert tcp.value.stage == "tcp"
    finally:
        for connection in sockets:
            connection.close()
        server.close()
