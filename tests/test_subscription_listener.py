"""Real socket regressions: idle peers must not stall subscription requests."""
from __future__ import annotations

import socket
import ssl
import threading
from http.client import HTTPSConnection
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from hydra.services.subscriptions.proxy_protocol import SIGNATURE
from hydra.services.subscriptions.server import SubscriptionHandler, _ProxyTLSHTTPServer


@pytest.fixture
def tls_context(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context


@pytest.mark.parametrize("idle_phase", ["tls", "proxy", "http"])
def test_idle_peer_does_not_block_another_subscription_request(tls_context, idle_phase):
    server = _ProxyTLSHTTPServer(("127.0.0.1", 0), SubscriptionHandler, tls_context)
    server.subscription_plugins = MagicMock()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    idle = socket.create_connection(server.server_address, timeout=1)
    client_context = ssl._create_unverified_context()
    try:
        if idle_phase == "proxy":
            idle.sendall(SIGNATURE[:4])
        elif idle_phase == "http":
            idle = client_context.wrap_socket(idle, server_hostname="localhost")
        with socket.create_connection(server.server_address, timeout=1) as raw:
            with client_context.wrap_socket(raw, server_hostname="localhost") as client:
                client.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                assert b"404" in client.recv(4096)
    finally:
        idle.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_https_health_is_read_only_and_reports_unreadable_state(tls_context):
    server = _ProxyTLSHTTPServer(("127.0.0.1", 0), SubscriptionHandler, tls_context)
    server.subscription_plugins = MagicMock()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        for state_error, expected in [(None, 200), (ValueError("broken state"), 503)]:
            with patch("hydra.services.subscriptions.server.load_state", side_effect=state_error), \
                 patch("hydra.services.subscriptions.server.register_subscription_device") as register:
                client = HTTPSConnection(*server.server_address, timeout=2, context=ssl._create_unverified_context())
                try:
                    client.request("GET", "/healthz")
                    response = client.getresponse()
                    assert response.status == expected
                    body = response.read()
                    if expected == 200:
                        assert body == b'{"status":"ok"}'
                    register.assert_not_called()
                finally:
                    client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_worker_admission_is_bounded_and_timeout_frees_capacity(tls_context):
    entered = threading.Event()

    class LimitedServer(_ProxyTLSHTTPServer):
        max_connections = 1
        request_timeout = 0.15

        def _tls_request(self, connection, address):
            entered.set()
            return super()._tls_request(connection, address)

    server = LimitedServer(("127.0.0.1", 0), SubscriptionHandler, tls_context)
    server.subscription_plugins = MagicMock()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as idle:
            assert entered.wait(timeout=1)
            with socket.create_connection(server.server_address, timeout=1) as overflow:
                assert overflow.recv(1) == b""
            assert idle.recv(1) == b""
        # A timeout must release the admission slot for a real request.
        assert server._slots.acquire(timeout=1)
        server._slots.release()
        client = HTTPSConnection(*server.server_address, timeout=2, context=ssl._create_unverified_context())
        try:
            client.request("GET", "/")
            assert client.getresponse().status == 404
        finally:
            client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
