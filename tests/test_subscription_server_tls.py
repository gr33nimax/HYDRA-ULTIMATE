"""TLS accept-order regression tests for the subscription listener."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from hydra.services.subscriptions.proxy_protocol import (
    SIGNATURE,
    looks_like_proxy_header,
)
from hydra.services.subscriptions.server import (
    SubscriptionHandler,
    _ProxyTLSHTTPServer,
    run_standalone,
)


def _server(
    connection: MagicMock,
    address: tuple[str, int],
) -> tuple[_ProxyTLSHTTPServer, MagicMock]:
    server = object.__new__(_ProxyTLSHTTPServer)
    server.socket = MagicMock()
    server.socket.accept.return_value = (connection, address)
    context = MagicMock()
    server.tls_context = context
    return server, context


def test_proxy_header_is_consumed_before_the_tls_handshake():
    connection = MagicMock()
    server, context = _server(connection, ("127.0.0.1", 45678))
    events: list[str] = []

    def read_proxy(current):
        assert current is connection
        events.append("proxy")
        return "198.51.100.7", 54321

    def wrap_tls(current, *, server_side):
        assert current is connection
        assert server_side is True
        events.append("tls")
        return "tls-connection"

    context.wrap_socket.side_effect = wrap_tls
    with patch(
        "hydra.services.subscriptions.server.read_source_address",
        side_effect=read_proxy,
    ):
        accepted = server.get_request()

    assert events == ["proxy", "tls"]
    assert accepted == ("tls-connection", ("198.51.100.7", 54321))


def test_direct_remote_tls_skips_proxy_protocol_parsing():
    connection = MagicMock()
    server, context = _server(connection, ("203.0.113.9", 45678))
    context.wrap_socket.return_value = "tls-connection"

    with patch(
        "hydra.services.subscriptions.server.read_source_address",
    ) as read_proxy:
        accepted = server.get_request()

    read_proxy.assert_not_called()
    assert accepted == ("tls-connection", ("203.0.113.9", 45678))


def test_malformed_proxy_header_closes_the_raw_connection():
    connection = MagicMock()
    server, context = _server(connection, ("127.0.0.1", 45678))

    with patch(
        "hydra.services.subscriptions.server.read_source_address",
        side_effect=OSError("truncated PROXY header"),
    ), pytest.raises(OSError, match="truncated"):
        server.get_request()

    connection.close.assert_called_once_with()
    context.wrap_socket.assert_not_called()


def test_fragmented_proxy_signature_is_not_mistaken_for_tls():
    connection = MagicMock()
    connection.recv.return_value = SIGNATURE[:4]

    assert looks_like_proxy_header(connection) is True


def test_standalone_server_wraps_each_accepted_connection():
    plugins = MagicMock()
    context = MagicMock()
    server = MagicMock()
    server.serve_forever.side_effect = KeyboardInterrupt

    with patch(
        "hydra.services.subscriptions.server.load_state",
    ), patch(
        "hydra.services.subscriptions.server.find_any_cert",
        return_value=("/cert.pem", "/key.pem"),
    ), patch(
        "hydra.services.subscriptions.server.ssl.SSLContext",
        return_value=context,
    ), patch(
        "hydra.services.subscriptions.server._ProxyTLSHTTPServer",
        return_value=server,
    ) as server_type:
        run_standalone(plugins, "127.0.0.1", 9443)

    context.load_cert_chain.assert_called_once_with(
        certfile="/cert.pem",
        keyfile="/key.pem",
    )
    server_type.assert_called_once_with(
        ("127.0.0.1", 9443),
        SubscriptionHandler,
        context,
    )
    server.server_close.assert_called_once_with()
