"""Bounded HTTPS workers with trusted loopback PROXY protocol support."""
from __future__ import annotations

import ipaddress
import ssl
import threading
from http.server import HTTPServer
from socketserver import ThreadingMixIn

from hydra.services.subscriptions.proxy_protocol import read_source_address


def _is_loopback(address: tuple[object, ...]) -> bool:
    try:
        return ipaddress.ip_address(str(address[0])).is_loopback
    except ValueError:
        return False


class _ProxyTLSHTTPServer(ThreadingMixIn, HTTPServer):
    """Keep PROXY reads, TLS handshakes and HTTP reads outside the accept loop."""

    daemon_threads = True
    block_on_close = False
    max_connections = 32
    request_timeout = 5.0

    def __init__(self, server_address, handler_class, tls_context: ssl.SSLContext) -> None:
        self.tls_context = tls_context
        self._slots = threading.BoundedSemaphore(self.max_connections)
        super().__init__(server_address, handler_class)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.request_timeout)
        return connection, address

    def _tls_request(self, connection, address):
        try:
            source = read_source_address(connection) if _is_loopback(address) else None
            tls_connection = self.tls_context.wrap_socket(connection, server_side=True)
        except Exception:
            connection.close()
            raise
        return tls_connection, source or address

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        connection = request
        try:
            connection, address = self._tls_request(request, client_address)
            self.finish_request(connection, address)
        except OSError:
            pass
        except Exception:
            self.handle_error(request, client_address)
        finally:
            try:
                self.shutdown_request(connection)
            finally:
                self._slots.release()
