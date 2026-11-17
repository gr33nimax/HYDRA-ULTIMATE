"""Disposable TLS terminator for the canonical plaintext AnyTLS mux backend."""
from __future__ import annotations

import socket
import socketserver
import ssl
import threading


class TLSFrontend:
    def __init__(self, address, port, backend_port, certificate, private_key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, private_key)
        self.connections, self.lock = set(), threading.Lock()
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                raw = self.request
                raw.settimeout(2)
                client = raw
                try:
                    client = context.wrap_socket(raw, server_side=True)
                    backend = socket.create_connection((address, backend_port), timeout=2)
                except OSError:
                    client.close()
                    return
                client.settimeout(None)
                backend.settimeout(None)
                pair = (client, backend)
                with owner.lock:
                    owner.connections.add(pair)
                def forward(source, destination):
                    try:
                        while data := source.recv(65536):
                            destination.sendall(data)
                    except OSError:
                        pass
                    finally:
                        for connection in pair:
                            try:
                                connection.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                reply = threading.Thread(target=forward, args=(backend, client), daemon=True)
                reply.start()
                try:
                    forward(client, backend)
                    reply.join(timeout=2)
                finally:
                    for connection in pair:
                        connection.close()
                    with owner.lock:
                        owner.connections.discard(pair)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server((address, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        with self.lock:
            for pair in self.connections:
                for connection in pair:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        self.server.server_close()
        self.thread.join(timeout=2)
