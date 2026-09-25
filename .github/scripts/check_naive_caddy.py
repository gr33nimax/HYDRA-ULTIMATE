"""CI-only build, real Caddy validation and HTTP/1.1 CONNECT smoke test."""
from __future__ import annotations

import base64
import json
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path

from hydra.plugins.naive.configuration import render_caddyfile
from hydra.plugins.naive.plugin import NaivePlugin


def read_exact(stream, size):
    result = b""
    while len(result) < size:
        part = stream.read(size - len(result))
        if not part:
            raise EOFError("SOCKS stream closed")
        result += part
    return result


class SocksEcho(socketserver.StreamRequestHandler):
    """Record CONNECT targets and echo bytes without decoding UoT."""

    def handle(self):
        self.request.settimeout(10)
        version, count = read_exact(self.rfile, 2)
        assert version == 5 and 0 in read_exact(self.rfile, count)
        self.wfile.write(b"\x05\x00")
        version, command, reserved, kind = read_exact(self.rfile, 4)
        assert (version, command, reserved, kind) == (5, 1, 0, 3)
        target = read_exact(self.rfile, read_exact(self.rfile, 1)[0]).decode()
        read_exact(self.rfile, 2)
        self.server.targets.append(target)
        self.wfile.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x04\x38")
        while data := self.request.recv(4096):
            self.wfile.write(data)


def connect_and_echo(port, cert, target):
    context = ssl.create_default_context(cafile=str(cert))
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as connection:
            assert connection.selected_alpn_protocol() == "http/1.1"
            auth = base64.b64encode(b"ci-user:ci-password").decode()
            connection.sendall(
                (f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n"
                 f"Proxy-Authorization: Basic {auth}\r\n\r\n").encode(),
            )
            response = b""
            while not response.endswith(b"\r\n\r\n"):
                chunk = connection.recv(1)
                assert chunk, response
                response += chunk
                assert len(response) < 65536
            assert response.startswith(b"HTTP/1.1 200"), response
            payload = b"\x00\xffhydra-uot-passthrough\x00"
            connection.sendall(payload)
            with connection.makefile("rb") as stream:
                assert read_exact(stream, len(payload)) == payload


def run_check(directory):
    plugin = NaivePlugin()
    layout = replace(plugin._runtime_layout(), binary=directory / "caddy-naive")
    plugin._runtime_layout = lambda: layout
    assert plugin._download_binary(), "Naive installer failed"
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
    ], check=True, capture_output=True, timeout=30)
    config = directory / "Caddyfile"
    for proxy_protocol in (False, True):
        config.write_text(render_caddyfile(
            domain="localhost", port=18443,
            users=[{"username": "ci-user", "password": "ci-password"}],
            decoy_dir=directory, log_dir=directory,
            cert_file=str(cert), key_file=str(key),
            accept_proxy_protocol=proxy_protocol,
        ))
        assert not plugin._validate_caddy(config), "Real Caddy validation failed"
        adapted = subprocess.run([
            str(layout.binary), "adapt", "--config", str(config), "--adapter", "caddyfile",
        ], check=True, capture_output=True, text=True, timeout=30)
        servers = json.loads(adapted.stdout)["apps"]["http"]["servers"]
        assert all(server["protocols"] == ["h1", "h2", "h3"] for server in servers.values())
        if not proxy_protocol:
            direct_config = config.read_text()
    config.write_text(direct_config)
    with socketserver.ThreadingTCPServer(("127.0.0.1", 1080), SocksEcho) as socks:
        socks.daemon_threads = True
        socks.targets = []
        thread = threading.Thread(target=socks.serve_forever, daemon=True)
        thread.start()
        with (directory / "runtime.log").open("w+") as log:
            process = subprocess.Popen([
                str(layout.binary), "run", "--config", str(config), "--adapter", "caddyfile",
            ], stdout=log, stderr=log)
            try:
                for attempt in range(100):
                    assert process.poll() is None, "Caddy exited before readiness"
                    try:
                        with socket.create_connection(("127.0.0.1", 18443), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.1)
                for target in ("example.test", "sp.udp-over-tcp.arpa", "sp.v2.udp-over-tcp.arpa"):
                    connect_and_echo(18443, cert, target)
                    assert socks.targets[-1] == target
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read())
                raise
            finally:
                process.terminate()
                process.wait(timeout=10)
                socks.shutdown()
                thread.join(timeout=5)
    print("Naive: real config validation, HTTP/1.1 CONNECT and UoT passthrough passed")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="hydra-naive-ci-") as temporary:
        run_check(Path(temporary))
