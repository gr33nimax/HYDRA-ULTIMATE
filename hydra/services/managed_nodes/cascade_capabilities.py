"""Prove auth_user routing and cumulative counters with the installed executable."""
from __future__ import annotations

import hashlib
import http.client
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from hydra.services.managed_nodes.cascade_stats import user_counters
from hydra.services.managed_nodes.identity import create_certificate_pair
from hydra.services.managed_nodes.probe_clients import _stop_process, ManagedNodeProbeClient


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class InstalledCascadeCapabilities:
    def __init__(self, *, host, binary):
        self.host, self.binary, self.cache = host, binary, {}
        self.lock = threading.Lock()

    def __call__(self, protocol, engine_digest):
        key = (protocol, engine_digest)
        with self.lock:
            if self.cache.get(key):
                return True
            try:
                actual = hashlib.sha256(self.host.read_bytes(Path(self.binary), max_bytes=256 * 1024 * 1024)).hexdigest()
                if actual != engine_digest:
                    return False
                result = self._prove(protocol)
            except Exception:
                return False
            if result:
                self.cache[key] = True
            return result

    def _prove(self, protocol):
        if protocol not in {"vless", "anytls"}:
            return False
        nonce = uuid.uuid4().hex.encode()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(nonce)))
                self.end_headers()
                self.wfile.write(nonce)

            def log_message(self, *_args):
                pass
        target = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=target.serve_forever, daemon=True)
        thread.start()
        processes = []
        directory = tempfile.mkdtemp(prefix="hydra-cascade-capability-")
        root = Path(directory)
        try:
            certificate, key = create_certificate_pair("cascade-proof", role="server", address="127.0.0.1")
            self.host.atomic_write(root / "cert.pem", certificate, mode=0o600)
            self.host.atomic_write(root / "key.pem", key, mode=0o600)
            inbound_port, mixed_port, stats_port = free_port(), free_port(), free_port()
            name, identity = "hydra-cascade-auth-proof", str(uuid.uuid4())
            auth_key, auth_value = ("uuid", identity) if protocol == "vless" else ("password", uuid.uuid4().hex)
            server = {
                "log": {"level": "error"},
                "inbounds": [{"type": protocol, "tag": "proof", "listen": "127.0.0.1", "listen_port": inbound_port,
                              "users": [{"name": name, auth_key: auth_value}],
                              "tls": {"enabled": True, "certificate_path": str(root / "cert.pem"),
                                      "key_path": str(root / "key.pem")}}],
                "outbounds": [{"type": "direct", "tag": "proof-direct"}],
                "route": {"rules": [{"auth_user": [name], "outbound": "proof-direct"}, {"action": "reject"}]},
                "experimental": {"v2ray_api": {"listen": f"127.0.0.1:{stats_port}",
                                               "stats": {"enabled": True, "users": [name]}}},
            }
            client = {
                "log": {"level": "error"},
                "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": mixed_port}],
                "outbounds": [{"type": protocol, "tag": "proof-client", "server": "127.0.0.1",
                               "server_port": inbound_port, auth_key: auth_value,
                               "tls": {"enabled": True, "server_name": "127.0.0.1",
                                       "certificate_path": str(root / "cert.pem")}}],
                "route": {"final": "proof-client"},
            }
            deadline = time.monotonic() + 15
            for label, config, port in (("server", server, inbound_port), ("client", client, mixed_port)):
                path = root / (label + ".json")
                self.host.atomic_write(path, json.dumps(config), mode=0o600)
                check = self.host.run([self.binary, "check", "-c", str(path)], timeout=5, text=True)
                if check.returncode:
                    return False
                process = self.host.popen([self.binary, "run", "-c", str(path)], timeout=15,
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(process)
                if not ManagedNodeProbeClient._wait_listener(port, process, deadline):
                    return False
            connection = http.client.HTTPConnection("127.0.0.1", mixed_port, timeout=5)
            try:
                connection.request("GET", f"http://127.0.0.1:{target.server_port}/proof")
                response = connection.getresponse()
                passed = response.status == 200 and response.read(128) == nonce
            finally:
                connection.close()
            return passed and user_counters(stats_port).get(name, 0) > 0
        finally:
            stopped = [_stop_process(process) for process in reversed(processes)]
            if all(stopped):
                shutil.rmtree(directory, ignore_errors=True)
            target.shutdown()
            target.server_close()
            thread.join(timeout=1)
