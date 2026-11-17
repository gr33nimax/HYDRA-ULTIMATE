"""Unprivileged real-core loopback lab; it never touches systemd, routing or firewall."""
from __future__ import annotations

import copy
import hashlib
import json
import socket
import subprocess
import time

from hydra.services.managed_nodes.cascade_capabilities import InstalledCascadeCapabilities, free_port
from hydra.services.managed_nodes.cascade_accounting import scoped_samples
from hydra.services.managed_nodes.accounting import apply_traffic_samples
from hydra.services.managed_nodes.cascade_stats import user_counters
from hydra.services.managed_nodes.probe_clients import _stop_process
from tests.cascade_lab import LabNode
from tests.cascade_tls_frontend import TLSFrontend


class MappedProtocols:
    """Map the fixture's separate VPS addresses onto isolated loopback addresses."""
    def __init__(self, owner, original):
        self.owner, self.original = owner, original

    def __getattr__(self, name):
        return getattr(self.original, name)

    def singbox_client_config(self, state, protocol, user, **kwargs):
        return self._map(self.original.singbox_client_config(state, protocol, user, **kwargs), protocol)

    def client_config(self, state, protocol, user, **kwargs):
        return self._map(self.original.client_config(state, protocol, user, **kwargs), protocol)

    def _map(self, payload, protocol):
        document = json.loads(payload)
        for outbound in document.get("outbounds", []):
            if outbound.get("type") == protocol:
                outbound.update(server=self.owner.address, server_port=self.owner.data_ports[protocol])
                outbound["tls"]["server_name"] = "127.0.0.1"
        return json.dumps(document)


class LiveNode(LabNode):
    def __init__(self, root, identity, protocols, *, binary, certificate, key, index):
        self.binary, self.certificate, self.key = binary, certificate, key
        self.address, self.stats_port = f"127.0.0.{index + 2}", free_port()
        self.data_ports = {name: free_port() for name in protocols}
        self.backend_ports = {name: free_port() if name == "anytls" else port
                              for name, port in self.data_ports.items()}
        self.frontend = None
        self.process, self.log_file = None, None
        self.engine_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        super().__init__(root, identity, protocols)
        if "anytls" in protocols:
            # Production terminates TLS in Caddy before the canonical AnyTLS inbound.
            self.frontend = TLSFrontend(self.address, self.data_ports["anytls"], self.backend_ports["anytls"],
                                        root / "cert.pem", root / "key.pem")
        self.protocols = MappedProtocols(self, self.protocols)
        self.owner.protocols = self.protocols
        self.owner.capability_probe = InstalledCascadeCapabilities(host=self.host, binary=str(binary))
        self.owner.stats_reader = lambda: user_counters(self.stats_port)
        self.owner.final_accounting = self.final_accounting

    def render(self, state):
        state = copy.deepcopy(state)
        state.install["cascade_stats_port"] = self.stats_port
        config = super().render(state)
        # No privileged marks or host interface discovery are needed in this disposable lab.
        config["route"].pop("default_mark", None)
        config["route"]["auto_detect_interface"] = False
        for inbound in config["inbounds"]:
            inbound["listen"] = self.address
            if inbound.get("type") in {"vless", "anytls"}:
                inbound["listen_port"] = self.backend_ports[inbound["type"]]
                inbound.get("tls", {})["server_name"] = "127.0.0.1"
        return config

    def write_config(self):
        self.host.atomic_write(self.root / "cert.pem", self.certificate, mode=0o600)
        self.host.atomic_write(self.root / "key.pem", self.key, mode=0o600)
        super().write_config()
        result = self.host.run([str(self.binary), "check", "-c", str(self.config)], timeout=10, text=True)
        if result.returncode:
            raise RuntimeError("real core rejected the canonical test configuration: " + result.stderr[-1000:])
        self.stop()
        self.log_file = open(self.root / "engine.log", "ab")
        self.process = self.host.popen([str(self.binary), "run", "-c", str(self.config)], timeout=30,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.log_file)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("real core could not start; see isolated engine.log")
            try:
                for port in self.backend_ports.values():
                    with socket.create_connection((self.address, port), timeout=0.1):
                        pass
                return
            except OSError:
                time.sleep(0.03)
        raise RuntimeError("real core listener did not start")

    def context(self):
        return self.engine_digest, hashlib.sha256(self.config.read_bytes()).hexdigest()

    def observe(self):
        return {"engine_active": bool(self.process and self.process.poll() is None), "config_sha256": self.context()[1],
                "runtime_id": hashlib.sha256(f"{self.identity}:{getattr(self.process, 'pid', 0)}:{self.applies}".encode()).hexdigest()}

    def stop(self):
        if self.process is not None:
            if not _stop_process(self.process):
                raise RuntimeError("could not stop real core test process")
        if self.log_file is not None:
            self.log_file.close()
            self.log_file = None

    def final_accounting(self):
        config = json.loads(self.config.read_bytes())
        if "v2ray_api" not in config.get("experimental", {}):
            return
        bindings = self.deployments.counter_bindings(self.read())
        raw, epoch = user_counters(self.stats_port), self.observe()["runtime_id"]
        def mutate(state):
            samples = scoped_samples(state, bindings, raw, epoch)
            if self.identity == "base":
                apply_traffic_samples(state, "base-cascades", samples)
        self.update(mutate)

    def close(self):
        self.stop()
        if self.frontend is not None:
            self.frontend.close()
