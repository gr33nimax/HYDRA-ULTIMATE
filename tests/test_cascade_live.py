"""Opt-in data-plane acceptance with actual VLESS/XHTTP, AnyTLS, gRPC and mTLS."""
from __future__ import annotations

import os
import ssl
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hydra.contracts.managed_node_models import CascadeDefinition
from hydra.contracts.managed_node_probe import ProbeMaterial
from hydra.services.managed_nodes.identity import create_certificate_pair
from hydra.services.managed_nodes.probe_clients import ManagedNodeProbeClient
from hydra.services.subscriptions.node_exports import CascadeSubscriptionReader
from tests.cascade_lab import CascadeLab, USER, management_transport
from tests.cascade_live_lab import LiveNode

CORE = os.environ.get("HYDRA_CASCADE_CORE")
pytestmark = pytest.mark.skipif(not CORE, reason="set HYDRA_CASCADE_CORE to run the real-engine isolated acceptance")


@pytest.mark.parametrize("topology", [("base", "exit"), ("entry", "base"), ("entry", "exit")])
@pytest.mark.parametrize("protocol", ["vless", "anytls"])
def test_actual_two_hop_path_profiles_billing_and_no_exit_fallback(tmp_path, monkeypatch, topology, protocol):
    certificate, key = create_certificate_pair("lab", role="server", address="127.0.0.1")
    cert_path, key_path = tmp_path / "ca.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate)
    key_path.write_bytes(key)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_path))
    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass
    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    target.socket = context.wrap_socket(target.socket, server_side=True)
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    created = []
    def node_factory(root, identity, protocols):
        node = LiveNode(root, identity, protocols, binary=Path(CORE).resolve(), certificate=certificate, key=key,
                         index=len(created))
        created.append(node)
        return node
    try:
        lab = CascadeLab(tmp_path / "nodes", topology=topology, protocols=(protocol,), node_factory=node_factory)
        trusted = ssl.create_default_context(cafile=str(cert_path))
        probe = ManagedNodeProbeClient(host=lab.nodes["base"].host, binary=CORE,
            target_url=f"https://127.0.0.1:{target.server_port}/", ssl_context=trusted, auto_detect_interface=False)
        lab.runtime._path_publisher.probe_client = probe
        route = CascadeDefinition("live-route", "Live Route", *topology, [protocol])
        with management_transport(lab):
            result = lab.service.save_cascade(route, confirmed=True)
            assert result.state == "succeeded", result.error
            base, entry, exit = lab.nodes["base"], lab.nodes[topology[0]], lab.nodes[topology[1]]
            exported = CascadeSubscriptionReader(lab.publications).profiles_for_user(USER, base.read())
            assert len(exported) == 1
            document = next(config for config in exported[0].singbox
                            if any(item.get("type") == protocol for item in config.get("outbounds", [])))
            outbound = next(item for item in document["outbounds"] if item.get("type") == protocol)
            business_probe = ProbeMaterial(protocol, outbound)
            assert probe.probe_client(business_probe, node_id=route.id, deadline=time.monotonic() + 15).outcome == "ok"
            entry.final_accounting()
            exit.final_accounting()
            entry_bytes = sum(item["used"] for item in entry.state.install.get("cascade_counter_baselines", {}).values())
            transit_bytes = sum(item["used"] for item in exit.state.install.get("cascade_counter_baselines", {}).values())
            assert entry_bytes > 0 and transit_bytes == 0
            assert lab.service.refresh() == []
            exit.stop()
            assert probe.probe_client(business_probe, node_id=route.id, deadline=time.monotonic() + 10).outcome != "ok"
            assert lab.service.refresh()
            assert CascadeSubscriptionReader(lab.publications).profiles_for_user(USER, base.read()) == ()
            exit.write_config()
            assert lab.service.refresh() == []
            assert lab.service.remove_cascade(route.id, confirmed=True).state == "succeeded"
            assert all(not node.credentials.exists(route.id) for node in lab.nodes.values())
    finally:
        for node in created:
            node.stop()
        target.shutdown()
        target.server_close()
        thread.join(timeout=1)
