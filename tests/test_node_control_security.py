"""Transport security and bounded request handling for the node control API."""

from __future__ import annotations

import ipaddress
import json
import ssl
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from hydra.contracts.node_export import NodeClientExport
from hydra.contracts.node_snapshot import NodeDesiredSnapshot
from hydra.contracts.node_traffic import NodeTrafficReport
from hydra.core.node_identity import NodeIdentity

from tests.node_mtls import certificate_fingerprint, write_certificates


class _Operations:
    node_id = "de-1"

    def __init__(self):
        self.generation = 0
        self.applied: list[NodeDesiredSnapshot] = []
        self.upgrade_requests: list[tuple[str, str]] = []

    def current_generation(self) -> int:
        return self.generation

    def apply(self, snapshot: NodeDesiredSnapshot) -> None:
        self.applied.append(snapshot)
        self.generation = snapshot.generation

    def export(self) -> NodeClientExport:
        return NodeClientExport(node_id=self.node_id, generation=self.generation)

    def traffic_report(self) -> NodeTrafficReport:
        return NodeTrafficReport(node_id=self.node_id, generation=self.generation)

    def diagnostics(self) -> dict[str, object]:
        return {"last_error": "", "generation": self.generation}

    def installed_revision(self) -> str:
        return "a" * 40

    def schedule_upgrade(self, *, branch: str, revision: str) -> dict[str, object]:
        self.upgrade_requests.append((branch, revision))
        return {"status": "scheduled", "branch": branch, "revision": revision}


@pytest.fixture
def secured_server(tmp_path):
    from hydra.services.nodes.transport import create_control_server

    files = write_certificates(tmp_path)
    identity = NodeIdentity(
        node_id="de-1",
        base_url="https://base.example.com:8443",
        base_ip="127.0.0.1",
        certificate=str(files["server_cert"]),
        private_key=str(files["server_key"]),
        base_ca=str(files["ca"]),
        base_fingerprint=certificate_fingerprint(files["client_cert"]),
    )
    operations = _Operations()
    server = create_control_server(identity, operations, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, thread, operations, files
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_mtls_client_can_read_health_apply_and_fetch_export(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient

    server, _, operations, files = secured_server
    host, port = server.server_address[:2]
    client = NodeControlClient(
        host=host,
        port=port,
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
        server_fingerprint=certificate_fingerprint(files["server_cert"]),
    )
    assert client.health()["generation"] == 0
    snapshot = NodeDesiredSnapshot(node_id="de-1", generation=1)
    assert client.apply(snapshot)["generation"] == 1
    assert operations.applied == [snapshot]
    assert client.export() == NodeClientExport(node_id="de-1", generation=1)
    assert client.traffic_report() == NodeTrafficReport(node_id="de-1", generation=1)
    assert client.diagnostics()["generation"] == 1


def test_mutual_tls_upgrade_request_schedules_exact_revision(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient

    server, _, operations, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
        server_fingerprint=certificate_fingerprint(files["server_cert"]),
    )
    revision = "c" * 40

    result = client.upgrade(branch="main", revision=revision)

    assert result == {"status": "scheduled", "branch": "main", "revision": revision}
    assert operations.upgrade_requests == [("main", revision)]


def test_node_rejects_malformed_upgrade_request_before_scheduling(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient, NodeControlError

    server, _, operations, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
        server_fingerprint=certificate_fingerprint(files["server_cert"]),
    )

    with pytest.raises(NodeControlError, match="invalid upgrade request"):
        client._request("POST", "/upgrade", {"branch": "main", "revision": "not-a-sha"})

    assert operations.upgrade_requests == []


def test_upgrade_requires_the_pinned_base_certificate(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient, NodeControlError

    server, _, operations, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["other_client_cert"],
        private_key=files["other_client_key"],
        server_fingerprint=certificate_fingerprint(files["server_cert"]),
    )

    with pytest.raises(NodeControlError, match="base certificate fingerprint"):
        client.upgrade(branch="main", revision="c" * 40)

    assert operations.upgrade_requests == []


def test_upgrade_request_body_is_small_and_bounded(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient, NodeControlError

    server, _, operations, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
        server_fingerprint=certificate_fingerprint(files["server_cert"]),
    )

    with pytest.raises(NodeControlError, match="request body exceeds the supported size"):
        client.upgrade(branch="x" * 1100, revision="c" * 40)

    assert operations.upgrade_requests == []


def test_server_filters_peer_ip_by_pinned_base_ip(secured_server):
    server, _, _, _ = secured_server
    assert server.verify_request(None, ("127.0.0.1", 0)) is True
    assert server.verify_request(None, ("127.0.0.2", 0)) is False


def test_node_rejects_client_certificate_with_wrong_trustedcertificate_fingerprint(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient, NodeControlError

    server, _, _, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["other_client_cert"],
        private_key=files["other_client_key"],
        server_fingerprint=certificate_fingerprint(files["server_cert"]),
    )
    with pytest.raises(NodeControlError, match="base certificate fingerprint"):
        client.health()


def test_client_rejects_wrong_pinned_nodecertificate_fingerprint(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient, NodeControlError

    server, _, _, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
        server_fingerprint="0" * 64,
    )
    with pytest.raises(NodeControlError, match="node certificate fingerprint"):
        client.health()


def test_node_rejects_untrusted_or_missing_client_certificate(secured_server):
    server, _, _, files = secured_server
    url = f"https://127.0.0.1:{server.server_address[1]}/health"
    context = ssl.create_default_context(cafile=str(files["ca"]))
    with pytest.raises((OSError, urllib.error.URLError, ssl.SSLError)):
        urllib.request.urlopen(url, context=context, timeout=2)


def test_node_rejects_snapshot_for_another_node_before_mutation(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient, NodeControlError

    server, _, operations, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
    )
    with pytest.raises(NodeControlError, match="node_id"):
        client.apply(NodeDesiredSnapshot(node_id="nl-2", generation=1))
    assert operations.applied == []


def test_health_must_match_the_pinned_node_id(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient, NodeControlError

    server, _, _, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="wrong-node",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
    )
    with pytest.raises(NodeControlError, match="node_id"):
        client.health()


def test_health_is_read_only_and_exposes_only_safe_fields(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient

    server, _, _, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
    )
    health = client.health()
    # ``revision`` is the node's own source marker: a public commit id, and the only
    # evidence that an update actually landed. Nothing else may travel here.
    assert set(health) == {"node_id", "generation", "contract_version", "ok", "revision"}
    assert isinstance(health["revision"], str)
    assert "private_key" not in json.dumps(health)


def test_client_rejects_malformed_nodecertificate_fingerprint():
    from hydra.services.nodes.control_client import NodeControlClient

    with pytest.raises(ValueError, match="server_fingerprint"):
        NodeControlClient(
            host="node.example",
            port=9444,
            node_id="de-1",
            ca_file=Path("/ca.pem"),
            certificate=Path("/client.pem"),
            private_key=Path("/client.key"),
            server_fingerprint="not-a-fingerprint",
        )


def test_invalid_identity_cannot_start_control_server(tmp_path):
    from hydra.services.nodes.transport import create_control_server

    identity = NodeIdentity(
        node_id="de-1",
        base_url="https://127.0.0.1:8443",
        certificate="/missing/server.pem",
        private_key="/missing/server.key",
        base_ca="/missing/ca.pem",
        base_fingerprint="a" * 64,
        base_ip="127.0.0.1",
    )
    with pytest.raises((ValueError, OSError, ssl.SSLError)):
        create_control_server(identity, _Operations(), host="127.0.0.1", port=0)


def test_health_reports_the_revision_the_node_runs(secured_server):
    from hydra.services.nodes.control_client import NodeControlClient

    server, _, _, files = secured_server
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
    )

    assert client.health()["revision"] == "a" * 40


def test_a_failed_apply_reports_a_redacted_reason(secured_server):
    """ "Snapshot apply failed" alone sent the operator looking in the wrong place."""
    from hydra.services.nodes.control_client import NodeControlClient, NodeControlError

    server, _, operations, files = secured_server

    def boom(snapshot):
        del snapshot
        raise RuntimeError("Режим 3.1: S3=0 меньше 12 token=supersecret")

    operations.apply = boom
    client = NodeControlClient(
        host=server.server_address[0],
        port=server.server_address[1],
        node_id="de-1",
        ca_file=files["ca"],
        certificate=files["client_cert"],
        private_key=files["client_key"],
    )

    with pytest.raises(NodeControlError) as failure:
        client.apply(NodeDesiredSnapshot(node_id="de-1", generation=1))

    message = str(failure.value)
    assert "S3=0" in message
    assert "supersecret" not in message
