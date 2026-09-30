from datetime import timezone
from pathlib import Path
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID

from hydra.contracts.node_export import NodeClientExport
from hydra.contracts.node_snapshot import NodeDesiredSnapshot
from hydra.core.node_identity import NodeIdentity
from hydra.services.nodes.credentials import generate_control_certificate


def test_generated_certificates_are_role_scoped_and_key_matched():
    server = generate_control_certificate("de-1", role="server", address="127.0.0.1")
    client = generate_control_certificate("de-1", role="client")

    for generated, expected_usage in (
        (server, ExtendedKeyUsageOID.SERVER_AUTH),
        (client, ExtendedKeyUsageOID.CLIENT_AUTH),
    ):
        certificate = x509.load_pem_x509_certificate(generated.certificate)
        private_key = serialization.load_pem_private_key(generated.private_key, password=None)
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert constraints.ca is True
        assert expected_usage in usages
        assert certificate.fingerprint(hashes.SHA256()).hex() == generated.fingerprint
        assert certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) == (
            private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )
        assert certificate.not_valid_after_utc.tzinfo == timezone.utc

    assert server.fingerprint != client.fingerprint
    assert (
        x509.load_pem_x509_certificate(server.certificate)
        .extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        )
        .value.get_values_for_type(x509.IPAddress)
    )


def test_self_signed_per_node_certificates_complete_pinned_mtls_handshake(tmp_path: Path):
    from hydra.services.nodes.control_client import NodeControlClient
    from hydra.services.nodes.transport import create_control_server

    server_material = generate_control_certificate("de-1", role="server", address="127.0.0.1")
    client_material = generate_control_certificate("de-1", role="client")
    server_cert = tmp_path / "node.crt"
    server_key = tmp_path / "node.key"
    client_cert = tmp_path / "base.crt"
    client_key = tmp_path / "base.key"
    for path, content in (
        (server_cert, server_material.certificate),
        (server_key, server_material.private_key),
        (client_cert, client_material.certificate),
        (client_key, client_material.private_key),
    ):
        path.write_bytes(content)

    class Operations:
        node_id = "de-1"

        def current_generation(self) -> int:
            return 0

        def apply(self, snapshot: NodeDesiredSnapshot) -> object:
            return None

        def export(self) -> NodeClientExport:
            return NodeClientExport(node_id=self.node_id, generation=0)

        def diagnostics(self) -> dict[str, object]:
            return {"last_error": ""}

    identity = NodeIdentity(
        node_id="de-1",
        base_url="https://base.example.com:9444",
        base_ip="127.0.0.1",
        certificate=str(server_cert),
        private_key=str(server_key),
        base_ca=str(client_cert),
        base_fingerprint=client_material.fingerprint,
    )
    server = create_control_server(identity, Operations(), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        assert isinstance(host, str)
        assert isinstance(port, int)
        client = NodeControlClient(
            host=host,
            port=port,
            node_id="de-1",
            ca_file=server_cert,
            certificate=client_cert,
            private_key=client_key,
            server_fingerprint=server_material.fingerprint,
        )
        assert client.health()["node_id"] == "de-1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_certificate_generation_rejects_missing_or_invalid_server_address():
    with pytest.raises(ValueError, match="server address"):
        generate_control_certificate("de-1", role="server")
    with pytest.raises(ValueError, match="role"):
        generate_control_certificate("de-1", role="admin")
