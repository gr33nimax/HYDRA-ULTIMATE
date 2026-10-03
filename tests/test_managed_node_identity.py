from __future__ import annotations

from pathlib import Path

import pytest

from hydra.core.host import HostBackend
import hydra.services.managed_nodes.identity as identity


def test_management_certificates_are_pinned_to_node_identity_and_role():
    cert, key = identity.create_certificate_pair("de-1", role="server", address="203.0.113.4")
    assert key.startswith(b"-----BEGIN PRIVATE KEY-----")
    fingerprint = identity.certificate_fingerprint(cert)
    identity.validate_certificate_identity(
        cert,
        node_id="de-1",
        role="server",
        address="203.0.113.4",
        expected_fingerprint=fingerprint,
    )
    with pytest.raises(identity.CertificateIdentityError):
        identity.validate_certificate_identity(cert, node_id="uk-2", role="server")
    with pytest.raises(identity.CertificateIdentityError):
        identity.validate_certificate_identity(cert, node_id="de-1", role="client")


def test_management_identity_writes_private_material_restricted_and_checks_source_ips(tmp_path: Path):
    base_certificate, _ = identity.create_certificate_pair("base", role="client")
    stored = identity.persist_management_identity(
        host=HostBackend(),
        root=tmp_path / "managed-node",
        node_id="de-1",
        address="203.0.113.4",
        control_port=24443,
        base_certificate=base_certificate,
        allowed_source_ips=["198.51.100.8"],
    )
    loaded = identity.load_management_identity(tmp_path / "managed-node", host=HostBackend())
    assert stored == loaded
    assert loaded.node_id == "de-1"
    assert loaded.allowed_source_ips == ("198.51.100.8",)
    assert loaded.trusted_client_fingerprint == identity.certificate_fingerprint(base_certificate)
    if __import__("os").name != "nt":
        assert loaded.private_key_path.stat().st_mode & 0o777 == 0o600


def test_management_identity_is_idempotent_but_never_implicitly_rotates(tmp_path: Path):
    host = HostBackend()
    root = tmp_path / "identity"
    base_certificate, _ = identity.create_certificate_pair("base", role="client")
    first = identity.persist_management_identity(
        host=host, root=root, node_id="de-1", address="203.0.113.4",
        control_port=24443, base_certificate=base_certificate,
        allowed_source_ips=["198.51.100.8"],
    )
    second = identity.persist_management_identity(
        host=host, root=root, node_id="de-1", address="203.0.113.4",
        control_port=24443, base_certificate=base_certificate,
        allowed_source_ips=["198.51.100.8"],
    )
    assert second == first
    with pytest.raises(ValueError, match="implicit rotation is forbidden"):
        identity.persist_management_identity(
            host=host, root=root, node_id="de-1", address="203.0.113.4",
            control_port=24444, base_certificate=base_certificate,
            allowed_source_ips=["198.51.100.8"],
        )
    assert identity.load_management_identity(root, host=host) == first


def test_management_identity_rejects_invalid_source_and_symlinked_key(tmp_path: Path, monkeypatch):
    base_certificate, _ = identity.create_certificate_pair("base", role="client")
    root = tmp_path / "identity"
    with pytest.raises(ValueError, match="source IP"):
        identity.persist_management_identity(
            host=HostBackend(), root=root, node_id="de-1", address="203.0.113.4",
            control_port=24443, base_certificate=base_certificate,
            allowed_source_ips=["not-an-ip"],
        )
    identity.persist_management_identity(
        host=HostBackend(), root=root, node_id="de-1", address="203.0.113.4",
        control_port=24443, base_certificate=base_certificate,
        allowed_source_ips=["198.51.100.8"],
    )
    key_path = root / "node.key"
    original_is_symlink = Path.is_symlink

    def report_key_symlink(path: Path) -> bool:
        return path == key_path or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", report_key_symlink)
    with pytest.raises(ValueError, match="unsafe"):
        identity.load_management_identity(root, host=HostBackend())
