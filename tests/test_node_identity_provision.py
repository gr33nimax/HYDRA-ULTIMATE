import json
import os
from pathlib import Path
from subprocess import CompletedProcess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from hydra.core.host import HostBackend
from hydra.core.node_identity import load_node_identity
from hydra.services.nodes.credentials import generate_control_certificate
from hydra.services.nodes.provision import (
    provision_node_identity,
    revoke_node_control_identity,
    rotate_node_control_identity,
)


def _provision(
    host, base_certificate, node_directory, *, base_ip="203.0.113.2", base_url="https://base.example.com:9444"
):
    return provision_node_identity(
        node_id="de-1",
        base_url=base_url,
        base_ip=base_ip,
        control_address="node.example.com",
        control_port=9444,
        base_certificate=base_certificate,
        host=host,
        node_directory=node_directory,
    )


def test_provision_writes_local_server_key_and_base_trust_atomically(tmp_path, monkeypatch):
    base = generate_control_certificate("de-1", role="client")
    node_directory = tmp_path / "node"
    host = HostBackend()
    written_modes = {}
    directory_modes = []
    original_write = host.atomic_write
    original_ensure = host.ensure_directory

    def record_write(path, content, *, mode=0o644):
        written_modes[path.name] = mode
        original_write(path, content, mode=mode)

    def record_directory(path, *, mode=0o755):
        directory_modes.append((path, mode))
        original_ensure(path, mode=mode)

    monkeypatch.setattr(host, "atomic_write", record_write)
    monkeypatch.setattr(host, "ensure_directory", record_directory)
    identity = _provision(host, base.certificate, node_directory)

    assert identity.base_ip == "203.0.113.2"
    assert identity.base_fingerprint == base.fingerprint
    assert identity.certificate == str(node_directory / "node.crt")
    assert identity.private_key == str(node_directory / "node.key")
    assert identity.base_ca == str(node_directory / "base-ca.crt")
    assert directory_modes == [(node_directory, 0o700)]
    assert written_modes == {
        "node.crt": 0o644,
        "node.key": 0o600,
        "base-ca.crt": 0o644,
        "identity.json": 0o600,
    }
    if os.name != "nt":
        assert (node_directory.stat().st_mode & 0o777) == 0o700
        assert ((node_directory / "node.key").stat().st_mode & 0o777) == 0o600
        assert ((node_directory / "identity.json").stat().st_mode & 0o777) == 0o600
    assert (node_directory / "base-ca.crt").read_bytes() == base.certificate
    assert base.private_key not in (node_directory / "node.key").read_bytes()
    assert load_node_identity(node_directory / "identity.json") == identity

    server_certificate = x509.load_pem_x509_certificate((node_directory / "node.crt").read_bytes())
    server_key = serialization.load_pem_private_key((node_directory / "node.key").read_bytes(), password=None)
    assert server_certificate.fingerprint(hashes.SHA256()).hex()
    assert server_certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == server_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_provision_is_idempotent_but_refuses_a_different_base(tmp_path):
    host = HostBackend()
    base = generate_control_certificate("de-1", role="client")
    node_directory = tmp_path / "node"

    first = _provision(host, base.certificate, node_directory)
    original_key = (node_directory / "node.key").read_bytes()
    second = _provision(host, base.certificate, node_directory)

    assert second == first
    assert (node_directory / "node.key").read_bytes() == original_key
    with pytest.raises(ValueError, match="already provisioned"):
        _provision(host, base.certificate, node_directory, base_ip="203.0.113.9")
    assert load_node_identity(node_directory / "identity.json") == first


def test_provision_rolls_back_partial_files_after_identity_write_failure(tmp_path, monkeypatch):
    host = HostBackend()
    base = generate_control_certificate("de-1", role="client")
    node_directory = tmp_path / "node"
    original_write = host.atomic_write

    def fail_after_identity(path: Path, content: str | bytes, *, mode: int = 0o644):
        original_write(path, content, mode=mode)
        if path.name == "identity.json":
            raise OSError("simulated write failure")

    monkeypatch.setattr(host, "atomic_write", fail_after_identity)
    with pytest.raises(OSError, match="simulated write failure"):
        _provision(host, base.certificate, node_directory)

    assert not any(node_directory.iterdir())
    assert not (node_directory / "identity.json").exists()


def test_rotation_rekeys_both_mtls_peers_without_exporting_node_private_key(tmp_path, monkeypatch):
    host = HostBackend()
    systemd_calls = []
    monkeypatch.setattr(
        host,
        "systemd",
        lambda action, unit: systemd_calls.append((action, unit)) or CompletedProcess([], 0),
    )
    node_directory = tmp_path / "node"
    first_base = generate_control_certificate("de-1", role="client")
    next_base = generate_control_certificate("de-1", role="client")
    original = _provision(host, first_base.certificate, node_directory)
    server_certificate = (node_directory / "node.crt").read_bytes()
    server_key = (node_directory / "node.key").read_bytes()

    rotated = rotate_node_control_identity(
        node_id="de-1",
        base_url="https://new-base.example.com:9444",
        base_ip="203.0.113.9",
        control_address="node.example.com",
        control_port=9444,
        base_certificate=next_base.certificate,
        host=host,
        node_directory=node_directory,
    )

    assert rotated.base_fingerprint == next_base.fingerprint
    assert rotated.base_ip == "203.0.113.9"
    assert rotated.base_url == "https://new-base.example.com:9444"
    assert (node_directory / "base-ca.crt").read_bytes() == next_base.certificate
    new_server_certificate = (node_directory / "node.crt").read_bytes()
    new_server_key = (node_directory / "node.key").read_bytes()
    assert new_server_certificate != server_certificate
    assert new_server_key != server_key
    assert rotated.certificate == original.certificate
    parsed_certificate = x509.load_pem_x509_certificate(new_server_certificate)
    parsed_key = serialization.load_pem_private_key(new_server_key, password=None)
    assert parsed_certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == parsed_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert systemd_calls == [
        ("stop", "hydra-node-control.service"),
        ("enable", "hydra-node-control.service"),
        ("start", "hydra-node-control.service"),
    ]


def test_rotation_rolls_back_trust_when_new_control_service_fails_to_start(tmp_path, monkeypatch):
    host = HostBackend()
    node_directory = tmp_path / "node"
    old_base = generate_control_certificate("de-1", role="client")
    next_base = generate_control_certificate("de-1", role="client")
    original = _provision(host, old_base.certificate, node_directory)
    systemd_results = iter((0, 0, 1, 0))
    monkeypatch.setattr(
        host,
        "systemd",
        lambda action, unit: CompletedProcess([], next(systemd_results)),
    )

    with pytest.raises(RuntimeError, match="could not start rotated node control service"):
        rotate_node_control_identity(
            node_id="de-1",
            base_url="https://base.example.com:9444",
            base_ip="203.0.113.2",
            control_address="node.example.com",
            control_port=9444,
            base_certificate=next_base.certificate,
            host=host,
            node_directory=node_directory,
        )

    assert load_node_identity(node_directory / "identity.json") == original
    assert (node_directory / "base-ca.crt").read_bytes() == old_base.certificate


def test_revoke_disables_control_and_keeps_node_identity_for_read_only_role(
    tmp_path,
    monkeypatch,
):
    import hydra.services.nodes.provision as provision

    host = HostBackend()
    node_directory = tmp_path / "node"
    base = generate_control_certificate("de-1", role="client")
    identity = _provision(host, base.certificate, node_directory)
    systemd_calls = []
    firewall_calls = []
    monkeypatch.setattr(
        host,
        "systemd",
        lambda action, unit: systemd_calls.append((action, unit)) or CompletedProcess([], 0),
    )
    monkeypatch.setattr(provision, "remove_control_firewall", lambda *, host: firewall_calls.append(host))

    revoke_node_control_identity(node_id="de-1", host=host, node_directory=node_directory)

    assert load_node_identity(node_directory / "identity.json") == identity
    assert not (node_directory / "node.key").exists()
    assert not (node_directory / "node.crt").exists()
    assert not (node_directory / "base-ca.crt").exists()
    assert systemd_calls == [
        ("stop", "hydra-node-control.service"),
        ("disable", "hydra-node-control.service"),
    ]
    assert firewall_calls == [host]


def test_revoked_node_can_be_reprovisioned_with_fresh_mtls_keys(tmp_path, monkeypatch):
    import hydra.services.nodes.provision as provision

    host = HostBackend()
    node_directory = tmp_path / "node"
    old_base = generate_control_certificate("de-1", role="client")
    new_base = generate_control_certificate("de-1", role="client")
    original = _provision(host, old_base.certificate, node_directory)
    old_node_key = (node_directory / "node.key").read_bytes()
    systemd_calls = []
    monkeypatch.setattr(
        host,
        "systemd",
        lambda action, unit: systemd_calls.append(action) or CompletedProcess([], 0),
    )
    monkeypatch.setattr(provision, "remove_control_firewall", lambda *, host: None)

    revoke_node_control_identity(node_id="de-1", host=host, node_directory=node_directory)
    rotated = rotate_node_control_identity(
        node_id="de-1",
        base_url=original.base_url,
        base_ip=original.base_ip,
        control_address="node.example.com",
        control_port=9444,
        base_certificate=new_base.certificate,
        host=host,
        node_directory=node_directory,
    )

    assert rotated.base_fingerprint == new_base.fingerprint
    assert (node_directory / "node.key").read_bytes() != old_node_key
    assert (node_directory / "base-ca.crt").read_bytes() == new_base.certificate
    assert systemd_calls == ["stop", "disable", "stop", "enable", "start"]


def test_revoke_rejects_identity_paths_outside_the_node_directory(tmp_path, monkeypatch):
    host = HostBackend()
    node_directory = tmp_path / "node"
    base = generate_control_certificate("de-1", role="client")
    identity = _provision(host, base.certificate, node_directory)
    outside = tmp_path / "do-not-delete.pem"
    outside.write_bytes(base.certificate)
    document = json.loads((node_directory / "identity.json").read_text())
    document["base_ca"] = str(outside)
    (node_directory / "identity.json").write_text(json.dumps(document))
    monkeypatch.setattr(host, "systemd", lambda action, unit: CompletedProcess([], 0))

    with pytest.raises(ValueError, match="unsupported credential paths"):
        revoke_node_control_identity(node_id=identity.node_id, host=host, node_directory=node_directory)

    assert outside.read_bytes() == base.certificate
