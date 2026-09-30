"""Provision one node's pinned control-plane identity without exporting keys."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from hydra.core.host import HostBackend
from cryptography import x509

from hydra.core.node_identity import NODE_ETC_DIR, NodeIdentity, load_node_identity
from hydra.services.nodes.firewall import remove_control_firewall

_NODE_CONTROL_UNIT = "hydra-node-control.service"
from hydra.services.nodes.credentials import (
    generate_control_certificate,
    validate_control_certificate,
)


def _base_fingerprint(pem: bytes, node_id: str) -> str:
    return validate_control_certificate(pem, node_id=node_id, role="client")


def _same_identity(actual: NodeIdentity, expected: NodeIdentity) -> bool:
    return (
        actual.node_id == expected.node_id
        and actual.base_url == expected.base_url
        and actual.base_ip == expected.base_ip
        and actual.control_port == expected.control_port
        and actual.certificate == expected.certificate
        and actual.private_key == expected.private_key
        and actual.base_ca == expected.base_ca
        and actual.base_fingerprint == expected.base_fingerprint
    )


def _check_managed_paths(identity: NodeIdentity, node_directory: Path) -> None:
    expected = (
        node_directory / "node.crt",
        node_directory / "node.key",
        node_directory / "base-ca.crt",
    )
    actual = tuple(Path(path) for path in (identity.certificate, identity.private_key, identity.base_ca))
    if actual != expected or any(path.is_symlink() for path in (*expected, node_directory / "identity.json")):
        raise ValueError("node identity contains unsupported credential paths")


def _verify_node_material(identity: NodeIdentity, control_address: str) -> str:
    certificate_pem = Path(identity.certificate).read_bytes()
    node_fingerprint = validate_control_certificate(
        certificate_pem,
        node_id=identity.node_id,
        role="server",
        address=control_address,
    )
    key = serialization.load_pem_private_key(Path(identity.private_key).read_bytes(), password=None)
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    if certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        raise ValueError("stored node certificate and private key do not match")
    return node_fingerprint


def _verify_existing_material(
    identity: NodeIdentity,
    base_fingerprint: str,
    control_address: str,
) -> None:
    node_fingerprint = _verify_node_material(identity, control_address)
    trust_pem = Path(identity.base_ca).read_bytes()
    trust_fingerprint = validate_control_certificate(
        trust_pem,
        node_id=identity.node_id,
        role="client",
    )
    if node_fingerprint == base_fingerprint:
        raise ValueError("node and base control certificates must be distinct")
    if trust_fingerprint != base_fingerprint:
        raise ValueError("stored base trust certificate does not match the identity")


def provision_node_identity(
    *,
    node_id: str,
    base_url: str,
    base_ip: str,
    control_address: str,
    control_port: int,
    base_certificate: bytes,
    host: HostBackend,
    node_directory: Path = NODE_ETC_DIR,
) -> NodeIdentity:
    """Create the node's private server key and install its base trust pin."""
    if not node_directory.is_absolute():
        raise ValueError("node credential directory must be absolute")
    base_ip = str(ipaddress.ip_address(base_ip))
    base_fingerprint = _base_fingerprint(base_certificate, node_id)
    certificate_path = node_directory / "node.crt"
    private_key_path = node_directory / "node.key"
    base_ca_path = node_directory / "base-ca.crt"
    identity_path = node_directory / "identity.json"
    identity = NodeIdentity(
        node_id=node_id,
        base_url=base_url,
        base_ip=base_ip,
        control_port=control_port,
        certificate=str(certificate_path),
        private_key=str(private_key_path),
        base_ca=str(base_ca_path),
        base_fingerprint=base_fingerprint,
    )
    identity.validate()

    if identity_path.exists():
        if identity_path.is_symlink():
            raise ValueError("node identity must not be a symlink")
        existing = load_node_identity(identity_path)
        if existing is None:
            raise ValueError("node identity is missing")
        _check_managed_paths(existing, node_directory)
        if not _same_identity(existing, identity):
            raise ValueError("node is already provisioned for a different base identity")
        _verify_existing_material(existing, base_fingerprint, control_address)
        return existing

    managed_paths = (certificate_path, private_key_path, base_ca_path)
    if any(path.exists() for path in managed_paths):
        raise FileExistsError("partial node control credentials exist")

    generated = generate_control_certificate(node_id, role="server", address=control_address)
    document = json.dumps(asdict(identity), sort_keys=True, separators=(",", ":")) + "\n"
    writes = (
        (certificate_path, generated.certificate, 0o644),
        (private_key_path, generated.private_key, 0o600),
        (base_ca_path, base_certificate, 0o644),
        (identity_path, document, 0o600),
    )
    created: list[Path] = []
    host.ensure_directory(node_directory, mode=0o700)
    try:
        for path, content, mode in writes:
            created.append(path)
            host.atomic_write(path, content, mode=mode)
    except Exception as exc:
        cleanup_errors = []
        for path in reversed(created):
            try:
                host.remove_file(path)
            except Exception as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            raise RuntimeError("could not roll back partial node control credentials") from exc
        raise
    return identity


def _systemd(host: HostBackend, action: str) -> None:
    result = host.systemd(action, _NODE_CONTROL_UNIT)
    if result.returncode != 0:
        raise RuntimeError(f"systemd {action} failed")


def _restore_rotation(
    *,
    host: HostBackend,
    certificate_path: Path,
    private_key_path: Path,
    base_ca_path: Path,
    identity_path: Path,
    old_certificate: bytes | None,
    old_private_key: bytes | None,
    old_base_certificate: bytes | None,
    old_identity: bytes,
) -> None:
    if old_certificate is None:
        host.remove_file(certificate_path)
    else:
        host.atomic_write(certificate_path, old_certificate, mode=0o644)
    if old_private_key is None:
        host.remove_file(private_key_path)
    else:
        host.atomic_write(private_key_path, old_private_key, mode=0o600)
    if old_base_certificate is None:
        host.remove_file(base_ca_path)
    else:
        host.atomic_write(base_ca_path, old_base_certificate, mode=0o644)
    host.atomic_write(identity_path, old_identity, mode=0o600)
    if old_base_certificate is None:
        _systemd(host, "disable")
        _systemd(host, "stop")
    else:
        _systemd(host, "start")


def rotate_node_control_identity(
    *,
    node_id: str,
    base_url: str,
    base_ip: str,
    control_address: str,
    control_port: int,
    base_certificate: bytes,
    host: HostBackend,
    node_directory: Path = NODE_ETC_DIR,
) -> NodeIdentity:
    """Replace the trusted base client identity without moving node keys."""
    if not node_directory.is_absolute():
        raise ValueError("node credential directory must be absolute")
    base_ip = str(ipaddress.ip_address(base_ip))
    base_fingerprint = _base_fingerprint(base_certificate, node_id)
    identity_path = node_directory / "identity.json"
    base_ca_path = node_directory / "base-ca.crt"
    existing = load_node_identity(identity_path)
    if existing is None or existing.node_id != node_id:
        raise ValueError("node identity does not match the rotation request")
    _check_managed_paths(existing, node_directory)
    certificate_path = Path(existing.certificate)
    private_key_path = Path(existing.private_key)
    old_base_certificate = base_ca_path.read_bytes() if base_ca_path.exists() else None
    certificate_exists, key_exists = certificate_path.exists(), private_key_path.exists()
    if certificate_exists != key_exists or (old_base_certificate is not None and not certificate_exists):
        raise ValueError("node control credentials are incomplete")
    if certificate_exists:
        node_fingerprint = _verify_node_material(existing, control_address)
        old_certificate, old_private_key = certificate_path.read_bytes(), private_key_path.read_bytes()
        if old_base_certificate is not None:
            _verify_existing_material(existing, existing.base_fingerprint, control_address)
    else:
        node_fingerprint = ""
        old_certificate = old_private_key = None
    if node_fingerprint and node_fingerprint == base_fingerprint:
        raise ValueError("node and base control certificates must be distinct")
    rotated = NodeIdentity(
        node_id=node_id,
        base_url=base_url,
        base_ip=base_ip,
        control_port=control_port,
        certificate=existing.certificate,
        private_key=existing.private_key,
        base_ca=existing.base_ca,
        base_fingerprint=base_fingerprint,
    )
    rotated.validate()
    old_identity = identity_path.read_bytes()
    if old_base_certificate is not None and _same_identity(existing, rotated):
        _systemd(host, "enable")
        _systemd(host, "start")
        return existing

    generated_node = generate_control_certificate(node_id, role="server", address=control_address)
    if generated_node.fingerprint == base_fingerprint:
        raise ValueError("node and base control certificates must be distinct")
    _systemd(host, "stop")
    try:
        document = json.dumps(asdict(rotated), sort_keys=True, separators=(",", ":")) + "\n"
        host.atomic_write(certificate_path, generated_node.certificate, mode=0o644)
        host.atomic_write(private_key_path, generated_node.private_key, mode=0o600)
        host.atomic_write(base_ca_path, base_certificate, mode=0o644)
        host.atomic_write(identity_path, document, mode=0o600)
        _systemd(host, "enable")
        _systemd(host, "start")
    except Exception as exc:
        try:
            _restore_rotation(
                host=host,
                certificate_path=certificate_path,
                private_key_path=private_key_path,
                base_ca_path=base_ca_path,
                identity_path=identity_path,
                old_certificate=old_certificate,
                old_private_key=old_private_key,
                old_base_certificate=old_base_certificate,
                old_identity=old_identity,
            )
        except Exception as rollback_error:
            raise RuntimeError("could not roll back node control identity rotation") from rollback_error
        if isinstance(exc, RuntimeError) and str(exc) == "systemd start failed":
            raise RuntimeError("could not start rotated node control service") from exc
        raise RuntimeError("could not rotate node control identity") from exc
    return rotated


def revoke_node_control_identity(
    *,
    node_id: str,
    host: HostBackend,
    node_directory: Path = NODE_ETC_DIR,
) -> None:
    """Disable control access while retaining node role and applied runtime state."""
    if not node_directory.is_absolute():
        raise ValueError("node credential directory must be absolute")
    identity_path = node_directory / "identity.json"
    if identity_path.is_symlink():
        raise ValueError("node identity must not be a symlink")
    identity = load_node_identity(identity_path)
    if identity is None or identity.node_id != node_id:
        raise ValueError("node identity does not match the revocation request")
    _check_managed_paths(identity, node_directory)
    _systemd(host, "stop")
    _systemd(host, "disable")
    host.remove_file(Path(identity.base_ca))
    host.remove_file(Path(identity.private_key))
    host.remove_file(Path(identity.certificate))
    remove_control_firewall(host=host)


__all__ = [
    "provision_node_identity",
    "revoke_node_control_identity",
    "rotate_node_control_identity",
]
