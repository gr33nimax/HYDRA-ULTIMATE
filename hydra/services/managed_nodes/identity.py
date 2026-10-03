"""Pinned management identities and narrowly scoped certificate storage."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from hydra.core.host import HostBackend

_IDENTITY_URI = "urn:hydra:managed-node:{node_id}:{role}"
_MAX_CERT_BYTES = 64 * 1024
_MAX_CONFIG_BYTES = 16 * 1024
_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class CertificateIdentityError(ValueError):
    """A pinned certificate does not identify the expected peer."""


@dataclass(frozen=True)
class ManagementIdentity:
    node_id: str
    address: str
    control_port: int
    certificate_path: Path
    private_key_path: Path
    trusted_client_certificate_path: Path
    trusted_client_fingerprint: str
    allowed_source_ips: tuple[str, ...]


def _certificate(data: bytes | str):
    raw = data.encode("ascii") if isinstance(data, str) else data
    if len(raw) > _MAX_CERT_BYTES:
        raise CertificateIdentityError("management certificate exceeds the size limit")
    try:
        if raw.startswith(b"-----BEGIN CERTIFICATE-----"):
            return x509.load_pem_x509_certificate(raw)
        return x509.load_der_x509_certificate(raw)
    except (ValueError, TypeError) as exc:
        raise CertificateIdentityError("management certificate is invalid") from exc


def certificate_fingerprint(data: bytes | str) -> str:
    return hashlib.sha256(_certificate(data).public_bytes(serialization.Encoding.DER)).hexdigest()


def validate_certificate_identity(
    certificate: bytes | str,
    *,
    node_id: str,
    role: str,
    address: str | None = None,
    expected_fingerprint: str | None = None,
) -> None:
    if role not in {"server", "client"} or not isinstance(node_id, str) or not node_id:
        raise CertificateIdentityError("expected management identity is invalid")
    cert = _certificate(certificate)
    now = datetime.now(timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if now < not_before or now > not_after:
        raise CertificateIdentityError("management certificate is outside its validity period")
    if expected_fingerprint is not None:
        if not isinstance(expected_fingerprint, str):
            raise CertificateIdentityError("expected certificate fingerprint is invalid")
        expected = expected_fingerprint.replace(":", "").casefold()
        if len(expected) != 64 or certificate_fingerprint(certificate) != expected:
            raise CertificateIdentityError("management certificate fingerprint does not match")
    try:
        usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        required_usage = ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
        if required_usage not in usages:
            raise CertificateIdentityError("management certificate has the wrong TLS role")
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        expected_uri = _IDENTITY_URI.format(node_id=node_id, role=role)
        if expected_uri not in names.get_values_for_type(x509.UniformResourceIdentifier):
            raise CertificateIdentityError("management certificate identity does not match")
        if address is not None:
            parsed_address = ipaddress.ip_address(address)
            if parsed_address not in names.get_values_for_type(x509.IPAddress):
                raise CertificateIdentityError("management certificate address does not match")
    except x509.ExtensionNotFound as exc:
        raise CertificateIdentityError("management certificate is missing identity extensions") from exc


def validate_key_pair(certificate: bytes, private_key: bytes) -> None:
    try:
        key = serialization.load_pem_private_key(private_key, password=None)
    except (ValueError, TypeError) as exc:
        raise CertificateIdentityError("management private key is invalid") from exc
    private_public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    certificate_public = _certificate(certificate).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if private_public != certificate_public:
        raise CertificateIdentityError("management private key does not match its certificate")


def create_certificate_pair(
    node_id: str,
    *,
    role: str,
    address: str | None = None,
    valid_days: int = 90,
) -> tuple[bytes, bytes]:
    """Create a self-signed ECDSA peer certificate and its private key."""
    if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
        raise ValueError("management certificate node_id is invalid")
    if role not in {"server", "client"}:
        raise ValueError("management certificate role must be server or client")
    if type(valid_days) is not int or not 1 <= valid_days <= 365:
        raise ValueError("management certificate lifetime must be 1..365 days")
    parsed_address = ipaddress.ip_address(address) if address is not None else None
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id[:64])])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    san_names: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(_IDENTITY_URI.format(node_id=node_id, role=role)),
    ]
    if parsed_address is not None:
        san_names.append(x509.IPAddress(parsed_address))
    usage = ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=True)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=True, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def persist_management_identity(
    *,
    host: HostBackend,
    root: Path,
    node_id: str,
    address: str,
    control_port: int,
    base_certificate: bytes,
    allowed_source_ips: list[str],
) -> ManagementIdentity:
    parsed_address = str(ipaddress.ip_address(address))
    if type(control_port) is not int or not 1024 <= control_port <= 65535 or control_port == 22:
        raise ValueError("management control port must be 1024..65535 and not SSH")
    if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
        raise ValueError("management node_id is invalid")
    if not isinstance(allowed_source_ips, list) or not allowed_source_ips:
        raise ValueError("at least one allowed source IP is required")
    try:
        sources = tuple(sorted({str(ipaddress.ip_address(value)) for value in allowed_source_ips}))
    except (TypeError, ValueError) as exc:
        raise ValueError("allowed source IP list contains an invalid source IP") from exc
    validate_certificate_identity(base_certificate, node_id="base", role="client")
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("management identity directory is unsafe")
    host.ensure_directory(root, mode=0o700)
    cert_path, key_path = root / "node.crt", root / "node.key"
    client_path, config_path = root / "base.crt", root / "identity.json"
    if any(path.exists() or path.is_symlink() for path in (cert_path, key_path, client_path, config_path)):
        try:
            existing = load_management_identity(root, host=host)
        except (OSError, ValueError, TypeError) as exc:
            raise ValueError("partial management identity requires explicit recovery") from exc
        expected_fingerprint = certificate_fingerprint(base_certificate)
        if (
            existing.node_id != node_id or existing.address != parsed_address
            or existing.control_port != control_port
            or existing.allowed_source_ips != sources
            or existing.trusted_client_fingerprint != expected_fingerprint
        ):
            raise ValueError("existing management identity differs; implicit rotation is forbidden")
        return existing
    certificate, private_key = create_certificate_pair(node_id, role="server", address=parsed_address)
    host.atomic_write(cert_path, certificate, mode=0o644, durable=True)
    host.atomic_write(key_path, private_key, mode=0o600, durable=True)
    host.atomic_write(client_path, base_certificate, mode=0o644, durable=True)
    config = {
        "version": 1, "node_id": node_id, "address": parsed_address,
        "control_port": control_port, "allowed_source_ips": list(sources),
        "trusted_client_fingerprint": certificate_fingerprint(base_certificate),
    }
    host.atomic_write(config_path, json.dumps(config, sort_keys=True), mode=0o600, durable=True)
    return ManagementIdentity(node_id, parsed_address, control_port, cert_path, key_path, client_path, config["trusted_client_fingerprint"], sources)


def load_management_identity(
    root: Path = Path("/etc/hydra/managed-node"),
    *,
    host: HostBackend,
) -> ManagementIdentity:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("management identity directory is unsafe or unavailable")
    config_path, cert_path, key_path, client_path = (root / name for name in ("identity.json", "node.crt", "node.key", "base.crt"))
    paths = ((config_path, _MAX_CONFIG_BYTES), (cert_path, _MAX_CERT_BYTES), (key_path, _MAX_CERT_BYTES), (client_path, _MAX_CERT_BYTES))
    for path, _ in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("management identity file is unsafe or unavailable")
    config_raw, cert, private_key, trusted = (
        host.read_bytes(path, max_bytes=limit) for path, limit in paths
    )
    config = json.loads(config_raw.decode("utf-8"))
    expected_keys = {"version", "node_id", "address", "control_port", "allowed_source_ips", "trusted_client_fingerprint"}
    if not isinstance(config, dict) or set(config) != expected_keys or type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("management identity configuration is invalid")
    if os.name != "nt" and key_path.stat().st_mode & 0o077:
        raise ValueError("management private key permissions are unsafe")
    node_id = config["node_id"]
    if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
        raise ValueError("management identity node_id is invalid")
    address = str(ipaddress.ip_address(config["address"]))
    if type(config["control_port"]) is not int or not 1024 <= config["control_port"] <= 65535 or config["control_port"] == 22:
        raise ValueError("management identity control port is invalid")
    allowed = config["allowed_source_ips"]
    if not isinstance(allowed, list) or not allowed:
        raise ValueError("management identity source list is invalid")
    sources = tuple(sorted({str(ipaddress.ip_address(value)) for value in allowed}))
    fingerprint = config["trusted_client_fingerprint"]
    validate_certificate_identity(cert, node_id=node_id, role="server", address=address)
    validate_key_pair(cert, private_key)
    validate_certificate_identity(trusted, node_id="base", role="client", expected_fingerprint=fingerprint)
    return ManagementIdentity(node_id, address, config["control_port"], cert_path, key_path, client_path, fingerprint, sources)


__all__ = [
    "CertificateIdentityError", "ManagementIdentity", "certificate_fingerprint",
    "create_certificate_pair", "load_management_identity", "persist_management_identity",
    "validate_certificate_identity", "validate_key_pair",
]
