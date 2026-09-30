"""Create per-node self-signed control-plane TLS credentials."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from hydra.contracts.node_validation import checked_node_id
from hydra.core.host import HostBackend

_VALIDITY_DAYS = 825
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


@dataclass(frozen=True)
class GeneratedControlCertificate:
    certificate: bytes
    private_key: bytes
    fingerprint: str


@dataclass(frozen=True)
class NodeControlCredentials:
    client_certificate: Path
    client_private_key: Path
    node_certificate: Path
    base_fingerprint: str
    node_fingerprint: str


def _server_name(address: str) -> x509.GeneralName:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        hostname = address.rstrip(".").lower()
        labels = hostname.split(".")
        if not hostname or len(hostname) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("invalid control server address") from None
        return x509.DNSName(hostname)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.scope_id is not None:
        raise ValueError("scoped IPv6 addresses cannot be used in a certificate")
    return x509.IPAddress(parsed)


def validate_control_certificate(
    certificate_pem: bytes,
    *,
    node_id: str,
    role: str,
    address: str | None = None,
) -> str:
    checked_node_id(node_id, context="node_id")
    if role not in {"server", "client"}:
        raise ValueError("role must be server or client")
    if role == "server" and not address:
        raise ValueError("server address is required")
    if role == "client" and address is not None:
        raise ValueError("client certificate must not have a server address")
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise ValueError("control certificate is invalid") from exc
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    expected_usage = ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
    now = datetime.now(timezone.utc)
    if (
        not constraints.ca
        or certificate.subject != certificate.issuer
        or len(common_names) != 1
        or common_names[0].value != node_id
        or expected_usage not in usages
        or not key_usage.digital_signature
        or not key_usage.key_cert_sign
        or certificate.not_valid_before_utc > now
        or certificate.not_valid_after_utc <= now
    ):
        raise ValueError("control certificate does not match its node role")
    if role == "server":
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if tuple(names) != (_server_name(address or ""),):
            raise ValueError("control server certificate address does not match")
    else:
        try:
            certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            pass
        else:
            raise ValueError("base client certificate must not have a server address")
    return certificate.fingerprint(hashes.SHA256()).hex()


def generate_control_certificate(
    node_id: str,
    *,
    role: str,
    address: str | None = None,
) -> GeneratedControlCertificate:
    """Generate a self-signed CA-capable leaf pinned independently per node."""
    checked_node_id(node_id, context="node_id")
    if role not in {"server", "client"}:
        raise ValueError("role must be server or client")
    if role == "server" and not address:
        raise ValueError("server address is required")
    if role == "client" and address is not None:
        raise ValueError("client certificate must not have a server address")

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = key.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=5)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=_VALIDITY_DAYS)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH],
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
    )
    if role == "server":
        builder = builder.add_extension(
            x509.SubjectAlternativeName([_server_name(address or "")]),
            critical=False,
        )
    certificate = builder.sign(key, hashes.SHA256())
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    return GeneratedControlCertificate(
        certificate=pem,
        private_key=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        fingerprint=validate_control_certificate(
            pem,
            node_id=node_id,
            role=role,
            address=address,
        ),
    )


def cleanup_node_credentials(
    *,
    host: HostBackend,
    credentials_root: Path,
    known_hosts_root: Path,
    node_id: str,
    forget_host_key: bool = False,
) -> None:
    """Delete only this node's known credential files after remote confirmation."""
    checked_node_id(node_id, context="node_id")
    for root in (credentials_root, known_hosts_root):
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("node credential roots must be absolute non-symlink paths")
    directory = credentials_root / node_id
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise RuntimeError("node credential directory is not managed")
    if directory.exists():
        for path in directory.iterdir():
            managed = path.name in {
                "base-client.crt",
                "base-client.key",
                "base-client.pending.crt",
                "base-client.pending.key",
                "base-client.active",
                "node.crt",
                ".node.crt.pending",
            } or re.fullmatch(r"base-client-[0-9a-f]{64}\\.(?:crt|key)", path.name)
            if not managed:
                continue
            if path.exists() or path.is_symlink():
                if not (path.is_file() or path.is_symlink()):
                    raise RuntimeError("managed node credential is not a file")
                host.remove_file(path)
    if forget_host_key:
        known_hosts_path = known_hosts_root / node_id / "known_hosts"
        if known_hosts_path.is_symlink():
            raise RuntimeError("pinned SSH host key is not a regular file")
        if known_hosts_path.exists():
            if not known_hosts_path.is_file():
                raise RuntimeError("pinned SSH host key is not a regular file")
            host.remove_file(known_hosts_path)


__all__ = [
    "GeneratedControlCertificate",
    "NodeControlCredentials",
    "generate_control_certificate",
    "validate_control_certificate",
]
