"""Loopback mTLS material for node control tests.

Shared by the transport security tests and the end-to-end node path: both need a private
CA with one server and two client certificates, and neither may depend on the other's
module.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_certificates(directory: Path) -> dict[str, Path]:
    """Create a private CA and one server/client leaf pair for loopback tests."""
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hydra node test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    paths = {"ca": directory / "ca.pem"}
    paths["ca"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    for role, usage in (
        ("server", ExtendedKeyUsageOID.SERVER_AUTH),
        ("client", ExtendedKeyUsageOID.CLIENT_AUTH),
        ("other_client", ExtendedKeyUsageOID.CLIENT_AUTH),
    ):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"hydra-{role}")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        paths[f"{role}_cert"] = directory / f"{role}.pem"
        paths[f"{role}_key"] = directory / f"{role}.key"
        paths[f"{role}_cert"].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        paths[f"{role}_key"].write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
    return paths


def certificate_fingerprint(path: Path) -> str:
    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    return certificate.fingerprint(hashes.SHA256()).hex()


__all__ = ["certificate_fingerprint", "write_certificates"]
