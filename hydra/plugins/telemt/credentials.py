"""Deterministic Telemt user credentials."""
import hashlib

from hydra.utils.crypto import derive_key


def derive_username(uuid: str) -> str:
    return "u" + derive_key("telemt-user", uuid)[:8]


def derive_secret(uuid: str) -> str:
    return hashlib.sha256(f"telemt-secret|{uuid}".encode()).hexdigest()[:32]


def make_tls_secret(base_secret: str, domain: str) -> str:
    return f"ee{base_secret}{domain.encode().hex()}"
