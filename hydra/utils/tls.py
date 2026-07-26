"""Pure TLS material lookup shared by plugins and certificate services."""
from __future__ import annotations

from pathlib import Path


def resolve_tls_material(domain: str, config: dict) -> tuple[str, str]:
    cert = str(config.get("cert_file", "")).strip()
    key = str(config.get("key_file", "")).strip()
    if cert and key:
        return cert, key
    candidates = (
        (
            f"/etc/letsencrypt/live/{domain}/fullchain.pem",
            f"/etc/letsencrypt/live/{domain}/privkey.pem",
        ),
    )
    return next(
        (
            (cert_path, key_path)
            for cert_path, key_path in candidates
            if Path(cert_path).exists() and Path(key_path).exists()
        ),
        ("", ""),
    )


__all__ = ["resolve_tls_material"]
