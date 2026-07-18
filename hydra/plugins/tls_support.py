"""Shared TLS certificate helpers for domain-based transport plugins."""
from __future__ import annotations

from pathlib import Path

from hydra.core.state import AppState, get_protocol


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
        (f"/etc/xray/{domain}.crt", f"/etc/xray/{domain}.key"),
        ("/etc/xray/xray.crt", "/etc/xray/xray.key"),
    )
    for cert_path, key_path in candidates:
        if Path(cert_path).exists() and Path(key_path).exists():
            return cert_path, key_path
    return "", ""


def ensure_tls_material(state: AppState, protocol: str) -> tuple[str, str, str]:
    """Prompt for a domain and obtain or request its TLS certificate paths."""
    from hydra.ui.tui import prompt

    ps = get_protocol(state, protocol)
    domain = str(ps.config.get("domain", "")).strip().lower().rstrip(".")
    if not domain:
        domain = prompt(
            f"Домен для {protocol}", default=state.network.domain or "",
        ).strip().lower().rstrip(".")
    if not domain or "://" in domain or any(ch.isspace() for ch in domain):
        raise ValueError(f"Корректный домен обязателен для {protocol}")

    cert, key = resolve_tls_material(domain, ps.config)
    if not cert or not key:
        # Reuse the established certbot workflow already used by AnyTLS.
        from hydra.plugins.anytls.plugin import AnyTLSPlugin

        helper = AnyTLSPlugin()
        if helper._obtain_cert_certbot(domain):
            cert, key = resolve_tls_material(domain, ps.config)
    if not cert or not key:
        cert = prompt("Путь к сертификату (fullchain.pem)", default="").strip()
        key = prompt("Путь к приватному ключу (privkey.pem)", default="").strip()
    if not cert or not key:
        raise ValueError(f"TLS-сертификат для {domain} не найден")

    ps.config.update({"domain": domain, "cert_file": cert, "key_file": key})
    return domain, cert, key
