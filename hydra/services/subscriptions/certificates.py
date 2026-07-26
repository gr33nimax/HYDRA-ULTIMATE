"""TLS certificate discovery for the standalone subscription server."""
from __future__ import annotations

from pathlib import Path

from hydra.core.state_models import AppState


def _certificate_pair(domain: str) -> tuple[tuple[str, str], ...]:
    return (
        (
            f"/etc/letsencrypt/live/{domain}/fullchain.pem",
            f"/etc/letsencrypt/live/{domain}/privkey.pem",
        ),
    )


def _first_existing(
    candidates: tuple[tuple[str, str], ...],
) -> tuple[str | None, str | None]:
    for certificate, key in candidates:
        if Path(certificate).exists() and Path(key).exists():
            return certificate, key
    return None, None


def find_any_cert(state: AppState) -> tuple[str | None, str | None]:
    """Find a TLS certificate matching the subscription endpoint."""
    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        return _first_existing(_certificate_pair(sub_domain))

    domains: list[str] = []
    if state.network.domain:
        domains.append(state.network.domain)
    for protocol_state in state.protocols.values():
        domain = (protocol_state.config or {}).get("domain")
        if domain and domain not in domains:
            domains.append(domain)

    for domain in domains:
        result = _first_existing(_certificate_pair(domain))
        if result[0]:
            return result

    return None, None
