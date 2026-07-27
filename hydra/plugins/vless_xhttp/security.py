"""TLS security modes of the VLESS transport.

Two modes serve the same XHTTP transport but own the TLS handshake differently:

``tls``
    Caddy terminates a real certificate for the operator's domain and forwards
    the configured path into Sing-Box. Requires a domain, a certificate and a
    decoy site for every other URL.

``reality``
    Sing-Box performs the handshake itself, borrowing the certificate of a
    third-party site. No domain, no certificate and no decoy — the borrowed
    site is the cover story.
"""
from __future__ import annotations

import re
from collections.abc import Mapping


MODE_TLS = "tls"
MODE_REALITY = "reality"
MODES = (MODE_TLS, MODE_REALITY)

DECOY_ROUTE_KEY = "_tls_http_decoy_route"
PASSTHROUGH_ROUTE_KEY = "_tls_passthrough_route"
PASSTHROUGH_ROUTE_KIND = "tls_passthrough"
HANDSHAKE_CONFIG_KEY = "reality_handshake"

DEFAULT_HANDSHAKE = "www.samsung.com"
DEFAULT_REALITY_FINGERPRINT = "chrome"

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SHORT_ID = re.compile(r"[0-9a-f]{2,16}")


def normalize_domain(value: object) -> str:
    """Return a syntactically valid host name in lower case."""
    domain = str(value or "").strip().lower().rstrip(".")
    labels = domain.split(".")
    if (
        not domain
        or len(domain) > 253
        or "://" in domain
        or any(character.isspace() for character in domain)
        or len(labels) < 2
        or any(not _LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("VLESS XHTTP domain is invalid")
    return domain


def validate_security(value: object) -> str:
    """Return a supported security mode."""
    mode = str(value or "").strip().lower()
    if mode not in MODES:
        allowed = ", ".join(MODES)
        raise ValueError(f"VLESS security must be one of: {allowed}")
    return mode


def validate_handshake(value: object) -> str:
    """Return the third-party host whose handshake Reality borrows."""
    try:
        return normalize_domain(value)
    except ValueError:
        raise ValueError(
            "Reality handshake must be a real TLS 1.3 host name, "
            "for example www.samsung.com",
        ) from None


def validate_short_id(value: object) -> str:
    """Return a Reality short id: an even-length hex string up to 16 chars."""
    short_id = str(value or "").strip().lower()
    if not _SHORT_ID.fullmatch(short_id) or len(short_id) % 2:
        raise ValueError(
            "Reality short_id must be 2 to 16 hexadecimal characters",
        )
    return short_id


def security_mode(config: Mapping[str, object]) -> str:
    """Return the configured security mode, defaulting to certificate TLS."""
    return validate_security(config.get("security", MODE_TLS))


def is_reality(config: Mapping[str, object]) -> bool:
    """Report whether the endpoint performs a borrowed handshake."""
    return security_mode(config) == MODE_REALITY


def handshake_target(config: Mapping[str, object]) -> str:
    """Return the borrowed handshake host."""
    return validate_handshake(
        config.get(HANDSHAKE_CONFIG_KEY, DEFAULT_HANDSHAKE),
    )


def passthrough_route(internal_port: int) -> dict[str, object]:
    """Return the declarative Caddy route metadata for Reality."""
    return {
        "kind": PASSTHROUGH_ROUTE_KIND,
        "internal_port": int(internal_port),
        "sni_config": HANDSHAKE_CONFIG_KEY,
    }


def apply_tls_mode(
    config: dict[str, object],
    *,
    domain: object,
    decoy_route: dict[str, object],
) -> None:
    """Switch the endpoint to a certificate served through Caddy."""
    normalized = normalize_domain(domain)
    if normalized != config.get("domain"):
        config.pop("cert_file", None)
        config.pop("key_file", None)
    config["domain"] = normalized
    config["security"] = MODE_TLS
    config.pop(PASSTHROUGH_ROUTE_KEY, None)
    config[DECOY_ROUTE_KEY] = dict(decoy_route)


def apply_reality_mode(
    config: dict[str, object],
    *,
    handshake: str,
    private_key: str,
    public_key: str,
    short_id: str,
    internal_port: int,
) -> None:
    """Switch the endpoint to a borrowed handshake without a certificate."""
    config["security"] = MODE_REALITY
    config[HANDSHAKE_CONFIG_KEY] = validate_handshake(handshake)
    config["reality_private_key"] = str(private_key)
    config["reality_public_key"] = str(public_key)
    config["reality_short_id"] = validate_short_id(short_id)
    config[PASSTHROUGH_ROUTE_KEY] = passthrough_route(internal_port)
    # Keep an explicit tombstone so generic config-default normalization does
    # not resurrect the mutually exclusive certificate/decoy route.
    config[DECOY_ROUTE_KEY] = None
    # A borrowed handshake owns no domain and no certificate of its own.
    for key in ("domain", "cert_file", "key_file"):
        config.pop(key, None)


def server_tls(config: Mapping[str, object]) -> dict[str, object]:
    """Return the inbound TLS block for the Reality handshake."""
    handshake = handshake_target(config)
    private_key = str(config.get("reality_private_key", "")).strip()
    short_id = validate_short_id(config.get("reality_short_id", ""))
    if not private_key:
        raise ValueError("Reality private key is missing")
    return {
        "enabled": True,
        "server_name": handshake,
        "reality": {
            "enabled": True,
            "handshake": {"server": handshake, "server_port": 443},
            "private_key": private_key,
            "short_id": [short_id],
        },
    }


def client_tls(
    config: Mapping[str, object],
    *,
    fingerprint: str,
) -> dict[str, object]:
    """Return the outbound TLS block a Reality client needs."""
    public_key = str(config.get("reality_public_key", "")).strip()
    if not public_key:
        raise ValueError("Reality public key is missing")
    return {
        "enabled": True,
        "server_name": handshake_target(config),
        "utls": {
            "enabled": True,
            "fingerprint": fingerprint or DEFAULT_REALITY_FINGERPRINT,
        },
        "reality": {
            "enabled": True,
            "public_key": public_key,
            "short_id": validate_short_id(config.get("reality_short_id", "")),
        },
    }


def link_parameters(
    config: Mapping[str, object],
    *,
    fingerprint: str,
) -> dict[str, str]:
    """Return the share-link parameters describing the borrowed handshake."""
    handshake = handshake_target(config)
    public_key = str(config.get("reality_public_key", "")).strip()
    if not public_key:
        raise ValueError("Reality public key is missing")
    return {
        "security": "reality",
        "sni": handshake,
        "pbk": public_key,
        "sid": validate_short_id(config.get("reality_short_id", "")),
        "fp": fingerprint or DEFAULT_REALITY_FINGERPRINT,
    }


__all__ = [
    "DECOY_ROUTE_KEY",
    "DEFAULT_HANDSHAKE",
    "DEFAULT_REALITY_FINGERPRINT",
    "HANDSHAKE_CONFIG_KEY",
    "MODES",
    "MODE_REALITY",
    "MODE_TLS",
    "PASSTHROUGH_ROUTE_KEY",
    "PASSTHROUGH_ROUTE_KIND",
    "apply_reality_mode",
    "apply_tls_mode",
    "client_tls",
    "handshake_target",
    "is_reality",
    "link_parameters",
    "normalize_domain",
    "passthrough_route",
    "security_mode",
    "server_tls",
    "validate_handshake",
    "validate_security",
    "validate_short_id",
]
