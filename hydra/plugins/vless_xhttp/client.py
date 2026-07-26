"""Client-facing artefacts of the VLESS transport: links and profiles."""
from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping

from hydra.core.state_models import User
from hydra.plugins.vless_xhttp.security import (
    DEFAULT_REALITY_FINGERPRINT,
    client_tls as reality_client_tls,
    handshake_target,
    is_reality,
    link_parameters as reality_link_parameters,
)
from hydra.plugins.vless_xhttp.tuning import (
    DEFAULT_MODE,
    DEFAULT_PATH,
    client_tls as xhttp_client_tls,
    link_extra,
    link_params,
    transport as build_transport,
    validate_mode,
    validate_path,
)


PUBLIC_PORT = 443


def _fingerprint(config: Mapping[str, object]) -> str:
    """Return the configured uTLS fingerprint, or "" when the client decides."""
    fingerprint = str(config.get("utls_fingerprint", "none")).strip().lower()
    return "" if fingerprint == "none" else fingerprint


def tls_block(config: Mapping[str, object], host: str) -> dict[str, object]:
    """Return the outbound TLS block matching the configured security mode."""
    if is_reality(config):
        # Reality is fingerprinted by definition, so a client that made no
        # choice still gets a concrete, common ClientHello.
        return reality_client_tls(
            config,
            fingerprint=_fingerprint(config) or DEFAULT_REALITY_FINGERPRINT,
        )
    return {
        "enabled": True,
        "server_name": host,
        "alpn": ["h2"],
        **xhttp_client_tls(config),
    }


def profile(
    user: User,
    config: Mapping[str, object],
    *,
    server: str,
    host: str,
) -> str:
    """Build a personal sing-box configuration for one user."""
    outbound = {
        "type": "vless",
        "tag": f"vless-xhttp-{user.email}",
        "server": server,
        "server_port": PUBLIC_PORT,
        "uuid": user.uuid,
        "tls": tls_block(config, host),
        "transport": build_transport(config, client=True, domain=host),
    }
    return json.dumps(
        {
            "log": {"level": "info"},
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": outbound["tag"]},
        },
        indent=2,
    )


def share_link(
    user: User,
    config: Mapping[str, object],
    *,
    server: str,
    host: str,
) -> str:
    """Build the ``vless://`` link matching the configured security mode."""
    parameters: dict[str, str] = {
        "encryption": "none",
        "type": "xhttp",
        "host": host,
        "path": validate_path(config.get("xhttp_path", DEFAULT_PATH)),
        "mode": validate_mode(config.get("xhttp_mode", DEFAULT_MODE)),
    }
    if is_reality(config):
        parameters.update(
            reality_link_parameters(
                config,
                fingerprint=_fingerprint(config),
            ),
        )
        # Reality borrows the handshake of another host; the XHTTP Host header
        # stays that host too, so intermediaries see one consistent name.
        parameters["host"] = handshake_target(config)
    else:
        parameters.update(
            {
                "security": "tls",
                "sni": host,
                "alpn": "h2",
            },
        )
        parameters.update(link_params(config))
    extra = link_extra(config)
    if extra:
        parameters["extra"] = json.dumps(
            extra,
            separators=(",", ":"),
            sort_keys=True,
        )
    query = urllib.parse.urlencode(_ordered(parameters))
    uuid = urllib.parse.quote(user.uuid, safe="")
    label = "VLESS Reality" if is_reality(config) else "VLESS XHTTP"
    tag = urllib.parse.quote(f"{user.email} {label}", safe="")
    return f"vless://{uuid}@{server}:{PUBLIC_PORT}?{query}#{tag}"


_ORDER = (
    "encryption",
    "security",
    "sni",
    "alpn",
    "pbk",
    "sid",
    "fp",
    "type",
    "host",
    "path",
    "mode",
    "extra",
)


def _ordered(parameters: dict[str, str]) -> list[tuple[str, str]]:
    """Keep share links stable so unchanged settings produce identical text."""
    known = [
        (key, parameters[key]) for key in _ORDER if key in parameters
    ]
    rest = sorted(
        (key, value)
        for key, value in parameters.items()
        if key not in set(_ORDER)
    )
    return [*known, *rest]


__all__ = ["PUBLIC_PORT", "profile", "share_link", "tls_block"]
