"""Telemt client profile construction."""
from __future__ import annotations

import json
from collections.abc import Callable

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess

from .constants import DEFAULT_PORT
from .credentials import derive_secret, make_tls_secret


def client_links(
    user: User,
    state: PluginStateAccess,
    *,
    resolve_public_ip: Callable[[], str],
    ios_status: Callable[[], dict],
) -> list[str]:
    protocol = state.protocols.get("telemt")
    cfg = protocol.config if protocol else {}
    port = cfg.get("port", DEFAULT_PORT)
    domain = cfg.get("tls_domain")
    if domain is None:
        domain = state.network.domain
    secret = derive_secret(user.uuid)
    server_ip = state.network.server_ip or resolve_public_ip()
    tls_secret = make_tls_secret(secret, domain) if domain else secret
    links = [
        f"tg://proxy?server={server_ip}&port={port}&secret={tls_secret}",
    ]
    try:
        ios = ios_status()
        if ios.get("enabled"):
            links.append(
                "tg://proxy"
                f"?server={server_ip}"
                f"&port={ios['ext_port']}"
                f"&secret={tls_secret}"
            )
    except Exception:
        pass
    return list(dict.fromkeys(links))


def generate_client_config(link: str) -> str:
    if not link:
        return ""
    return json.dumps({"link": link, "protocol": "telemt"})
