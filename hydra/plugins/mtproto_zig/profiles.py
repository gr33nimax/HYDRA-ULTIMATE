"""Shared-client-artifact projections for mtproto.zig."""

from __future__ import annotations

import json
from collections.abc import Callable

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess

from . import configuration
from .credentials import derive_secret, make_tls_secret


def _config(state: PluginStateAccess) -> dict:
    protocol = state.protocols.get("mtproto_zig")
    return dict(protocol.config) if protocol else {}


def fake_tls_link(user: User, state: PluginStateAccess, *, resolve_public_ip: Callable[[], str]) -> str:
    config = _config(state)
    domain = str(config.get("domain", "")).strip()
    if not domain:
        return ""
    server = state.network.server_ip or resolve_public_ip()
    return f"tg://proxy?server={server}&port=443&secret={make_tls_secret(derive_secret(user.uuid), domain)}"


def web_link(user: User, state: PluginStateAccess) -> str:
    """Telegram Desktop 7.1+ WEB link: the relay host is the SNI, port is implicit."""
    config = _config(state)
    domain = configuration.web_domain(config)
    if not domain:
        return ""
    return f"tg://webproxy?server={domain}&secret=dd{derive_secret(user.uuid)}"


def client_links(user: User, state: PluginStateAccess, *, resolve_public_ip: Callable[[], str]) -> list[str]:
    """Return the links that actually connect in the configured access mode."""
    mode = configuration.web_mode(_config(state))
    links: list[str] = []
    if mode != "web-only":
        direct = fake_tls_link(user, state, resolve_public_ip=resolve_public_ip)
        if direct:
            links.append(direct)
    if mode != "off":
        web = web_link(user, state)
        if web:
            links.append(web)
    return links


def client_link(user: User, state: PluginStateAccess, *, resolve_public_ip: Callable[[], str]) -> str:
    links = client_links(user, state, resolve_public_ip=resolve_public_ip)
    return links[0] if links else ""


def generate_client_config(link: str) -> str:
    return json.dumps({"link": link, "protocol": "mtproto_zig"}) if link else ""
