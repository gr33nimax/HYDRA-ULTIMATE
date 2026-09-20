"""Shared-client-artifact projections for mtproto.zig."""

from __future__ import annotations

import json
from collections.abc import Callable

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess

from .credentials import derive_secret, make_tls_secret


def client_link(user: User, state: PluginStateAccess, *, resolve_public_ip: Callable[[], str]) -> str:
    protocol = state.protocols.get("mtproto_zig")
    domain = str(protocol.config.get("domain", "") if protocol else "").strip()
    if not domain:
        return ""
    server = state.network.server_ip or resolve_public_ip()
    return f"tg://proxy?server={server}&port=443&secret={make_tls_secret(derive_secret(user.uuid), domain)}"


def generate_client_config(link: str) -> str:
    return json.dumps({"link": link, "protocol": "mtproto_zig"}) if link else ""
