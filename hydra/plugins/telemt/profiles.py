"""Telemt client artifact construction."""

from __future__ import annotations

import json
from collections.abc import Callable

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess

from .configuration import settings_from_state
from .credentials import derive_secret, make_tls_secret


def client_links(
    user: User,
    state: PluginStateAccess,
    *,
    resolve_public_ip: Callable[[], str],
    ios_status: Callable[[], dict] | None = None,
) -> list[str]:
    """Return one artifact from the same settings snapshot used for TOML."""
    del ios_status
    settings = settings_from_state(state)
    server_ip = state.network.server_ip or resolve_public_ip()
    secret = make_tls_secret(derive_secret(user.uuid), settings.tls_domain)
    return [
        f"tg://proxy?server={server_ip}&port={settings.port}&secret={secret}",
    ]


def generate_client_config(link: str) -> str:
    return json.dumps({"link": link, "protocol": "telemt"}) if link else ""
