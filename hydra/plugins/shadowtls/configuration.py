"""Sing-box configuration planning for ShadowTLS."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import User
from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess


def configure(
    state: PluginStateAccess,
    *,
    validate_sni: Callable[[str, PluginStateAccess], str],
    derive_username: Callable[[User], str],
    derive_stls_password: Callable[[str], str],
    derive_trojan_password: Callable[[str], str],
) -> ConfigFragment:
    """Build paired ShadowTLS and Trojan inbounds without side effects."""
    protocol = state.protocols.get("shadowtls")
    handshake_sni = (
        protocol.config.get("handshake_sni", "")
        if protocol and protocol.config
        else ""
    )
    if not handshake_sni:
        return ConfigFragment()
    handshake_sni = validate_sni(handshake_sni, state)

    stls_users, trojan_users = _active_users(
        state,
        derive_username=derive_username,
        derive_stls_password=derive_stls_password,
        derive_trojan_password=derive_trojan_password,
    )
    if not stls_users:
        return ConfigFragment()

    from hydra.core.sni_router import get_effective_port, needs_mux

    listen_port = get_effective_port("shadowtls", state)
    listen = "127.0.0.1" if needs_mux(state) else "::"
    shadowtls_inbound = {
        "type": "shadowtls",
        "tag": "shadowtls-in",
        "listen": listen,
        "listen_port": listen_port,
        "version": 3,
        "users": stls_users,
        "handshake": {
            "server": handshake_sni,
            "server_port": 443,
        },
        "strict_mode": True,
        "detour": "shadowtls-trojan-in",
    }
    trojan_inbound = {
        "type": "trojan",
        "tag": "shadowtls-trojan-in",
        "users": trojan_users,
    }
    return ConfigFragment(
        inbounds=[shadowtls_inbound, trojan_inbound]
    )


def _active_users(
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_stls_password: Callable[[str], str],
    derive_trojan_password: Callable[[str], str],
) -> tuple[list[dict], list[dict]]:
    stls_users = []
    trojan_users = []
    for user in state.users:
        if user.blocked:
            continue
        username = derive_username(user)
        stls_users.append(
            {
                "name": username,
                "password": derive_stls_password(user.uuid),
            }
        )
        trojan_users.append(
            {
                "name": username,
                "password": derive_trojan_password(user.uuid),
            }
        )
    return stls_users, trojan_users
