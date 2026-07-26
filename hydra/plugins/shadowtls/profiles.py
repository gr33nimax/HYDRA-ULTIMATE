"""Client profiles and subscription links for ShadowTLS."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess


def generate_client_config(
    user: User,
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_stls_password: Callable[[str], str],
    derive_trojan_password: Callable[[str], str],
    server_ip: Callable[[PluginStateAccess], str],
    json_dumps: Callable[..., str],
) -> str:
    protocol = state.protocols.get("shadowtls")
    handshake_sni = (
        protocol.config.get("handshake_sni", "")
        if protocol and protocol.config
        else ""
    )
    if not handshake_sni:
        return ""

    username = derive_username(user)
    stls_password = derive_stls_password(user.uuid)
    trojan_password = derive_trojan_password(user.uuid)
    server = server_ip(state)
    outbound_trojan = {
        "type": "trojan",
        "tag": f"shadowtls-trojan-{username}",
        "server": server,
        "server_port": 443,
        "password": trojan_password,
        "detour": f"shadowtls-{username}",
    }
    outbound_stls = {
        "type": "shadowtls",
        "tag": f"shadowtls-{username}",
        "server": server,
        "server_port": 443,
        "version": 3,
        "password": stls_password,
        "tls": {
            "enabled": True,
            "server_name": handshake_sni,
            "utls": {
                "enabled": True,
                "fingerprint": "chrome",
            },
        },
    }
    profile = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "google", "address": "8.8.8.8"},
                {
                    "tag": "local",
                    "address": "1.1.1.1",
                    "detour": "direct",
                },
            ],
        },
        "outbounds": [
            outbound_trojan,
            outbound_stls,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": outbound_trojan["tag"]},
    }
    return json_dumps(profile, indent=2)


def client_link(
    user: User,
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_stls_password: Callable[[str], str],
    derive_trojan_password: Callable[[str], str],
    server_ip: Callable[[PluginStateAccess], str],
    url_host: Callable[[str], str],
    quote: Callable[..., str],
) -> str:
    protocol = state.protocols.get("shadowtls")
    handshake_sni = (
        protocol.config.get("handshake_sni", "")
        if protocol and protocol.config
        else ""
    )
    if not handshake_sni:
        return ""

    stls_password = derive_stls_password(user.uuid)
    trojan_password = derive_trojan_password(user.uuid)
    tag = quote(derive_username(user), safe="")
    host = url_host(server_ip(state))
    options = (
        f"host={handshake_sni};"
        f"password={stls_password};version=3"
    )
    encoded_options = quote(options, safe="")
    return (
        f"trojan://{trojan_password}@{host}:443"
        f"?plugin=shadow-tls&plugin-opts={encoded_options}#{tag}"
    )
