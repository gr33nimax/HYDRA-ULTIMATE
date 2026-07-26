"""Client profiles and subscription links for TrustTunnel."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import PluginState, User
from hydra.plugins.context import PluginStateAccess


def generate_client_config(
    user: User,
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_password: Callable[[str], str],
    transport_of: Callable[[PluginState | None], str],
    build_outbound: Callable[[str, str, str, str, bool], dict],
    json_dumps: Callable[..., str],
) -> str:
    protocol = state.protocols.get("trusttunnel")
    domain = (
        protocol.config.get("domain", "")
        if protocol and protocol.config
        else ""
    )
    if not domain:
        return ""

    username = derive_username(user)
    password = derive_password(user.uuid)
    transport = transport_of(protocol)
    outbounds = []
    if transport in ("tcp", "both"):
        outbounds.append(
            build_outbound(
                domain,
                domain,
                username,
                password,
                False,
            )
        )
    if transport in ("quic", "both"):
        outbounds.append(
            build_outbound(
                domain,
                domain,
                username,
                password,
                True,
            )
        )

    direct_out = {"type": "direct", "tag": "direct"}
    final_tag = outbounds[0]["tag"] if outbounds else "direct"
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
        "outbounds": outbounds + [direct_out],
        "route": {"final": final_tag},
    }
    return json_dumps(profile, indent=2)


def build_client_outbound(
    server: str,
    domain: str,
    username: str,
    password: str,
    quic: bool,
) -> dict:
    outbound = {
        "type": "trusttunnel",
        "tag": f"trusttunnel{'-quic' if quic else ''}-{username}",
        "server": server,
        "server_port": 443,
        "username": username,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": domain,
        },
    }
    if quic:
        outbound["quic"] = True
        outbound["tls"]["alpn"] = ["h3"]
    return outbound


def client_link(
    user: User,
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_password: Callable[[str], str],
    transport_of: Callable[[PluginState | None], str],
    quote: Callable[..., str],
) -> str:
    """Return the primary link; TCP remains primary for ``both``."""
    protocol = state.protocols.get("trusttunnel")
    domain = (
        protocol.config.get("domain", "")
        if protocol and protocol.config
        else ""
    )
    if not domain:
        return ""

    raw_username = derive_username(user)
    username = quote(raw_username, safe="")
    password = quote(derive_password(user.uuid), safe="")
    transport = transport_of(protocol)
    alpn = "h3" if transport == "quic" else "h2"
    suffix = " TrustTunnel QUIC" if transport == "quic" else ""
    tag = quote(f"{raw_username}{suffix}", safe="")
    return (
        f"tt://{username}:{password}@{domain}:443"
        f"?security=tls&sni={domain}&alpn={alpn}#{tag}"
    )


def client_links(
    user: User,
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_password: Callable[[str], str],
    transport_of: Callable[[PluginState | None], str],
    quote: Callable[..., str],
) -> list[str]:
    protocol = state.protocols.get("trusttunnel")
    domain = (
        protocol.config.get("domain", "")
        if protocol and protocol.config
        else ""
    )
    if not domain:
        return []

    raw_username = derive_username(user)
    username = quote(raw_username, safe="")
    password = quote(derive_password(user.uuid), safe="")
    transport = transport_of(protocol)
    links = []
    if transport in ("tcp", "both"):
        tag = quote(raw_username, safe="")
        links.append(
            f"tt://{username}:{password}@{domain}:443"
            f"?security=tls&sni={domain}&alpn=h2#{tag}"
        )
    if transport in ("quic", "both"):
        tag = quote(f"{raw_username} TrustTunnel QUIC", safe="")
        links.append(
            f"tt://{username}:{password}@{domain}:443"
            f"?security=tls&sni={domain}&alpn=h3#{tag}"
        )
    return links
