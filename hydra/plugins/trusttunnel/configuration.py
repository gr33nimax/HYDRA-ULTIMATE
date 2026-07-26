"""Sing-box configuration planning for TrustTunnel."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import PluginState, User
from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess


def configure(
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_password: Callable[[str], str],
    resolve_certs: Callable[[str, PluginState | None], tuple[str, str]],
    transport_of: Callable[[PluginState | None], str],
    build_tcp_inbound: Callable[..., dict],
    build_quic_inbound: Callable[..., dict],
) -> ConfigFragment:
    """Build the desired TrustTunnel inbounds without runtime side effects."""
    protocol = state.protocols.get("trusttunnel")
    domain = (
        protocol.config.get("domain", "")
        if protocol and protocol.config
        else ""
    )
    if not domain:
        return ConfigFragment()

    users = _active_users(
        state,
        derive_username=derive_username,
        derive_password=derive_password,
    )
    if not users:
        return ConfigFragment()

    cert_file, key_file = resolve_certs(domain, protocol)
    if not cert_file or not key_file:
        return ConfigFragment()

    transport = transport_of(protocol)
    if transport in ("quic", "both"):
        from hydra.core.sni_router import get_quic_owner

        get_quic_owner(state)

    from hydra.core.sni_router import get_effective_port, needs_mux

    listen_port = get_effective_port("trusttunnel", state)
    behind_mux = needs_mux(state)
    inbounds = []
    if transport in ("tcp", "both"):
        inbounds.append(
            build_tcp_inbound(
                domain,
                cert_file,
                key_file,
                users,
                listen_port,
                behind_mux,
            )
        )
    if transport in ("quic", "both"):
        inbounds.append(
            build_quic_inbound(
                domain,
                cert_file,
                key_file,
                users,
                listen_port,
                behind_mux,
            )
        )
    return ConfigFragment(inbounds=inbounds)


def _active_users(
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_password: Callable[[str], str],
) -> list[dict]:
    users = []
    for user in state.users:
        if user.blocked:
            continue
        users.append(
            {
                "name": derive_username(user),
                "password": derive_password(user.uuid),
            }
        )
    return users


def build_tcp_inbound(
    domain: str,
    cert_file: str,
    key_file: str,
    users: list[dict],
    listen_port: int,
    behind_mux: bool,
) -> dict:
    """Build the HTTP/2 TCP inbound."""
    return {
        "type": "trusttunnel",
        "tag": "trusttunnel-in",
        "listen": "127.0.0.1" if behind_mux else "::",
        "listen_port": listen_port,
        "network": "tcp",
        "users": users,
        "tls": {
            "enabled": True,
            "server_name": domain,
            "certificate_path": cert_file,
            "key_path": key_file,
            "alpn": ["h2"],
        },
    }


def build_quic_inbound(
    domain: str,
    cert_file: str,
    key_file: str,
    users: list[dict],
    listen_port: int,
    behind_mux: bool,
) -> dict:
    """Build the UDP form understood by the extended sing-box core."""
    return {
        "type": "trusttunnel",
        "tag": "trusttunnel-quic-in",
        "listen": "127.0.0.1" if behind_mux else "::",
        "listen_port": listen_port,
        "network": "udp",
        "users": users,
        "tls": {
            "enabled": True,
            "server_name": domain,
            "certificate_path": cert_file,
            "key_path": key_file,
            "alpn": ["h3"],
        },
    }
