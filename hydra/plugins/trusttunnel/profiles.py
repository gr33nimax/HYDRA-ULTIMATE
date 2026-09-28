"""Client profiles and subscription links for TrustTunnel."""
from __future__ import annotations

import base64
from collections.abc import Callable

from hydra.core.configuration_names import _unique_configuration_tag, resolve_configuration_name
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
        outbound = build_outbound(
            domain, domain, username, password, False,
        )
        outbound["tag"] = resolve_configuration_name(
            key="trusttunnel:tcp",
            default=outbound["tag"],
            global_names={},
            user_names=user.configuration_name_overrides,
        )
        outbounds.append(outbound)
    if transport in ("quic", "both"):
        outbound = build_outbound(
            domain, domain, username, password, True,
        )
        outbound["tag"] = resolve_configuration_name(
            key="trusttunnel:quic",
            default=outbound["tag"],
            global_names={},
            user_names=user.configuration_name_overrides,
        )
        outbounds.append(outbound)

    tags = {"direct"}
    for outbound in outbounds:
        outbound["tag"] = _unique_configuration_tag(outbound["tag"], tags)
        tags.add(outbound["tag"])
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
            "alpn": ["h3" if quic else "h2"],
        },
    }
    if quic:
        outbound["quic"] = True
    return outbound


def _varint(value: int) -> bytes:
    if not 0 <= value < 2**62:
        raise ValueError("TrustTunnel TLV integer is out of range")
    for size, limit, prefix in ((1, 2**6, 0), (2, 2**14, 0x4000),
                                (4, 2**30, 0x80000000), (8, 2**62, 0xC000000000000000)):
        if value < limit:
            return (prefix | value).to_bytes(size, "big")
    raise AssertionError("unreachable")


def _tlv(tag: int, value: bytes) -> bytes:
    return _varint(tag) + _varint(len(value)) + value


def deep_link(
    *,
    hostname: str,
    address: str,
    username: str,
    password: str,
    upstream_protocol: str,
    name: str,
) -> str:
    """Encode the official ``tt://?<base64url-TLV>`` endpoint URI."""
    protocol = {"h2": 1, "h3": 2}[upstream_protocol]
    fields = (
        (0x00, _varint(1)),
        (0x01, hostname.encode("utf-8")),
        (0x05, username.encode("utf-8")),
        (0x06, password.encode("utf-8")),
        (0x02, address.encode("utf-8")),
        (0x09, _varint(protocol)),
        (0x0C, name.encode("utf-8")),
    )
    payload = b"".join(_tlv(tag, value) for tag, value in fields)
    return "tt://?" + base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _link_for_transport(
    *,
    user: User,
    state: PluginStateAccess,
    domain: str,
    username: str,
    password: str,
    quic: bool,
) -> str:
    suffix = " TrustTunnel QUIC" if quic else " TrustTunnel"
    return deep_link(
        hostname=domain,
        address=f"{domain}:443",
        username=username,
        password=password,
        upstream_protocol="h3" if quic else "h2",
        name=resolve_configuration_name(
            key=f"trusttunnel:{'quic' if quic else 'tcp'}",
            default=f"{username}{suffix}",
            global_names={},
            user_names=user.configuration_name_overrides,
        ),
    )


def client_link(
    user: User,
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_password: Callable[[str], str],
    transport_of: Callable[[PluginState | None], str],
) -> str:
    """Return the primary deep link; TCP remains primary for ``both``."""
    protocol = state.protocols.get("trusttunnel")
    domain = protocol.config.get("domain", "") if protocol and protocol.config else ""
    if not domain:
        return ""
    return _link_for_transport(
        user=user,
        state=state,
        domain=domain,
        username=derive_username(user),
        password=derive_password(user.uuid),
        quic=transport_of(protocol) == "quic",
    )


def client_links(
    user: User,
    state: PluginStateAccess,
    *,
    derive_username: Callable[[User], str],
    derive_password: Callable[[str], str],
    transport_of: Callable[[PluginState | None], str],
) -> list[str]:
    protocol = state.protocols.get("trusttunnel")
    domain = (
        protocol.config.get("domain", "")
        if protocol and protocol.config
        else ""
    )
    if not domain:
        return []

    username = derive_username(user)
    password = derive_password(user.uuid)
    transport = transport_of(protocol)
    links = []
    if transport in ("tcp", "both"):
        links.append(_link_for_transport(
            user=user, state=state,
            domain=domain, username=username, password=password, quic=False,
        ))
    if transport in ("quic", "both"):
        links.append(_link_for_transport(
            user=user, state=state,
            domain=domain, username=username, password=password, quic=True,
        ))
    return links
