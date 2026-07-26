"""Pure Telemt configuration planning and TOML rendering."""
from __future__ import annotations

from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess

from .constants import DEFAULT_PORT
from .credentials import derive_secret, derive_username


def build_toml(
    port: int,
    ipv4: bool,
    ipv6: bool,
    tls_domain: str,
    users: dict[str, str],
    use_middle_proxy: bool = False,
    client_mss: str = "",
) -> str:
    net_prefer = 6 if (ipv6 and not ipv4) else 4
    shown_users = ", ".join(f'"{user}"' for user in users)
    lines = [
        "[general]",
        "prefer_ipv6 = false",
        "fast_mode = true",
        f"use_middle_proxy = {str(use_middle_proxy).lower()}",
    ]
    if client_mss:
        lines.append(f'client_mss = "{client_mss}"')
    lines += [
        "",
        "[network]",
        f"ipv4 = {str(ipv4).lower()}",
        f"ipv6 = {str(ipv6).lower()}",
        f"prefer = {net_prefer}",
        "",
        "[general.modes]",
        "classic = false",
        "secure = false",
        "tls = true",
        "",
        "[general.links]",
        f"show = [{shown_users}]",
        "",
        "[server]",
        f"port = {port}",
        "",
    ]
    if ipv4:
        lines += ['[[server.listeners]]', 'ip = "0.0.0.0"', ""]
    if ipv6:
        lines += ['[[server.listeners]]', 'ip = "::"', ""]
    lines += [
        "[timeouts]",
        "client_handshake = 300",
        "client_keepalive = 60",
        "client_ack = 300",
        "",
        "[censorship]",
        f'tls_domain = "{tls_domain}"',
        "mask = true",
        "mask_port = 443",
        "fake_cert_len = 2048",
        "",
        "[access]",
        "replay_check_len = 65536",
        "ignore_time_skew = false",
        "",
        "[access.users]",
    ]
    lines.extend(f'{name} = "{secret}"' for name, secret in users.items())
    lines += [
        "",
        "[[upstreams]]",
        'type = "direct"',
        "enabled = true",
        "weight = 10",
    ]
    return "\n".join(lines) + "\n"


def plan_configuration(state: PluginStateAccess) -> tuple[str, ConfigFragment]:
    protocol = state.protocols.get("telemt")
    cfg = protocol.config if protocol else {}
    port = cfg.get("port", DEFAULT_PORT)
    domain = cfg.get("tls_domain", state.network.domain or "google.com")
    if "ipv4" in cfg or "ipv6" in cfg:
        has_ipv4 = bool(cfg.get("ipv4", True))
        has_ipv6 = bool(cfg.get("ipv6", False))
    else:
        has_ipv4 = not (
            state.network.server_ip and ":" in state.network.server_ip
        )
        has_ipv6 = bool(
            state.network.server_ip and ":" in state.network.server_ip
        )
    users = {
        derive_username(user.uuid): derive_secret(user.uuid)
        for user in state.users
        if not user.blocked
    }
    toml = build_toml(
        port=port,
        ipv4=has_ipv4,
        ipv6=has_ipv6,
        tls_domain=domain,
        users=users,
        use_middle_proxy=cfg.get("use_middle_proxy", False),
        client_mss=cfg.get("client_mss", ""),
    )
    inbounds: list[dict] = []
    route_rules: list[dict] = []
    if cfg.get("singbox_integration_enabled", False):
        inbounds.append(
            {
                "type": "redirect",
                "tag": "redirect-telemt",
                "listen": "127.0.0.1",
                "listen_port": cfg.get("singbox_integration_port", 10811),
            }
        )
        warp = state.protocols.get("warp")
        if warp and warp.enabled:
            route_rules.append(
                {"inbound": ["redirect-telemt"], "outbound": "warp"}
            )
    return toml, ConfigFragment(
        inbounds=inbounds,
        route_rules=route_rules,
        nft_tproxy_ports=[port],
    )
