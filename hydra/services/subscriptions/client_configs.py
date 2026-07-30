"""Client-specific subscription and sing-box configuration assembly."""
from __future__ import annotations

import base64
import json
import socket
import urllib.parse

from hydra.core.state_models import AppState, User
from hydra.services.subscriptions.access import SubscriptionPluginAccess
from hydra.services.subscriptions.links import generate_base64_sub
from hydra.services.subscriptions.serialization import serialize_nekobox_config


def _links_without_custom_configs(
    user: User,
    state: AppState,
    plugins: SubscriptionPluginAccess,
) -> list[str]:
    payload = base64.b64decode(
        generate_base64_sub(user, state, plugins=plugins),
    ).decode()
    links: list[str] = []
    for link in payload.splitlines():
        parsed = urllib.parse.urlparse(link)
        query = urllib.parse.parse_qs(parsed.query)
        shadowtls_trojan = (
            parsed.scheme == "trojan"
            and "shadow-tls" in query.get("plugin", [])
        )
        trusttunnel_quic = (
            parsed.scheme in ("tt", "trusttunnel")
            and query.get("alpn", ["h2"])[0] == "h3"
        )
        if link and not shadowtls_trojan and not trusttunnel_quic:
            links.append(link)
    return links


def _transport_config(
    name: str,
    user: User,
    state: AppState,
    plugins: SubscriptionPluginAccess,
) -> dict | None:
    plugin = next(
        (
            item
            for item in plugins.enabled_transports(state)
            if item.meta.name == name
        ),
        None,
    )
    if plugin is None:
        return None
    return json.loads(plugins.client_config(plugin, user, state))


def _shadowtls_client_config(
    user: User,
    state: AppState,
    plugins: SubscriptionPluginAccess,
) -> dict | None:
    return _transport_config("shadowtls", user, state, plugins)


def _trusttunnel_quic_client_config(
    user: User,
    state: AppState,
    plugins: SubscriptionPluginAccess,
) -> dict | None:
    source = _transport_config("trusttunnel", user, state, plugins)
    if source is None:
        return None
    quic_outbound = next(
        (
            outbound
            for outbound in source.get("outbounds", [])
            if outbound.get("type") == "trusttunnel"
            and outbound.get("quic") is True
        ),
        None,
    )
    if quic_outbound is None:
        return None
    direct = next(
        (
            outbound
            for outbound in source.get("outbounds", [])
            if outbound.get("tag") == "direct"
        ),
        {"type": "direct", "tag": "direct"},
    )
    source["outbounds"] = [quic_outbound, direct]
    source["route"] = {
        "final": quic_outbound["tag"],
        "auto_detect_interface": True,
        "default_domain_resolver": "local",
    }
    return source


def _add_mixed_inbound(config: dict) -> None:
    config["inbounds"] = [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080,
        },
    ]


def _pin_trusttunnel_quic_endpoint(
    config: dict,
    state: AppState,
) -> None:
    outbound = next(
        (
            item
            for item in config.get("outbounds", [])
            if item.get("type") == "trusttunnel"
            and item.get("quic") is True
        ),
        None,
    )
    if outbound is None:
        return
    endpoint = (state.network.server_ip or "").strip().strip("[]")
    if not endpoint:
        try:
            endpoint = socket.gethostbyname(outbound.get("server", ""))
        except (OSError, TypeError):
            return
    outbound["server"] = endpoint


def _add_nekobox_inbounds(config: dict) -> None:
    config.setdefault("route", {})["auto_detect_interface"] = True
    config["inbounds"] = [
        {
            "type": "tun",
            "tag": "tun-in",
            "stack": "mixed",
            "mtu": 9000,
            "address": ["172.19.0.1/30"],
            "endpoint_independent_nat": True,
        },
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080,
        },
    ]


def _throne_custom_link(config: dict, name: str, link_type: str) -> str:
    wrapper = {
        "type": "custom",
        "name": name,
        "subtype": "fullconfig",
        "config": json.dumps(
            config,
            ensure_ascii=False,
            separators=(",", ":"),
        ),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(
            wrapper,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode(),
    ).decode("ascii").rstrip("=")
    return f"json://{link_type}#{encoded}"


def generate_throne_sub(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
) -> str:
    """Build a Throne subscription with complex transports kept atomic."""
    links = _links_without_custom_configs(user, state, plugins)
    try:
        config = _shadowtls_client_config(user, state, plugins)
        if config:
            _add_mixed_inbound(config)
            links.append(
                _throne_custom_link(
                    config,
                    f"{user.email} ShadowTLS",
                    "shadowtls",
                ),
            )
    except Exception:
        pass

    try:
        config = _trusttunnel_quic_client_config(user, state, plugins)
        if config:
            _pin_trusttunnel_quic_endpoint(config, state)
            _add_mixed_inbound(config)
            links.append(
                _throne_custom_link(
                    config,
                    f"{user.email} TrustTunnel QUIC",
                    "trusttunnel-quic",
                ),
            )
    except Exception:
        pass
    payload = "\n".join(links) + "\n"
    return base64.b64encode(payload.encode()).decode("ascii")


def generate_nekobox_sub(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
) -> str:
    """Build a NekoBox subscription with complex transports kept atomic."""
    links = _links_without_custom_configs(user, state, plugins)
    for name, label in (
        ("shadowtls", "ShadowTLS"),
        ("trusttunnel", "TrustTunnel QUIC"),
    ):
        try:
            config = (
                _shadowtls_client_config(user, state, plugins)
                if name == "shadowtls"
                else _trusttunnel_quic_client_config(user, state, plugins)
            )
            if config:
                _add_nekobox_inbounds(config)
                compact = json.dumps(
                    config,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                links.append(
                    serialize_nekobox_config(
                        compact,
                        f"{user.email} {label}",
                    ),
                )
        except Exception:
            continue
    payload = "\n".join(links) + "\n"
    return base64.b64encode(payload.encode()).decode("ascii")


def generate_singbox_config(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
) -> dict:
    """Build a personal sing-box configuration from enabled transports."""
    base_config: dict = {
        "log": {"level": "info"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            },
        ],
        "outbounds": [],
        "route": {"rules": [], "auto_detect_interface": True},
    }
    plugin_configs: list[dict] = []
    for plugin in plugins.enabled_transports(state):
        if not plugin.meta.capabilities.subscription_enabled:
            continue
        try:
            payload = plugins.singbox_config(plugin, user, state)
            if not payload:
                continue
            plugin_config = json.loads(payload)
            if isinstance(plugin_config, dict):
                plugin_configs.append(plugin_config)
        except Exception:
            continue

    if len(plugin_configs) == 1:
        config = plugin_configs[0]
        config.setdefault("log", base_config["log"])
        config.setdefault("inbounds", base_config["inbounds"])
        outbounds = config.setdefault("outbounds", [])
        outbound_tags = {
            outbound.get("tag", "")
            for outbound in outbounds
            if isinstance(outbound, dict)
        }
        if "direct" not in outbound_tags:
            outbounds.append({"type": "direct", "tag": "direct"})
        route = config.setdefault("route", {})
        if not route.get("final"):
            route["final"] = next(
                (
                    outbound.get("tag", "")
                    for outbound in outbounds
                    if outbound.get("type") != "direct"
                ),
                "",
            )
        return config

    config = base_config
    outbound_tags: set[str] = set()
    endpoint_tags: set[str] = set()
    selected_outbound = ""
    for plugin_config in plugin_configs:
        route = plugin_config.get("route", {})
        if not selected_outbound and route.get("final"):
            selected_outbound = route["final"]
        for endpoint in plugin_config.get("endpoints", []):
            tag = endpoint.get("tag", "")
            if tag and tag in endpoint_tags:
                continue
            config.setdefault("endpoints", []).append(endpoint)
            if tag:
                endpoint_tags.add(tag)
        for outbound in plugin_config.get("outbounds", []):
            tag = outbound.get("tag", "")
            if tag and tag in outbound_tags:
                continue
            config["outbounds"].append(outbound)
            if tag:
                outbound_tags.add(tag)
            if not selected_outbound and outbound.get("type") != "direct":
                selected_outbound = tag
        config["route"]["rules"].extend(route.get("rules", []))

    if "direct" not in outbound_tags:
        config["outbounds"].append({"type": "direct", "tag": "direct"})
    if selected_outbound:
        config["route"]["final"] = selected_outbound
    return config


def generate_client_config(
    user: User,
    state: AppState,
    protocol: str,
    *,
    plugins: SubscriptionPluginAccess,
) -> str:
    """Generate one protocol-specific client configuration."""
    plugin = plugins.get(protocol)
    if plugin is None or not plugins.status(plugin, state).enabled:
        return ""
    try:
        return plugins.client_config(plugin, user, state)
    except Exception:
        return ""
