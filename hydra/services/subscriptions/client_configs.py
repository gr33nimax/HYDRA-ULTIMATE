"""Client-specific subscription and sing-box configuration assembly."""
from __future__ import annotations

import base64
import json
import socket
import urllib.parse

from hydra.core.configuration_names import (
    _replace_profile_reference,
    resolve_configuration_name,
)
from hydra.core.state_models import AppState, User
from hydra.services.subscriptions.access import SubscriptionPluginAccess
from hydra.services.subscriptions.links import generate_base64_sub
from hydra.services.subscriptions.serialization import serialize_nekobox_config


def _links_without_custom_configs(
    user: User,
    state: AppState,
    plugins: SubscriptionPluginAccess,
    *,
    for_nekobox: bool = False,
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
        legacy_awg = (
            for_nekobox
            and parsed.scheme == "sn"
            and parsed.netloc == "awg"
        )
        if legacy_awg or not link or shadowtls_trojan or trusttunnel_quic:
            continue
        if for_nekobox and parsed.scheme == "wg":
            query_parts = [
                "peer_public_key=" + part.removeprefix("public_key=")
                if part.startswith("public_key=")
                else part
                for part in parsed.query.split("&")
            ]
            link = urllib.parse.urlunparse(
                parsed._replace(query="&".join(query_parts)),
            )
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
    try:
        return json.loads(plugins.client_config(plugin, user, state))
    except (json.JSONDecodeError, TypeError):
        return None


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
            and bool(outbound.get("quic"))
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
            and bool(item.get("quic"))
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


def _profile_name(user: User, state: AppState, key: str, default: str) -> str:
    return resolve_configuration_name(
        key=key, default=default, global_names=state.configuration_names,
        user_names=user.configuration_name_overrides,
    )


def _quic_profile_name(config: dict, user: User, state: AppState) -> str:
    keys = {"trusttunnel", "trusttunnel:quic"}
    if keys.intersection(state.configuration_names) or keys.intersection(user.configuration_name_overrides):
        return config["route"]["final"]
    return f"{user.email} TrustTunnel QUIC"


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
                    _profile_name(user, state, "shadowtls", f"{user.email} ShadowTLS"),
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
                    _quic_profile_name(config, user, state),
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
    links = _links_without_custom_configs(
        user,
        state,
        plugins,
        for_nekobox=True,
    )
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
                        _profile_name(user, state, name, f"{user.email} {label}")
                        if name == "shadowtls" else _quic_profile_name(config, user, state),
                    ),
                )
        except Exception:
            continue
    payload = "\n".join(links) + "\n"
    return base64.b64encode(payload.encode()).decode("ascii")


def _avoid_tag_collisions(document: dict, existing: set[str]) -> None:
    """Keep separate protocols with equal display names and their detours."""
    objects = [*document.get("outbounds", []), *document.get("endpoints", [])]
    reserved = existing | {item.get("tag", "") for item in objects} | {"direct"}
    changes = []
    for item in objects:
        old = item.get("tag", "")
        if not old or old not in existing or item == {"type": "direct", "tag": "direct"}:
            continue
        number = 2
        while f"{old} ({number})" in reserved:
            number += 1
        new = f"{old} ({number})"
        reserved.add(new)
        changes.append((old, new))
        item["tag"] = new
    for old, new in changes:
        _replace_profile_reference(document, old, new)


def generate_singbox_config(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
) -> dict:
    """Build a personal sing-box configuration from enabled transports."""
    config: dict = {
        "log": {"level": "info"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            },
        ],
        "endpoints": [],
        "outbounds": [],
        "route": {"rules": [], "auto_detect_interface": True},
    }
    endpoint_tags: set[str] = set()
    outbound_tags: set[str] = set()
    selected_outbound = ""
    for plugin in plugins.enabled_transports(state):
        if not plugin.meta.capabilities.subscription_enabled:
            continue
        try:
            payload = plugins.singbox_client_config(plugin, user, state)
            if not payload:
                continue
            plugin_config = json.loads(payload)
            _avoid_tag_collisions(plugin_config, outbound_tags | endpoint_tags)
            for endpoint in plugin_config.get("endpoints", []):
                tag = endpoint.get("tag", "")
                if tag and tag in endpoint_tags:
                    continue
                config["endpoints"].append(endpoint)
                if tag:
                    endpoint_tags.add(tag)
                if not selected_outbound:
                    selected_outbound = tag
            for outbound in plugin_config.get("outbounds", []):
                tag = outbound.get("tag", "")
                if tag and tag in outbound_tags:
                    continue
                config["outbounds"].append(outbound)
                if tag:
                    outbound_tags.add(tag)
                if not selected_outbound and outbound.get("type") != "direct":
                    selected_outbound = tag
            route = plugin_config.get("route", {})
            config["route"]["rules"].extend(route.get("rules", []))
        except Exception:
            continue

    if not config["endpoints"]:
        config.pop("endpoints")
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
