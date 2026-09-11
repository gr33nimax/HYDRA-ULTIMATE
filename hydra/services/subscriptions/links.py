"""Share-link and client-specific base64 subscription generation."""
from __future__ import annotations

import base64
import urllib.parse

from hydra.core.configuration_names import resolve_configuration_name
from hydra.core.state_models import AppState, User
from hydra.services.subscriptions.access import SubscriptionPluginAccess
from hydra.services.subscriptions.serialization import (
    clean_link_to_sn,
    generate_awg_sn_link,
)
from hydra.services.subscriptions.shadowrocket import (
    build_shadowrocket_naive_links,
    build_shadowrocket_snell_link,
)


def generate_links(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
) -> list[str]:
    """Collect links from all enabled transport plugins."""
    links: list[str] = []
    for plugin in plugins.enabled_transports(state):
        capabilities = plugin.meta.capabilities
        if not capabilities.subscription_enabled:
            continue
        try:
            if capabilities.subscription_profile_query:
                for profile in plugins.profiles(plugin, state):
                    link = plugins.client_link(
                        plugin,
                        user,
                        state,
                        profile=profile["name"],
                    )
                    if link:
                        links.append(link)
            else:
                links.extend(
                    link
                    for link in plugins.client_links(plugin, user, state)
                    if link
                )
        except Exception:
            continue
    return list(dict.fromkeys(links))


def _protocol_suffix(link: str) -> str:
    parsed = urllib.parse.urlparse(link)
    scheme = parsed.scheme.lower()
    if scheme == "naive+quic":
        return "NaiveProxy QUIC"
    if scheme in ("naive", "naive+https"):
        return "NaiveProxy"
    if scheme == "anytls":
        return "AnyTLS"
    if scheme in ("tt", "trusttunnel"):
        query = urllib.parse.parse_qs(parsed.query)
        return (
            "TrustTunnel QUIC"
            if query.get("alpn", ["h2"])[0] == "h3"
            else "TrustTunnel"
        )
    if scheme == "mierus":
        return "Mieru"
    if scheme in ("hysteria2", "hy2"):
        return "Hysteria2"
    if scheme == "vless":
        query = urllib.parse.parse_qs(parsed.query)
        if query.get("type", [""])[0] == "xhttp":
            return "VLESS XHTTP"
        return "VLESS"
    if scheme == "snell":
        return "Snell"
    if scheme == "trojan":
        query = urllib.parse.parse_qs(parsed.query)
        if "shadow-tls" in query.get("plugin", []):
            return "ShadowTLS"
    return ""


def _configuration_name_key(link: str) -> str:
    parsed = urllib.parse.urlparse(link)
    scheme = parsed.scheme.lower()
    query = urllib.parse.parse_qs(parsed.query)
    if scheme == "trojan" and "shadow-tls" in query.get("plugin", []):
        return "shadowtls"
    return {
        "naive": "naive",
        "naive+https": "naive",
        "naive+quic": "naive",
        "anytls": "anytls",
        "tt": "trusttunnel",
        "trusttunnel": "trusttunnel",
        "mierus": "mieru",
        "hysteria2": "hysteria2",
        "hy2": "hysteria2",
        "vless": "vless",
        "snell": "snell",
        "trojan": "trojan",
    }.get(scheme, "")


def tag_client_link(link: str, user: User, state: AppState) -> str:
    """Apply the resolved display name where the URI supports a fragment."""
    try:
        suffix = _protocol_suffix(link)
        key = _configuration_name_key(link)
        if not suffix or not key:
            return link
        parsed = urllib.parse.urlparse(link)
        if parsed.scheme.lower() in {"tt", "trusttunnel"}:
            return link
        label = resolve_configuration_name(
            key=key,
            default=f"{user.email} {suffix}",
            global_names=state.configuration_names,
            user_names=user.configuration_name_overrides,
        )
        return urllib.parse.urlunparse(
            parsed._replace(
                fragment=urllib.parse.quote(label),
            ),
        )
    except Exception:
        return link


def _awg_links(
    user: User,
    state: AppState,
    plugins: SubscriptionPluginAccess,
) -> list[str]:
    plugin = plugins.get("amneziawg")
    if plugin is None:
        return []
    try:
        if not plugins.status(plugin, state).enabled:
            return []
        links: list[str] = []
        for profile in plugins.profiles(plugin, state):
            config = plugins.client_config(
                plugin,
                user,
                state,
                profile=profile["name"],
            )
            if config:
                link = generate_awg_sn_link(
                    config,
                    resolve_configuration_name(
                        key=f"amneziawg:{profile['name']}",
                        default=f"{user.email} AWG {profile['label']}",
                        global_names=state.configuration_names,
                        user_names=user.configuration_name_overrides,
                    ),
                )
                if link:
                    links.append(link)
        return links
    except Exception:
        return []


def _base_subscription_links(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
) -> list[str]:
    formatted = [
        tag_client_link(link, user, state)
        for link in generate_links(user, state, plugins=plugins)
    ]
    links = [*formatted]
    links.extend(
        converted
        for link in formatted
        if (converted := clean_link_to_sn(link, user))
    )
    links.extend(_awg_links(user, state, plugins))
    return links


def generate_base64_sub(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
) -> str:
    """Build a generic base64 subscription with native NekoBox variants."""
    links = _base_subscription_links(user, state, plugins=plugins)
    payload = "\n".join(links) + "\n"
    return base64.b64encode(payload.encode()).decode()


def generate_shadowrocket_sub(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
) -> str:
    """Build a base64 list with native Shadowrocket transport variants."""
    links: list[str] = []
    for link in _base_subscription_links(user, state, plugins=plugins):
        try:
            scheme = urllib.parse.urlsplit(link).scheme.lower()
        except ValueError:
            links.append(link)
            continue
        if scheme in {"naive+https", "naive+quic"}:
            links.extend(build_shadowrocket_naive_links(link))
            continue
        links.append(
            build_shadowrocket_snell_link(link)
            if scheme == "snell"
            else link
        )
    payload = "\n".join(links) + "\n"
    return base64.b64encode(payload.encode()).decode("ascii")
