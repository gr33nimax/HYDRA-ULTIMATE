"""Share-link and client-specific base64 subscription generation."""

from __future__ import annotations

import base64
import json
import urllib.parse

from hydra.contracts.vless_cdn import CLIENT_LABEL
from hydra.core.configuration_names import resolve_configuration_name
from hydra.core.state_models import AppState, User
from hydra.services.subscriptions.access import SubscriptionPluginAccess
from hydra.services.subscriptions.serialization import (
    clean_link_to_sn,
    generate_awg_sn_link,
)
from hydra.services.subscriptions.shadowrocket import (
    build_shadowrocket_awg_link,
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
                links.extend(link for link in plugins.client_links(plugin, user, state) if link)
        except Exception:
            continue
    return list(dict.fromkeys(links))


def _naive_uot_enabled(state: AppState) -> bool:
    """Read the Naive UoT setting.

    Central layers may not import concrete plugins, so the desired value is read
    from state; the plugin keeps ownership of its meaning and validation.
    """
    protocol = state.protocols.get("naive")
    if protocol is None or not protocol.config:
        return True
    return bool(protocol.config.get("uot", True))


def _vless_uplink_over_get(query: dict[str, list[str]]) -> bool:
    """VLESS за внешним CDN узнаётся по uplink через GET в блоке `extra`.

    Тип `xhttp` стоит и у обычного профиля, поэтому по одному ему два VLESS не
    различить — и оба получали одно имя, то есть в клиенте появлялся клон.
    Поле `uplinkHTTPMethod` не выставляет больше никто: это признак протокола, а не
    договорённость о подписи.
    """
    raw = query.get("extra", [""])[0]
    if not raw:
        return False
    try:
        extra = json.loads(raw)
    except ValueError:
        return False
    return isinstance(extra, dict) and bool(extra.get("uplinkHTTPMethod"))


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
        return "TrustTunnel QUIC" if query.get("alpn", ["h2"])[0] == "h3" else "TrustTunnel"
    if scheme == "mierus":
        return "Mieru"
    if scheme in ("hysteria2", "hy2"):
        return "Hysteria2"
    if scheme == "vless":
        query = urllib.parse.parse_qs(parsed.query)
        if _vless_uplink_over_get(query):
            return CLIENT_LABEL
        if query.get("type", [""])[0] == "xhttp":
            return "VLESS XHTTP"
        return "VLESS"
    if scheme == "snell":
        return "Snell"
    if scheme == "wg":
        return "AWG Mobile" if urllib.parse.unquote(parsed.fragment).endswith("AWG Mobile") else "AWG Desktop"
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
    if scheme == "vless" and _vless_uplink_over_get(query):
        # Свой ключ: общий с обычным VLESS ключ переопределение имени накрыло бы оба
        # профиля разом, и они снова стали бы неразличимы.
        return "vless:cdn"
    return {
        "naive": "naive:https",
        "naive+https": "naive:https",
        "naive+quic": "naive:quic",
        "anytls": "anytls",
        "tt": "trusttunnel",
        "trusttunnel": "trusttunnel",
        "mierus": "mieru",
        "hysteria2": "hysteria2",
        "hy2": "hysteria2",
        "vless": "vless",
        "snell": "snell",
        "trojan": "trojan",
        "wg": (
            "amneziawg:mobile" if urllib.parse.unquote(parsed.fragment).endswith("AWG Mobile") else "amneziawg:desktop"
        ),
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
            base_key=key.partition(":")[0] if ":" in key else "",
            base_suffix={
                "naive:quic": " QUIC",
                "amneziawg:desktop": " Desktop",
                "amneziawg:mobile": " Mobile",
                "vless:cdn": " CDN",
            }.get(key, ""),
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
    formatted = [tag_client_link(link, user, state) for link in generate_links(user, state, plugins=plugins)]
    links = [*formatted]
    links.extend(converted for link in formatted if (converted := clean_link_to_sn(link, user)))
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
    naive_uot = _naive_uot_enabled(state)
    for link in _base_subscription_links(user, state, plugins=plugins):
        try:
            parsed = urllib.parse.urlsplit(link)
            scheme = parsed.scheme.lower()
        except ValueError:
            links.append(link)
            continue
        if scheme in {"naive+https", "naive+quic"}:
            links.extend(build_shadowrocket_naive_links(link, uot=naive_uot))
            continue
        if scheme == "wg":
            links.append(build_shadowrocket_awg_link(link))
            continue
        if scheme == "vpn" or (scheme == "sn" and parsed.netloc.lower() == "awg"):
            # Official Amnezia and NekoBox-only AWG containers do not belong in a
            # Shadowrocket subscription alongside its complete ``wg://`` form.
            continue
        links.append(build_shadowrocket_snell_link(link) if scheme == "snell" else link)
    payload = "\n".join(links) + "\n"
    return base64.b64encode(payload.encode()).decode("ascii")
