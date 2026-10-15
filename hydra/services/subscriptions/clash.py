"""Mihomo/FlClash profiles from existing, user-scoped transport share links."""

from __future__ import annotations

import json
import urllib.parse

from hydra.core.state_models import AppState, User
from hydra.services.subscriptions.access import SubscriptionPluginAccess
from hydra.services.subscriptions.links import _base_subscription_links
from hydra.services.subscriptions.node_exports import ManagedNodeProfileReader


_XHTTP_FIELDS = {
    "headers": "headers",
    "noGRPCHeader": "no-grpc-header",
    "xPaddingBytes": "x-padding-bytes",
    "xPaddingObfsMode": "x-padding-obfs-mode",
    "xPaddingKey": "x-padding-key",
    "xPaddingHeader": "x-padding-header",
    "xPaddingPlacement": "x-padding-placement",
    "xPaddingMethod": "x-padding-method",
    "uplinkHTTPMethod": "uplink-http-method",
    "sessionIDPlacement": "session-placement",
    "sessionIDKey": "session-key",
    "sessionIDTable": "session-table",
    "sessionIDLength": "session-length",
    "seqPlacement": "seq-placement",
    "seqKey": "seq-key",
    "uplinkDataPlacement": "uplink-data-placement",
    "uplinkDataKey": "uplink-data-key",
    "scMaxEachPostBytes": "sc-max-each-post-bytes",
    "scMinPostsIntervalMs": "sc-min-posts-interval-ms",
}


def _transport(query: dict[str, list[str]]) -> dict:
    network = query.get("type", ["tcp"])[0]
    if network == "tcp":
        return {}
    if network == "ws":
        options: dict = {"path": query.get("path", ["/"])[0]}
        if query.get("host"):
            options["headers"] = {"Host": query["host"][0]}
    elif network == "grpc":
        options = {"grpc-service-name": query.get("serviceName", [""])[0]}
    elif network == "xhttp":
        options = {key: query[key][0] for key in ("path", "host", "mode") if key in query}
        try:
            extra = json.loads(query.get("extra", ["{}"])[0])
        except (TypeError, ValueError) as exc:
            raise ValueError("Unsupported XHTTP options") from exc
        if not isinstance(extra, dict) or extra.keys() - _XHTTP_FIELDS.keys():
            raise ValueError("Unsupported XHTTP options")
        # Stock Mihomo does not promise Hydra's GET-uplink CDN dialect.
        if extra.get("uplinkHTTPMethod", "POST") not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("Unsupported XHTTP uplink method")
        options.update({_XHTTP_FIELDS[key]: value for key, value in extra.items()})
    else:
        raise ValueError("Unsupported transport")
    return {"network": network, f"{network}-opts": options}


def _proxy(link: str) -> dict | None:
    parsed = urllib.parse.urlsplit(link)
    scheme = parsed.scheme.lower()
    if scheme not in {"vless", "trojan", "hysteria2", "hy2", "anytls"}:
        return None
    query = urllib.parse.parse_qs(parsed.query)
    if query.get("plugin"):
        return None  # ShadowTLS's inner Trojan is not a standalone Trojan server.
    if not parsed.hostname or parsed.username is None:
        raise ValueError("Missing endpoint or credentials")
    protocol = "hysteria2" if scheme == "hy2" else scheme
    proxy = {
        "name": urllib.parse.unquote(parsed.fragment) or protocol,
        "type": protocol,
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "udp": True,
    }
    if not 1 <= proxy["port"] <= 65535:
        raise ValueError("Invalid port")
    credential = urllib.parse.unquote(parsed.username)
    if not credential:
        raise ValueError("Empty credentials")
    proxy["uuid" if scheme == "vless" else "password"] = credential
    security = query.get("security", ["none" if scheme == "vless" else "tls"])[0]
    if security not in {"none", "tls", "reality"}:
        raise ValueError("Unsupported security")
    if scheme in {"vless", "trojan"}:
        proxy.update(_transport(query))
        proxy["tls"] = security != "none"
        if query.get("flow"):
            proxy["flow"] = query["flow"][0]
        encryption = query.get("encryption", ["none"])[0]
        if scheme == "vless" and encryption != "none":
            proxy["encryption"] = encryption
    if query.get("sni"):
        proxy["servername" if scheme in {"vless", "trojan"} else "sni"] = query["sni"][0]
    if query.get("alpn"):
        proxy["alpn"] = query["alpn"][0].split(",")
    if query.get("fp"):
        proxy["client-fingerprint"] = query["fp"][0]
    if query.get("insecure", query.get("allowInsecure", ["0"]))[0].lower() in {"1", "true"}:
        proxy["skip-cert-verify"] = True
    if security == "reality":
        proxy["reality-opts"] = {"public-key": query["pbk"][0], "short-id": query.get("sid", [""])[0]}
    if protocol == "hysteria2" and query.get("obfs"):
        if query["obfs"][0] != "salamander":
            raise ValueError("Unsupported obfuscation")
        proxy["obfs"] = "salamander"
        proxy["obfs-password"] = query["obfs-password"][0]
    return proxy


def generate_clash_config(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
    node_exports: ManagedNodeProfileReader | None = None,
) -> dict:
    """Return a full Clash config; never turn an unsupported profile into DIRECT."""
    proxies = []
    reserved = {"HYDRA", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
    links = _base_subscription_links(user, state, plugins=plugins, node_exports=node_exports)
    for link in dict.fromkeys(links):
        try:
            proxy = _proxy(link)
        except (ValueError, TypeError, KeyError):
            continue
        if proxy is None:
            continue
        name = proxy["name"]
        number = 2
        while proxy["name"] in reserved:
            proxy["name"] = f"{name} ({number})"
            number += 1
        reserved.add(proxy["name"])
        proxies.append(proxy)
    if not proxies:
        raise ValueError("No compatible Clash profiles")
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "proxies": proxies,
        "proxy-groups": [{"name": "HYDRA", "type": "select", "proxies": [proxy["name"] for proxy in proxies]}],
        "rules": ["MATCH,HYDRA"],
    }
