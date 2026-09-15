"""Shadowrocket-native proxy link serialization."""

from __future__ import annotations

import base64
import json
import urllib.parse


_AWG_STANDARD_FIELDS = (
    ("public_key", "publicKey"),
    ("private_key", "privateKey"),
    ("pre_shared_key", "presharedKey"),
    ("local_address", "ip"),
    ("persistent_keepalive_interval", "keepalive"),
)
_AWG_OBFS_PARAM_FIELDS = (
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "header_protection_key",
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
    "max_handshake_attempts",
    "random_trailers",
    "disable_cookies",
)


def _raw_query_values(query: str) -> dict[str, str]:
    """Decode URI values without treating raw base64 ``+`` as a space."""
    values: dict[str, str] = {}
    for item in query.split("&"):
        key, separator, value = item.partition("=")
        if key:
            values.setdefault(
                urllib.parse.unquote(key),
                urllib.parse.unquote(value) if separator else "",
            )
    return values


def build_shadowrocket_https_link(link: str, *, uot: bool = True) -> str:
    """Convert a Naive HTTPS URI to Shadowrocket's HTTPS proxy scheme."""
    return _http_link(link, "https", uot=uot)


def build_shadowrocket_naive_links(link: str, *, uot: bool = True) -> list[str]:
    """Expose HTTP/1.1 and HTTP/2 for TCP, HTTP/3 for the QUIC transport."""
    scheme = urllib.parse.urlsplit(link).scheme.lower()
    if scheme == "naive+https":
        return [
            build_shadowrocket_https_link(link, uot=uot),
            _http_link(link, "http2", " HTTP/2", uot=uot),
        ]
    if scheme == "naive+quic":
        return [_http_link(link, "http3")]
    return [link]


def _http_link(
    link: str,
    scheme: str,
    suffix: str = "",
    *,
    uot: bool = True,
) -> str:
    try:
        parsed = urllib.parse.urlsplit(link)
        source_scheme = "naive+quic" if scheme == "http3" else "naive+https"
        if parsed.scheme.lower() != source_scheme:
            return link

        username = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")
        hostname = parsed.hostname or ""
        if not username or not hostname:
            return link
        port = parsed.port or 443
        host = f"[{hostname}]" if ":" in hostname else hostname
        credentials = f"{username}:{password}@{host}:{port}"
        encoded = (
            base64.urlsafe_b64encode(
                credentials.encode("utf-8"),
            )
            .decode("ascii")
            .rstrip("=")
        )
        remarks = urllib.parse.unquote(parsed.fragment) or "NaiveProxy"
        parameters = {
            "remarks": remarks + suffix,
            "padding": "1",
        }
        if scheme != "http3":
            # UoT is only offered while the server still serves it; TCP Fast Open is
            # independent of that choice.
            if uot:
                parameters["uot"] = "2"
            parameters["tfo"] = "1"
        query = urllib.parse.urlencode(
            parameters,
            quote_via=urllib.parse.quote,
        )
        return f"{scheme}://{encoded}?{query}"
    except (TypeError, ValueError):
        return link


def build_shadowrocket_awg_link(link: str) -> str:
    """Convert HYDRA's generic AWG URI into Shadowrocket's ``obfsParam`` form."""
    try:
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme.lower() != "wg":
            return link
        values = _raw_query_values(parsed.query)
        hostname = parsed.hostname or ""
        if not hostname or any(not values.get(key) for key in ("private_key", "public_key", "local_address")):
            return link
        if values.get("enable_amnezia", "").lower() != "true" and not any(
            values.get(key) for key in _AWG_OBFS_PARAM_FIELDS
        ):
            return link

        parameters = {target: values[source] for source, target in _AWG_STANDARD_FIELDS if values.get(source)}
        parameters["udp"] = "1"
        parameters["obfs"] = "amneziawg"
        obfs_param = {key: values[key] for key in _AWG_OBFS_PARAM_FIELDS if values.get(key) not in (None, "")}
        # A live Shadowrocket export writes these schema fields as strings even for AWG 2.0.
        obfs_param.setdefault("random_trailers", "false")
        obfs_param.setdefault("disable_cookies", "false")
        parameters["obfsParam"] = json.dumps(obfs_param, ensure_ascii=False, separators=(",", ":"))
        if values.get("flag"):
            parameters["flag"] = values["flag"]

        port = parsed.port or 51820
        host = f"[{hostname}]" if ":" in hostname else hostname
        tag = urllib.parse.quote(urllib.parse.unquote(parsed.fragment), safe="")
        query_text = urllib.parse.urlencode(parameters, quote_via=urllib.parse.quote)
        return f"wg://{host}:{port}?{query_text}#{tag}"
    except (TypeError, ValueError):
        return link


def build_shadowrocket_snell_link(link: str) -> str:
    """Convert the classic Snell pair into Shadowrocket's documented URI variants."""
    try:
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme.lower() != "snell":
            return link
        password = urllib.parse.unquote(parsed.username or "")
        hostname = parsed.hostname or ""
        if not password or not hostname:
            return link
        port = parsed.port or 443
        host = f"[{hostname}]" if ":" in hostname else hostname
        query = urllib.parse.parse_qs(parsed.query)
        version = query.get("version", ["4"])[0]
        if version != "4":
            # Shadowrocket imports the classic 5↔4 pair only. Generation 6 belongs to
            # sing-box, so preserve it instead of fabricating a link the client misreads.
            return link
        relay = query.get("udp-relay", query.get("udp", ["1"]))[0].lower()
        udp = "0" if relay in {"false", "0"} else "1"
        obfs_mode = query.get("obfs-mode", [""])[0].strip().lower()
        obfs_host = query.get("obfs-host", [""])[0].strip()
        if obfs_mode not in {"", "none", "http", "tls"} or (obfs_mode in {"http", "tls"} and not obfs_host):
            return link

        tag = urllib.parse.quote(urllib.parse.unquote(parsed.fragment), safe="")
        if obfs_mode in {"http", "tls"}:
            credentials = f"chacha20-ietf-poly1305:{password}"
            encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
            plugin_host = (
                json.dumps({"Host": obfs_host}, ensure_ascii=False, separators=(",", ":"))
                if obfs_mode == "tls"
                else obfs_host
            )
            parameters = {
                "plugin": f"obfs-local;obfs={obfs_mode};obfs-host={plugin_host};obfs-uri=/",
                "version": version,
                "udp": udp,
            }
            query_text = urllib.parse.urlencode(
                parameters,
                quote_via=urllib.parse.quote,
                safe=";/:",
            )
            return f"snell://{encoded}@{host}:{port}?{query_text}#{tag}"

        credentials = f"chacha20-ietf-poly1305:{password}@{host}:{port}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        query_text = urllib.parse.urlencode({"version": version, "udp": udp})
        return f"snell://{encoded}?{query_text}#{tag}"
    except (TypeError, ValueError):
        return link


__all__ = [
    "build_shadowrocket_awg_link",
    "build_shadowrocket_https_link",
    "build_shadowrocket_naive_links",
    "build_shadowrocket_snell_link",
]
