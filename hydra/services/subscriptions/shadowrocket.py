"""Shadowrocket-native proxy link serialization."""
from __future__ import annotations

import base64
import urllib.parse


def build_shadowrocket_https_link(link: str) -> str:
    """Convert a Naive HTTPS URI to Shadowrocket's HTTPS proxy scheme."""
    return _http_link(link, "https")


def build_shadowrocket_naive_links(link: str) -> list[str]:
    """Expose HTTP/1.1 and HTTP/2 for TCP, HTTP/3 for the QUIC transport."""
    scheme = urllib.parse.urlsplit(link).scheme.lower()
    if scheme == "naive+https":
        return [
            build_shadowrocket_https_link(link),
            _http_link(link, "http2", " HTTP/2"),
        ]
    if scheme == "naive+quic":
        return [_http_link(link, "http3")]
    return [link]


def _http_link(link: str, scheme: str, suffix: str = "") -> str:
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
        encoded = base64.urlsafe_b64encode(
            credentials.encode("utf-8"),
        ).decode("ascii").rstrip("=")
        remarks = urllib.parse.unquote(parsed.fragment) or "NaiveProxy"
        parameters = {
            "remarks": remarks + suffix,
            "padding": "1",
        }
        if scheme != "http3":
            parameters.update({"uot": "2", "tfo": "1"})
        query = urllib.parse.urlencode(
            parameters,
            quote_via=urllib.parse.quote,
        )
        return f"{scheme}://{encoded}?{query}"
    except (TypeError, ValueError):
        return link


def build_shadowrocket_snell_link(link: str) -> str:
    """Convert Snell's PSK URI to Shadowrocket's cipher/password form."""
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
        credentials = f"chacha20-ietf-poly1305:{password}@{host}:{port}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        query = urllib.parse.parse_qs(parsed.query)
        version = query.get("version", ["4"])[0]
        if version != "4":
            # Shadowrocket imports the classic pair only — a client-side 4 against a
            # version 5 server. A generation 6 profile belongs to sing-box, so the link
            # is passed through instead of being rewritten into one the client cannot use.
            return link
        relay = {"true": "1", "false": "0"}.get(
            query.get("udp-relay", ["1"])[0].lower(),
            query.get("udp-relay", ["1"])[0],
        )
        if relay not in {"0", "1", "2"}:
            relay = "1"
        tag = urllib.parse.quote(
            urllib.parse.unquote(parsed.fragment),
            safe="",
        )
        parameters = {
            "version": version,
            "udp-relay": relay,
        }
        for key in ("obfs-mode", "obfs-host"):
            if key in query:
                parameters[key] = query[key][0]
        query_text = urllib.parse.urlencode(parameters)
        return f"snell://{encoded}?{query_text}#{tag}"
    except (TypeError, ValueError):
        return link


__all__ = [
    "build_shadowrocket_https_link",
    "build_shadowrocket_naive_links",
    "build_shadowrocket_snell_link",
]
