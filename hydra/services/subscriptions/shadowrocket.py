"""Shadowrocket-native proxy link serialization."""
from __future__ import annotations

import base64
import urllib.parse


def build_shadowrocket_https_link(link: str) -> str:
    """Convert a Naive HTTPS URI to Shadowrocket's HTTPS proxy scheme."""
    try:
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme.lower() != "naive+https":
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
        return (
            f"https://{encoded}?remarks="
            f"{urllib.parse.quote(remarks, safe='')}"
        )
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
        version = "4"
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
        query_text = urllib.parse.urlencode({
            "version": version,
            "udp-relay": relay,
        })
        return f"snell://{encoded}?{query_text}#{tag}"
    except (TypeError, ValueError):
        return link


__all__ = [
    "build_shadowrocket_https_link",
    "build_shadowrocket_snell_link",
]
