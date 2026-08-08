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


__all__ = ["build_shadowrocket_https_link"]
