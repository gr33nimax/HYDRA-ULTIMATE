"""Subscription URLs, negotiation metadata, and access checks."""
from __future__ import annotations

import urllib.parse
from datetime import datetime

from hydra.core.state_models import AppState, User
from hydra.services.user_access import (
    access_status as get_user_access_status,
    entitlement_status as get_user_entitlement_status,
)


SUPPORTED_SUBSCRIPTION_FORMATS = {
    "base64",
    "nekobox",
    "shadowrocket",
    "throne",
    "singbox",
    "sing-box",
    "json",
    "hydrabox",
}


def resolve_subscription_format(
    requested: str | None,
    user_agent: str = "",
) -> str:
    """Resolve an explicit format or negotiate a client-specific subscription."""
    if requested:
        normalized = requested.lower()
        if normalized not in ("auto", "default"):
            return normalized

    ua = user_agent.lower()
    if "nekobox/android" in ua or "nekobox" in ua:
        return "nekobox"
    if "shadowrocket" in ua:
        return "shadowrocket"
    if "throne" in ua:
        return "throne"
    return "base64"


def generate_userinfo_header(user: User, state: AppState) -> str:
    """Build the standard traffic and expiry response header."""
    del state
    download = user.traffic_used_bytes
    total = int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0
    expire = 0
    if user.expiry_date:
        try:
            value = user.expiry_date
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            expire = int(datetime.fromisoformat(value).timestamp())
        except (TypeError, ValueError):
            pass
    return f"upload=0; download={download}; total={total}; expire={expire}"


def get_subscription_url(user: User, state: AppState) -> str:
    """Return a canonical HTTPS subscription URL."""
    token = urllib.parse.quote(str(user.uuid), safe="")
    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        return f"https://{sub_domain}/sub/{token}"

    from hydra.utils.net import public_ip

    host = state.network.domain or state.network.server_ip or public_ip()
    return f"https://{host}:9443/sub/{token}"


def get_subscription_urls(user: User, state: AppState) -> dict[str, str]:
    """Return canonical client-specific URLs."""
    base = get_subscription_url(user, state)

    def with_format(value: str) -> str:
        separator = "&" if "?" in base else "?"
        encoded = urllib.parse.quote(value, safe="")
        return f"{base}{separator}format={encoded}"

    hydrabox_url = with_format("hydrabox")
    if user.hydrabox_jwe_key:
        hydrabox_url = f"{hydrabox_url}#hbx-key={user.hydrabox_jwe_key}"
    return {
        "auto": base,
        "nekobox": with_format("nekobox"),
        "shadowrocket": with_format("shadowrocket"),
        "throne": with_format("throne"),
        "singbox": with_format("singbox"),
        "hydrabox": hydrabox_url,
    }


def is_user_valid(user: User, state: AppState) -> bool:
    """Check whether the user may download a subscription."""
    del state
    valid, _ = get_user_access_status(user)
    return valid
