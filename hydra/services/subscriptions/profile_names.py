"""Display names for multi-profile subscription transports."""
from __future__ import annotations

import hashlib
import re
from typing import Any

from hydra.core.configuration_names import resolve_configuration_name
from hydra.core.state_models import AppState, User


def hydrabox_profile_id(plugin_name: str, section: str, tag: str) -> str:
    prefix = re.sub(r"[^A-Za-z0-9._:-]+", "-", plugin_name).strip("-._:")
    prefix = prefix or "profile"
    digest = hashlib.sha256(f"{section}\0{tag}".encode()).hexdigest()[:16]
    return f"{prefix[:110]}-{digest}"


def hydrabox_resource_id(plugin_name: str) -> str:
    prefix = re.sub(r"[^A-Za-z0-9._:-]+", "-", plugin_name).strip("-._:")
    prefix = prefix or "transport"
    digest = hashlib.sha256(plugin_name.encode()).hexdigest()[:12]
    return f"resource-{prefix[:106]}-{digest}"


def hydrabox_profile_name(
    plugin_name: str,
    section: str,
    tag: str,
    objects: list[tuple[str, dict[str, Any]]],
    default: str,
    multiple: bool,
    state: AppState,
    user: User,
) -> str:
    item = next(
        item
        for object_section, item in objects
        if object_section == section and item["tag"] == tag
    )
    suffix = ""
    if plugin_name in {"naive", "trusttunnel"}:
        quic = item.get("quic") is True
        variant = "quic" if quic else ("https" if plugin_name == "naive" else "tcp")
        suffix = " QUIC" if quic else ""
    elif plugin_name == "amneziawg" and section == "endpoints":
        variant = next(
            (name for name in ("desktop", "mobile") if f"-{name}-" in tag),
            "",
        )
        suffix = f" {variant.title()}" if variant else ""
    else:
        variant = ""
    if not variant:
        return f"{default} — {tag}" if multiple else default
    return resolve_configuration_name(
        key=f"{plugin_name}:{variant}",
        default=default + suffix,
        global_names=state.configuration_names,
        user_names=user.configuration_name_overrides,
        base_key=plugin_name,
        base_suffix=suffix,
    )


__all__ = [
    "hydrabox_profile_id",
    "hydrabox_profile_name",
    "hydrabox_resource_id",
]
