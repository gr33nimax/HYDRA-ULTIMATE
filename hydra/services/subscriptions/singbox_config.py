"""Assemble sing-box subscriptions from local plugins and published node exports."""
from __future__ import annotations

import json

from hydra.core.configuration_names import _replace_profile_reference
from hydra.core.state_models import AppState, User
from hydra.services.subscriptions.access import SubscriptionPluginAccess
from hydra.services.subscriptions.node_exports import (
    ManagedNodeProfileReader,
    node_profiles_for_user,
)


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


def _merge_document(
    config: dict,
    plugin_config: dict,
    outbound_tags: set[str],
    endpoint_tags: set[str],
    selected_outbound: str,
) -> str:
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
    return selected_outbound


def generate_singbox_config(
    user: User,
    state: AppState,
    *,
    plugins: SubscriptionPluginAccess,
    node_exports: ManagedNodeProfileReader | None = None,
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
            selected_outbound = _merge_document(
                config,
                json.loads(payload),
                outbound_tags,
                endpoint_tags,
                selected_outbound,
            )
        except Exception:
            continue

    for profile in node_profiles_for_user(user, state, node_exports=node_exports):
        for document in profile.singbox:
            try:
                selected_outbound = _merge_document(
                    config,
                    document,
                    outbound_tags,
                    endpoint_tags,
                    selected_outbound,
                )
            except Exception:
                continue

    if not config["endpoints"]:
        config.pop("endpoints")
    if "direct" not in outbound_tags:
        config["outbounds"].append({"type": "direct", "tag": "direct"})
    if selected_outbound:
        config["route"]["final"] = selected_outbound
    return config


__all__ = ["generate_singbox_config"]
