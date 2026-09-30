"""Read already-published node client material for subscription rendering."""
from __future__ import annotations

import copy
import hashlib
import json
import urllib.parse
from dataclasses import dataclass
from typing import Any, Protocol

from hydra.contracts.node_export import NodeClientExport
from hydra.core.configuration_names import (
    apply_json_configuration_name,
    configuration_name_key,
    resolve_configuration_name,
)
from hydra.core.state_models import AppState, User


class PublishedNodeExportReader(Protocol):
    """Narrow, local-only read port; subscription requests never contact nodes."""

    def published_export(self, state: AppState, node_id: str) -> NodeClientExport | None: ...


@dataclass(frozen=True)
class NodeSubscriptionProfile:
    node_id: str
    protocol: str
    profile: str
    name: str
    name_key: str
    links: tuple[str, ...]
    singbox: tuple[dict[str, Any], ...]


def node_profile_name_key(node_id: str, protocol: str, profile: str) -> str:
    """Stable user-override key that stays within the persisted key-length limit."""
    identity = f"{node_id}\0{protocol}\0{profile}".encode("utf-8")
    return f"node:{hashlib.sha256(identity).hexdigest()}"


def node_profiles_for_user(
    user: User,
    state: AppState,
    *,
    node_exports: PublishedNodeExportReader | None,
) -> tuple[NodeSubscriptionProfile, ...]:
    """Resolve confirmed local exports and display names for one subscription user."""
    if node_exports is None:
        return ()

    result: list[NodeSubscriptionProfile] = []
    for node in state.nodes:
        if node.published_generation <= 0 or not node.published_digest:
            continue
        export = node_exports.published_export(state, node.id)
        if export is None:
            continue
        export.validate()
        if export.node_id != node.id or export.generation != node.published_generation:
            raise ValueError(f"published export identity mismatch for node {node.id}")
        exported_user = export.users.get(user.uuid)
        if exported_user is None:
            continue

        for profile in exported_user.profiles:
            profile_key = configuration_name_key(
                profile.protocol,
                {"profile": profile.profile},
            )
            name_key = node_profile_name_key(node.id, profile.protocol, profile.profile)
            default = _default_profile_name(node, profile.protocol, profile.profile)
            node_name = node.profile_names.get(profile_key, default)
            name = resolve_configuration_name(
                key=name_key,
                default=default,
                global_names={name_key: node_name},
                user_names=user.configuration_name_overrides,
            )
            singbox = tuple(
                _named_singbox_document(document, name_key=name_key, name=name)
                for document in profile.singbox
            )
            result.append(
                NodeSubscriptionProfile(
                    node_id=node.id,
                    protocol=profile.protocol,
                    profile=profile.profile,
                    name=name,
                    name_key=name_key,
                    links=tuple(_tag_node_link(link, name) for link in profile.links),
                    singbox=singbox,
                ),
            )
    return tuple(result)


def _default_profile_name(node, protocol: str, profile: str) -> str:
    region = node.region or node.name or node.id
    suffix = f" · {profile}" if profile else ""
    return f"{region} · {protocol}{suffix}"


def _tag_node_link(link: str, name: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme.casefold() in {"tt", "trusttunnel"}:
            return link
        return urllib.parse.urlunsplit(
            parsed._replace(fragment=urllib.parse.quote(name, safe="")),
        )
    except ValueError:
        return link


def _named_singbox_document(
    document: dict[str, Any],
    *,
    name_key: str,
    name: str,
) -> dict[str, Any]:
    copied = copy.deepcopy(document)
    payload = apply_json_configuration_name(
        json.dumps(copied, ensure_ascii=False),
        key=name_key,
        global_names={name_key: name},
        user_names={},
    )
    try:
        named = json.loads(payload)
    except (TypeError, ValueError):
        return copied
    return named if isinstance(named, dict) else copied


__all__ = [
    "NodeSubscriptionProfile",
    "PublishedNodeExportReader",
    "node_profile_name_key",
    "node_profiles_for_user",
]
