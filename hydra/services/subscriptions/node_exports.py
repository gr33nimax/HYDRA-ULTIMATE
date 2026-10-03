"""Read locally confirmed managed-node profiles for ordinary subscriptions."""

from __future__ import annotations

import copy
import hashlib
import json
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from hydra.contracts.managed_node_observations import ConfirmedProfiles
from hydra.core.configuration_names import (
    apply_json_configuration_name,
    configuration_name_key,
    resolve_configuration_name,
)
from hydra.core.state_managed_nodes import managed_nodes_from_extensions
from hydra.core.state_models import AppState, User
from hydra.services.managed_nodes.profile_store import ManagedNodeProfileStore
from hydra.services.user_access import access_status


@dataclass(frozen=True)
class NodeSubscriptionProfile:
    node_id: str
    protocol: str
    profile: str
    name: str
    name_key: str
    links: tuple[str, ...]
    singbox: tuple[dict[str, Any], ...]


class ManagedNodeProfileReader(Protocol):
    def profiles_for_user(self, user: User, state: AppState) -> tuple[NodeSubscriptionProfile, ...]: ...


class ManagedNodeSubscriptionReader:
    """Verify a protected local bundle against its committed apply receipt."""

    def __init__(self, *, profile_store: ManagedNodeProfileStore) -> None:
        self._profile_store = profile_store

    def profiles_for_user(self, user: User, state: AppState) -> tuple[NodeSubscriptionProfile, ...]:
        if not access_status(user)[0]:
            return ()
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        committed = {
            operation.id: operation.receipt
            for operation in namespace.operations
            if operation.state == "succeeded" and operation.receipt is not None
        }
        removal_pending = {
            operation.target_id
            for operation in namespace.operations
            if operation.kind == "remove" and operation.state != "succeeded"
        }
        profiles: list[NodeSubscriptionProfile] = []
        for definition in namespace.definitions:
            if definition.id in removal_pending:
                continue
            bundle = self._profile_store.read(
                definition.id,
                receipt_is_committed=lambda candidate: committed.get(candidate.receipt.operation_id) == candidate.receipt,
            )
            if bundle is None:
                continue
            profiles.extend(_profiles_for_bundle(user, state, definition, bundle))
        return tuple(profiles)


def node_profile_name_key(node_id: str, protocol: str, profile: str) -> str:
    identity = f"{node_id}\0{protocol}\0{profile}".encode("utf-8")
    return f"node:{hashlib.sha256(identity).hexdigest()}"


def node_profiles_for_user(
    user: User,
    state: AppState,
    *,
    node_exports: ManagedNodeProfileReader | None,
    on_error: Callable[[str, str], None] | None = None,
) -> tuple[NodeSubscriptionProfile, ...]:
    """Merge only current-user entries from verified immutable local bundles."""
    if node_exports is None:
        return ()
    try:
        return node_exports.profiles_for_user(user, state)
    except Exception as exc:
        if on_error is not None:
            on_error("managed_nodes", type(exc).__name__)
        return ()


def _profiles_for_bundle(user: User, state: AppState, definition: object, bundle: ConfirmedProfiles) -> list[NodeSubscriptionProfile]:
    from hydra.contracts.managed_node_models import NodeDefinition

    if not isinstance(definition, NodeDefinition) or bundle.node_id != definition.id:
        return []
    result: list[NodeSubscriptionProfile] = []
    for profile in bundle.profiles:
        if profile.user_uuid != user.uuid or profile.protocol in user.disabled_protocols:
            continue
        key = node_profile_name_key(definition.id, profile.protocol, profile.route_id)
        default = f"{definition.name} · {profile.protocol}" + (f" · {profile.route_id}" if profile.route_id != "direct" else "")
        name = resolve_configuration_name(
            key=key,
            default=default,
            global_names=state.configuration_names,
            user_names=user.configuration_name_overrides,
        )
        singbox = tuple(_named_config(document, key=key, name=name, user=user, state=state) for document in profile.client_configs)
        links = tuple(_tag_link(link, name) for link in profile.links)
        result.append(NodeSubscriptionProfile(definition.id, profile.protocol, profile.route_id, name, key, links, singbox))
    return result


def _named_config(document: dict[str, Any], *, key: str, name: str, user: User, state: AppState) -> dict[str, Any]:
    copied = copy.deepcopy(document)
    payload = apply_json_configuration_name(
        json.dumps(copied, ensure_ascii=False),
        key=key,
        global_names={key: name},
        user_names=user.configuration_name_overrides,
    )
    try:
        result = json.loads(payload)
    except (TypeError, ValueError):
        return copied
    return result if isinstance(result, dict) else copied


def _tag_link(link: str, name: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme.casefold() in {"tt", "trusttunnel"}:
            return link
        return urllib.parse.urlunsplit(parsed._replace(fragment=urllib.parse.quote(name, safe="")))
    except ValueError:
        return link


__all__ = [
    "ManagedNodeProfileReader",
    "ManagedNodeSubscriptionReader",
    "NodeSubscriptionProfile",
    "node_profile_name_key",
    "node_profiles_for_user",
]
