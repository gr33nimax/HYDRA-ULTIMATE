"""Build node-local client material through the existing transport owners."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from hydra.contracts.managed_node_models import ProtocolAssignment, UserAssignment, canonical_digest
from hydra.contracts.managed_node_observations import ConfirmedProfile
from hydra.core.state_models import AppState, User
from hydra.services.user_access import access_status


def expected_profile_pairs(
    users: Iterable[User | UserAssignment],
    protocols: Iterable[ProtocolAssignment],
) -> set[tuple[str, str]]:
    selected = list(protocols)
    pairs: set[tuple[str, str]] = set()
    for user in users:
        allowed = not user.blocked if isinstance(user, UserAssignment) else access_status(user)[0]
        if not allowed:
            continue
        pairs.update(
            (user.uuid, protocol.name)
            for protocol in selected
            if protocol.name not in user.disabled_protocols
        )
    return pairs


def expected_profile_users(pairs: Iterable[tuple[str, str]]) -> set[str]:
    return {user_id for user_id, _protocol in pairs}


class ManagedNodeProfileBuilder:
    """Export only configured, entitled users using canonical plugin APIs."""

    def __init__(self, *, protocols: Any) -> None:
        self._protocols = protocols

    def build(self, state: AppState, node_id: str) -> list[ConfirmedProfile]:
        profiles: list[ConfirmedProfile] = []
        for user in state.users:
            if not access_status(user)[0]:
                continue
            for name, desired in state.protocols.items():
                plugin = self._protocols.get(name)
                if (
                    name in user.disabled_protocols or plugin is None
                    or not desired.enabled or not plugin.meta.capabilities.subscription_enabled
                ):
                    continue
                try:
                    profiles.extend(self._plugin_profiles(state, node_id, user, name))
                except Exception:
                    # A plugin error cannot turn another transport's verified export into a failure.
                    continue
        return profiles

    def _plugin_profiles(
        self,
        state: AppState,
        node_id: str,
        user: User,
        protocol: str,
    ) -> list[ConfirmedProfile]:
        definitions = self._protocols.client_profiles(state, protocol)
        if definitions:
            result: list[ConfirmedProfile] = []
            for definition in definitions:
                profile_name = definition.get("name") if isinstance(definition, dict) else None
                if not isinstance(profile_name, str) or not profile_name:
                    continue
                result.append(self._one_profile(state, node_id, user, protocol, profile_name))
            return result
        return [self._one_profile(state, node_id, user, protocol, "")]

    def _one_profile(
        self,
        state: AppState,
        node_id: str,
        user: User,
        protocol: str,
        profile: str,
    ) -> ConfirmedProfile:
        parameters = {"profile": profile} if profile else {}
        links = self._protocols.client_links(state, protocol, user, **parameters)
        client_configs = self._client_documents(state, protocol, user, parameters)
        stable_id = canonical_digest({
            "node_id": node_id,
            "user_uuid": user.uuid,
            "protocol": protocol,
            "profile": profile,
        })
        return ConfirmedProfile(
            stable_id=stable_id,
            user_uuid=user.uuid,
            protocol=protocol,
            route_id=profile or "direct",
            links=[link for link in links if isinstance(link, str) and link],
            client_configs=client_configs,
        )

    def _client_documents(
        self,
        state: AppState,
        protocol: str,
        user: User,
        parameters: dict[str, str],
    ) -> list[dict[str, Any]]:
        documents: list[dict[str, Any]] = []
        sources = [self._protocols.client_config(state, protocol, user, **parameters)]
        sources.append(self._protocols.singbox_client_config(state, protocol, user))
        for source in sources:
            try:
                document = json.loads(source)
            except (TypeError, ValueError):
                continue
            if isinstance(document, dict) and document not in documents:
                documents.append(document)
        return documents


__all__ = ["ManagedNodeProfileBuilder", "expected_profile_pairs", "expected_profile_users"]
