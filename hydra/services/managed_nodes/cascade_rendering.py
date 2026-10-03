"""State-aware scoped VLESS/AnyTLS contexts for the canonical config renderer."""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from hydra.contracts import ConfigFragment, RuntimeRenderContributions, RuntimeSubject
from hydra.contracts.managed_node_cascade import CascadeParticipantRequest
from hydra.contracts.managed_node_models import CascadeDefinition, canonical_digest
from hydra.contracts.managed_node_probe import ProbeMaterial
from hydra.core.state_managed_nodes import managed_nodes_from_extensions
from hydra.core.state_models import AppState, User
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.managed_nodes.cascade_leases import (
    assert_cascade_unleased,
    cascade_candidate,
    cascade_participants,
    operation_is_active,
)
from hydra.services.managed_nodes.cascade_preparation import CascadeTechnicalPreparation
from hydra.services.managed_nodes.cascade_restore import CascadeRestoreContext
from hydra.services.managed_nodes.cascade_render_capture import capture_cascade_scope
from hydra.services.user_access import access_status
from hydra.utils.crypto import derive_hex_key

_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROTOCOLS = frozenset({"vless", "anytls"})


@dataclass(frozen=True)
class CascadeRenderPermit:
    """Receipt-bound, operation-scoped evidence required before route rendering."""

    cascade_id: str
    entry_id: str
    exit_id: str
    protocol: str
    operation_id: str
    entry_engine_sha256: str
    exit_engine_sha256: str
    entry_auth_user_proof_sha256: str
    exit_auth_user_proof_sha256: str
    entry_receipt_sha256: str
    exit_receipt_sha256: str
    path_proof_sha256: str

    def validate(self, route: CascadeDefinition, protocol: str) -> None:
        route.validate()
        if (
            self.cascade_id != route.id
            or self.entry_id != route.entry_id
            or self.exit_id != route.exit_id
            or self.protocol != protocol
            or protocol not in _PROTOCOLS
        ):
            raise ValueError("cascade render evidence is bound to a different route")
        if not isinstance(self.operation_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
            self.operation_id,
        ):
            raise ValueError("cascade render operation receipt is invalid")
        for digest in (
            self.entry_engine_sha256,
            self.exit_engine_sha256,
            self.entry_auth_user_proof_sha256,
            self.exit_auth_user_proof_sha256,
            self.entry_receipt_sha256,
            self.exit_receipt_sha256,
            self.path_proof_sha256,
        ):
            if not isinstance(digest, str) or not _HEX_SHA256.fullmatch(digest):
                raise ValueError("cascade render proof is invalid")

    def engines_match(self, current: Mapping[str, str]) -> bool:
        return (
            current.get(self.entry_id) == self.entry_engine_sha256
            and current.get(self.exit_id) == self.exit_engine_sha256
        )


@dataclass(frozen=True, repr=False)
class CascadePeerMaterial:
    """One receipt-bound canonical exit outbound; its credential stays private."""

    cascade_id: str
    exit_id: str
    protocol: str
    operation_id: str
    user_uuid: str = field(repr=False)
    receipt_sha256: str
    client_outbound: dict[str, Any] = field(repr=False)

    def validate_for(
        self,
        route: CascadeDefinition,
        protocol: str,
        business_user: User,
        transit_user: User,
        permit: CascadeRenderPermit,
    ) -> None:
        if (
            self.cascade_id != route.id
            or self.exit_id != route.exit_id
            or self.protocol != protocol
            or self.operation_id != permit.operation_id
            or self.user_uuid != business_user.uuid
            or self.receipt_sha256 != permit.exit_receipt_sha256
        ):
            raise ValueError("cascade peer material is not bound to its participant receipt")
        try:
            ProbeMaterial(protocol, self.client_outbound).validate()
        except ValueError as exc:
            raise ValueError("cascade peer material is invalid") from exc
        expected = transit_user.uuid if protocol == "vless" else derive_hex_key("anytls-pass", transit_user.uuid)
        credential_key = "uuid" if protocol == "vless" else "password"
        if self.client_outbound.get(credential_key) != expected:
            raise ValueError("cascade peer credential does not match its scoped transit subject")

    def __repr__(self) -> str:
        return "CascadePeerMaterial(<protected>)"


@dataclass(frozen=True, repr=False)
class CascadeTechnicalPeerMaterial:
    """Scoped technical-only client outbound received from the frozen exit."""

    cascade_id: str
    entry_id: str
    exit_id: str
    participant_id: str
    role: str
    protocol: str
    operation_id: str
    plan_digest: str
    engine_identity: str
    prepared_config_identity: str
    client_outbound: dict[str, Any] = field(repr=False)

    def validate_for(
        self,
        preparation: CascadeTechnicalPreparation,
        transit_user: User,
    ) -> None:
        route = preparation.route
        if (
            self.cascade_id != route.id
            or self.entry_id != route.entry_id
            or self.exit_id != route.exit_id
            or self.participant_id != route.exit_id
            or self.role != "transit"
            or self.protocol != preparation.protocol
            or self.operation_id != preparation.operation_id
            or self.plan_digest != preparation.plan_digest
            or not isinstance(self.engine_identity, str)
            or not _HEX_SHA256.fullmatch(self.engine_identity)
            or not isinstance(self.prepared_config_identity, str)
            or not _HEX_SHA256.fullmatch(self.prepared_config_identity)
        ):
            raise ValueError("cascade technical peer material is bound to another preparation")
        try:
            ProbeMaterial(self.protocol, self.client_outbound).validate()
        except ValueError as exc:
            raise ValueError("cascade technical peer material is invalid") from exc
        expected = transit_user.uuid if self.protocol == "vless" else derive_hex_key("anytls-pass", transit_user.uuid)
        key = "uuid" if self.protocol == "vless" else "password"
        if self.client_outbound.get(key) != expected:
            raise ValueError("cascade technical peer credential does not match its transit identity")

    def __repr__(self) -> str:
        return "CascadeTechnicalPeerMaterial(<protected>)"


PermitProvider = Callable[
    [AppState, CascadeDefinition, str],
    CascadeRenderPermit | None,
]
EngineFingerprintsProvider = Callable[
    [AppState, CascadeDefinition],
    Mapping[str, str] | None,
]
PeerMaterialProvider = Callable[
    [AppState, CascadeDefinition, str, User, User, CascadeRenderPermit],
    CascadePeerMaterial | None,
]
TechnicalPreparationProvider = Callable[[AppState], tuple[CascadeTechnicalPreparation, ...]]
TechnicalPeerMaterialProvider = Callable[
    [AppState, CascadeTechnicalPreparation, User],
    CascadeTechnicalPeerMaterial | None,
]
RestoreContextProvider = Callable[[AppState], tuple[CascadeRestoreContext, ...]]


class ManagedNodeCascadeRenderer:
    """Contribute only entitled, proven contexts from the AppState being rendered."""

    def __init__(
        self,
        *,
        participant_id: str,
        credentials: CascadeCredentialStore,
        permit_provider: PermitProvider | None = None,
        engine_fingerprints_provider: EngineFingerprintsProvider | None = None,
        peer_material_provider: PeerMaterialProvider | None = None,
        technical_preparation_provider: TechnicalPreparationProvider | None = None,
        technical_peer_material_provider: TechnicalPeerMaterialProvider | None = None,
        restore_context_provider: RestoreContextProvider | None = None,
    ) -> None:
        if not isinstance(participant_id, str) or not re.fullmatch(
            r"(?:base|[A-Za-z0-9][A-Za-z0-9._-]{0,63})",
            participant_id,
        ):
            raise ValueError("cascade render participant identity is invalid")
        self._participant_id = participant_id
        self._credentials = credentials
        self._permit_provider = permit_provider
        self._engine_fingerprints_provider = engine_fingerprints_provider
        self._peer_material_provider = peer_material_provider
        self._technical_preparation_provider = technical_preparation_provider
        self._technical_peer_material_provider = technical_peer_material_provider
        self._restore_context_provider = restore_context_provider

    def render(self, state: AppState) -> RuntimeRenderContributions:
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        users: list[RuntimeSubject] = []
        fragment = ConfigFragment()
        definitions = {item.id for item in namespace.definitions}
        restored = self._restore_context_provider(state) if self._restore_context_provider is not None else ()
        excluded = {(item.cascade_id, item.protocol) for item in restored}
        if self._permit_provider is not None and self._engine_fingerprints_provider is not None:
            self._render_confirmed(state, namespace.cascades, definitions, users, fragment, excluded=excluded)
        self._render_technical(state, users, fragment)
        for item in restored:
            if item.participant_id != self._participant_id:
                raise ValueError("cascade restore context provider returned a foreign participant")
            restored_users, restored_fragment = item.render_current_users(
                state, self._credentials, self._participant_id
            )
            users.extend(restored_users)
            _merge_fragment(fragment, restored_fragment)
        if not users and fragment.is_empty():
            return RuntimeRenderContributions()
        return RuntimeRenderContributions(tuple(users), {"managed_node_cascades": fragment})

    def capture_scope(
        self,
        state: AppState,
        request: CascadeParticipantRequest,
        route: CascadeDefinition | None,
    ) -> CascadeRestoreContext:
        return capture_cascade_scope(
            state, request, route, role_for=self._role, render_confirmed=self._render_confirmed
        )

    def _render_confirmed(
        self,
        state,
        routes,
        definitions,
        users,
        fragment,
        *,
        excluded: set[tuple[str, str]] | frozenset[tuple[str, str]] = frozenset(),
        protocols: set[str] | frozenset[str] | None = None,
    ) -> None:
        permit_provider = self._permit_provider
        engine_provider = self._engine_fingerprints_provider
        if permit_provider is None or engine_provider is None:
            return
        for route in routes:
            route.validate()
            self._validate_participants(route, definitions)
            role = self._role(route)
            if role is None:
                continue
            for protocol in route.protocols:
                if protocols is not None and protocol not in protocols:
                    continue
                if (route.id, protocol) in excluded:
                    continue
                if protocol not in _PROTOCOLS:
                    raise ValueError("cascade protocol is not supported by scoped rendering")
                protocol_state = state.protocols.get(protocol)
                if protocol_state is None or not protocol_state.enabled:
                    continue
                business_users = [
                    user for user in state.users if access_status(user)[0] and protocol not in user.disabled_protocols
                ]
                if not business_users:
                    continue
                permit = permit_provider(state, route, protocol)
                if permit is None:
                    continue
                permit.validate(route, protocol)
                current = engine_provider(state, route)
                if current is None or not permit.engines_match(current):
                    continue
                scope = self._credentials.load(route.id)
                for business_user in business_users:
                    local_role = "entry" if role == "entry" else "transit"
                    subject = scope.subject(self._participant_id, protocol, local_role, business_user)
                    if role == "entry":
                        material = self._entry_material(
                            state,
                            route,
                            protocol,
                            business_user,
                            subject,
                            scope.subject(route.exit_id, protocol, "transit", business_user),
                            permit,
                        )
                        self._append_entry(fragment, route, protocol, subject, material)
                    else:
                        fragment.route_rules.append({"auth_user": [subject.email], "outbound": "direct"})
                    users.append(RuntimeSubject(subject.email, subject.uuid, (protocol,)))

    def _render_technical(self, state, users, fragment) -> None:
        preparation_provider = self._technical_preparation_provider
        if preparation_provider is None:
            return
        for preparation in preparation_provider(state):
            if not isinstance(preparation, CascadeTechnicalPreparation):
                raise ValueError("cascade technical preparation provider returned an invalid binding")
            preparation.validate()
            if not self._preparation_matches_state(state, preparation):
                continue
            if preparation.participant_id != self._participant_id:
                continue
            protocol_state = state.protocols.get(preparation.protocol)
            if protocol_state is None or not protocol_state.enabled:
                continue
            try:
                scope = self._credentials.load(preparation.route.id)
            except ValueError:
                continue
            role = preparation.role
            local = scope.technical_subject(
                self._participant_id,
                preparation.protocol,
                role,
                preparation.operation_id,
            )
            if role == "entry":
                peer_provider = self._technical_peer_material_provider
                if peer_provider is None:
                    continue
                transit = scope.technical_subject(
                    preparation.route.exit_id,
                    preparation.protocol,
                    "transit",
                    preparation.operation_id,
                )
                try:
                    material = peer_provider(state, preparation, transit)
                except Exception:
                    continue
                if material is None:
                    continue
                material.validate_for(preparation, transit)
                self._append_technical_entry(fragment, preparation, local, material)
            else:
                fragment.route_rules.append({"auth_user": [local.email], "outbound": "direct"})
            users.append(RuntimeSubject(local.email, local.uuid, (preparation.protocol,)))

    @staticmethod
    def _preparation_matches_state(state: AppState, preparation: CascadeTechnicalPreparation) -> bool:
        namespace = managed_nodes_from_extensions(state.feature_extensions)
        operation = next((item for item in namespace.operations if item.id == preparation.operation_id), None)
        if operation is None or operation.kind != "cascade_save" or not operation_is_active(operation):
            return False
        try:
            assert_cascade_unleased(namespace, operation)
            participants = cascade_participants(operation)
            route = cascade_candidate(operation)
        except (AttributeError, TypeError, ValueError):
            return False
        return (
            route is not None
            and route == preparation.route
            and participants >= {route.entry_id, route.exit_id}
            and operation.desired_digest == preparation.plan_digest == canonical_digest(operation.plan)
            and preparation.protocol in route.protocols
        )

    @staticmethod
    def _append_technical_entry(
        fragment: ConfigFragment,
        preparation: CascadeTechnicalPreparation,
        subject: User,
        material: CascadeTechnicalPeerMaterial,
    ) -> None:
        outbound = copy.deepcopy(material.client_outbound)
        suffix = hashlib.sha256(f"{preparation.operation_id}:{subject.uuid}".encode()).hexdigest()[:12]
        tag = f"cascade-stage-{preparation.route.id}-{preparation.protocol}-{suffix}"
        outbound["tag"] = tag
        fragment.outbounds.append(outbound)
        fragment.route_rules.extend(
            (
                {"auth_user": [subject.email], "outbound": tag},
                {"auth_user": [subject.email], "action": "reject"},
            ),
        )

    def _entry_material(
        self,
        state: AppState,
        route: CascadeDefinition,
        protocol: str,
        business_user: User,
        entry_user: User,
        transit_user: User,
        permit: CascadeRenderPermit,
    ) -> CascadePeerMaterial:
        if self._peer_material_provider is None:
            raise ValueError("cascade peer material is unavailable")
        try:
            material = self._peer_material_provider(
                state,
                route,
                protocol,
                business_user,
                transit_user,
                permit,
            )
        except Exception:
            raise ValueError("cascade peer material provider failed") from None
        if material is None:
            raise ValueError("cascade peer material is unavailable")
        material.validate_for(route, protocol, business_user, transit_user, permit)
        return material

    @staticmethod
    def _append_entry(
        fragment: ConfigFragment,
        route: CascadeDefinition,
        protocol: str,
        subject: User,
        material: CascadePeerMaterial,
    ) -> None:
        outbound = copy.deepcopy(material.client_outbound)
        suffix = hashlib.sha256(subject.uuid.encode("utf-8")).hexdigest()[:12]
        tag = f"cascade-{route.id}-{protocol}-{suffix}"
        outbound["tag"] = tag
        fragment.outbounds.append(outbound)
        fragment.route_rules.extend(
            (
                {"auth_user": [subject.email], "outbound": tag},
                {"auth_user": [subject.email], "action": "reject"},
            ),
        )

    def _role(self, route: CascadeDefinition) -> str | None:
        if route.entry_id == self._participant_id:
            return "entry"
        if route.exit_id == self._participant_id:
            return "exit"
        return None

    @staticmethod
    def _validate_participants(route: CascadeDefinition, definitions: set[str]) -> None:
        for participant_id in (route.entry_id, route.exit_id):
            if participant_id != "base" and participant_id not in definitions:
                raise ValueError("cascade participant is not enrolled")


def _merge_fragment(target: ConfigFragment, source: ConfigFragment) -> None:
    for name in ("inbounds", "outbounds", "route_rules", "nft_tproxy_ports", "nft_tproxy_ifaces", "endpoints"):
        getattr(target, name).extend(copy.deepcopy(getattr(source, name)))
    target.dns.update(copy.deepcopy(source.dns))


__all__ = [
    "CascadePeerMaterial",
    "CascadeRenderPermit",
    "CascadeTechnicalPeerMaterial",
    "ManagedNodeCascadeRenderer",
]
