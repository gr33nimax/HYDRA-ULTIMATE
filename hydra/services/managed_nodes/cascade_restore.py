"""Protected, route-scoped canonical contribution used only during rollback."""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from hydra.contracts import ConfigFragment, RuntimeSubject, validate_fragment
from hydra.contracts.managed_node_cascade import CascadeParticipantRequest
from hydra.contracts.managed_node_models import CascadeDefinition
from hydra.contracts.managed_node_probe import ProbeMaterial
from hydra.core.state_models import AppState
from hydra.services.managed_nodes.cascade_credentials import CascadeCredentialStore
from hydra.services.user_access import access_status
from hydra.utils.crypto import derive_hex_key

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PROTOCOLS = frozenset({"vless", "anytls"})


@dataclass(frozen=True, repr=False)
class CascadeRestoreContext:
    """The actual prior cascade-owned contribution, never a full state/config snapshot."""

    cascade_id: str
    entry_id: str
    exit_id: str
    operation_id: str
    plan_digest: str
    participant_id: str
    protocol: str
    business_user_uuids: tuple[str, ...] = field(repr=False)
    users: tuple[RuntimeSubject, ...] = field(repr=False)
    fragment: ConfigFragment = field(repr=False)

    @classmethod
    def empty(cls, request: CascadeParticipantRequest) -> CascadeRestoreContext:
        previous = request.plan.get("previous")
        route = CascadeDefinition.from_document(previous) if previous is not None else request.route
        return cls(
            request.target_id,
            route.entry_id,
            route.exit_id,
            request.operation_id,
            request.plan_digest,
            request.participant_id,
            request.protocol,
            (),
            (),
            ConfigFragment(),
        )

    def validate(self) -> None:
        if not isinstance(self.cascade_id, str) or not _ID.fullmatch(self.cascade_id):
            raise ValueError("cascade restore scope is invalid")
        if not isinstance(self.operation_id, str) or not _ID.fullmatch(self.operation_id):
            raise ValueError("cascade restore operation is invalid")
        if not isinstance(self.plan_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", self.plan_digest):
            raise ValueError("cascade restore plan binding is invalid")
        if not isinstance(self.participant_id, str) or not _ID.fullmatch(self.participant_id):
            raise ValueError("cascade restore participant is invalid")
        if not isinstance(self.protocol, str) or self.protocol not in _PROTOCOLS:
            raise ValueError("cascade restore protocol is invalid")
        if (
            not isinstance(self.entry_id, str)
            or not _ID.fullmatch(self.entry_id)
            or not isinstance(self.exit_id, str)
            or not _ID.fullmatch(self.exit_id)
            or self.entry_id == self.exit_id
        ):
            raise ValueError("cascade restore topology is invalid")
        if (
            not isinstance(self.business_user_uuids, tuple)
            or any(not isinstance(item, str) or not item for item in self.business_user_uuids)
            or len(set(self.business_user_uuids)) != len(self.business_user_uuids)
        ):
            raise ValueError("cascade restore business-user bindings are invalid")
        if not isinstance(self.users, tuple) or any(not isinstance(item, RuntimeSubject) for item in self.users):
            raise ValueError("cascade restore subjects are invalid")
        if len(self.business_user_uuids) != len(self.users):
            raise ValueError("cascade restore subject/business-user bindings do not match")
        if not isinstance(self.fragment, ConfigFragment):
            raise ValueError("cascade restore fragment is invalid")
        if self.participant_id not in {self.entry_id, self.exit_id} and (self.users or not self.fragment.is_empty()):
            raise ValueError("cascade restore contribution exceeds its participant scope")
        for user in self.users:
            user.validate()
            if not user.email.startswith("cascade-") or user.protocols != (self.protocol,):
                raise ValueError("cascade restore subject is outside its private protocol scope")
        if len({item.uuid for item in self.users}) != len(self.users):
            raise ValueError("cascade restore subjects contain duplicate IDs")
        if len({item.email for item in self.users}) != len(self.users):
            raise ValueError("cascade restore subjects contain duplicate names")
        validate_fragment(self.fragment)
        if (
            self.fragment.inbounds
            or self.fragment.endpoints
            or self.fragment.dns
            or self.fragment.nft_tproxy_ports
            or self.fragment.nft_tproxy_ifaces
        ):
            raise ValueError("cascade restore cannot own listeners, host rules or DNS")
        tags = set()
        prefix = f"cascade-{self.cascade_id}-{self.protocol}-"
        for outbound in self.fragment.outbounds:
            tag = outbound.get("tag")
            if outbound.get("type") != self.protocol or not isinstance(tag, str) or not tag.startswith(prefix):
                raise ValueError("cascade restore outbound is outside its route/protocol scope")
            ProbeMaterial(self.protocol, outbound).validate()
            tags.add(tag)
        is_entry = self.participant_id == self.entry_id
        expected_rules = len(self.users) * (2 if is_entry else 1)
        if len(self.fragment.route_rules) != expected_rules:
            raise ValueError("cascade restore rules do not match its scoped subjects")
        if is_entry and len(self.fragment.outbounds) != len(self.users):
            raise ValueError("cascade entry restore materials do not match its scoped subjects")
        if not is_entry and self.fragment.outbounds:
            raise ValueError("cascade transit restore cannot own client outbounds")
        subjects = {item.email for item in self.users}
        for rule in self.fragment.route_rules:
            auth_user = rule.get("auth_user")
            if not isinstance(auth_user, list) or len(auth_user) != 1 or auth_user[0] not in subjects:
                raise ValueError("cascade restore route rule is outside its owned subjects")
            if set(rule) == {"auth_user", "outbound"}:
                if rule["outbound"] != "direct" and rule["outbound"] not in tags:
                    raise ValueError("cascade restore rule refers to an unowned outbound")
            elif set(rule) == {"auth_user", "action"} and rule["action"] == "reject":
                continue
            else:
                raise ValueError("cascade restore route rule has an unsupported shape")

    def validate_for(self, request: CascadeParticipantRequest) -> None:
        self.validate()
        if (
            self.cascade_id != request.target_id
            or self.operation_id != request.operation_id
            or self.plan_digest != request.plan_digest
            or self.participant_id != request.participant_id
            or self.protocol != request.protocol
        ):
            raise ValueError("cascade restore artifact is bound to another participant request")
        previous = request.plan.get("previous")
        route = CascadeDefinition.from_document(previous) if previous is not None else request.route
        if route.id != self.cascade_id or (self.entry_id, self.exit_id) != (route.entry_id, route.exit_id):
            raise ValueError("cascade restore artifact is bound to another route topology")
        if previous is None and (self.business_user_uuids or self.users or not self.fragment.is_empty()):
            raise ValueError("new cascade restore scope must be empty")
        if previous is not None and (
            request.participant_id not in {route.entry_id, route.exit_id} or request.protocol not in route.protocols
        ):
            if self.business_user_uuids or self.users or not self.fragment.is_empty():
                raise ValueError("cascade restore artifact exceeds its previous participant scope")

    def to_document(self) -> dict[str, Any]:
        self.validate()
        return {
            "cascade_id": self.cascade_id,
            "entry_id": self.entry_id,
            "exit_id": self.exit_id,
            "operation_id": self.operation_id,
            "plan_digest": self.plan_digest,
            "participant_id": self.participant_id,
            "protocol": self.protocol,
            "business_user_uuids": list(self.business_user_uuids),
            "users": [
                {"email": user.email, "uuid": user.uuid, "protocols": list(user.protocols)} for user in self.users
            ],
            "fragment": self.fragment.as_dict(),
        }

    @classmethod
    def from_document(cls, raw: object) -> CascadeRestoreContext:
        keys = {
            "cascade_id",
            "entry_id",
            "exit_id",
            "operation_id",
            "plan_digest",
            "participant_id",
            "protocol",
            "business_user_uuids",
            "users",
            "fragment",
        }
        if (
            not isinstance(raw, dict)
            or set(raw) != keys
            or not isinstance(raw["business_user_uuids"], list)
            or not isinstance(raw["users"], list)
        ):
            raise ValueError("cascade restore artifact has an invalid shape")
        users = []
        for item in raw["users"]:
            if not isinstance(item, dict) or set(item) != {"email", "uuid", "protocols"}:
                raise ValueError("cascade restore subject has an invalid shape")
            if not isinstance(item["protocols"], list):
                raise ValueError("cascade restore subject protocol scope is invalid")
            users.append(RuntimeSubject(item["email"], item["uuid"], tuple(item["protocols"])))
        fragment_raw = raw["fragment"]
        if not isinstance(fragment_raw, dict) or set(fragment_raw) != {
            "inbounds",
            "outbounds",
            "route_rules",
            "nft_tproxy_ports",
            "nft_tproxy_ifaces",
            "endpoints",
            "dns",
        }:
            raise ValueError("cascade restore fragment has an invalid shape")
        value = cls(
            raw["cascade_id"],
            raw["entry_id"],
            raw["exit_id"],
            raw["operation_id"],
            raw["plan_digest"],
            raw["participant_id"],
            raw["protocol"],
            tuple(raw["business_user_uuids"]),
            tuple(users),
            ConfigFragment(**copy.deepcopy(fragment_raw)),
        )
        value.validate()
        return value

    def render_current_users(
        self,
        state: AppState,
        credentials: CascadeCredentialStore,
        participant_id: str,
    ) -> tuple[tuple[RuntimeSubject, ...], ConfigFragment]:
        """Rebuild the prior route for current users without restoring any stale AppState."""
        self.validate()
        if participant_id != self.participant_id:
            raise ValueError("cascade restore context belongs to another participant")
        if not self.users:
            return (), ConfigFragment()
        protocol_state = state.protocols.get(self.protocol)
        if protocol_state is None or not protocol_state.enabled:
            return (), ConfigFragment()
        business_users = [
            user for user in state.users if access_status(user)[0] and self.protocol not in user.disabled_protocols
        ]
        if not business_users:
            return (), ConfigFragment()
        scope = credentials.load(self.cascade_id)
        restored_users: list[RuntimeSubject] = []
        fragment = ConfigFragment()
        is_entry = participant_id == self.entry_id
        templates = dict(zip(self.business_user_uuids, self.fragment.outbounds))
        if is_entry and not self.fragment.outbounds:
            raise ValueError("previous cascade peer material is unavailable for new users")
        template = self.fragment.outbounds[0] if self.fragment.outbounds else None
        for business_user in business_users:
            role = "entry" if is_entry else "transit"
            subject = scope.subject(participant_id, self.protocol, role, business_user)
            restored_users.append(RuntimeSubject(subject.email, subject.uuid, (self.protocol,)))
            if not is_entry:
                fragment.route_rules.append({"auth_user": [subject.email], "outbound": "direct"})
                continue
            if template is None:
                raise ValueError("previous cascade peer material is unavailable for new users")
            transit = scope.subject(self.exit_id, self.protocol, "transit", business_user)
            outbound = copy.deepcopy(templates.get(business_user.uuid, template))
            credential_key = "uuid" if self.protocol == "vless" else "password"
            outbound[credential_key] = (
                transit.uuid if self.protocol == "vless" else derive_hex_key("anytls-pass", transit.uuid)
            )
            suffix = hashlib.sha256(subject.uuid.encode("utf-8")).hexdigest()[:12]
            tag = f"cascade-{self.cascade_id}-{self.protocol}-{suffix}"
            outbound["tag"] = tag
            ProbeMaterial(self.protocol, outbound).validate()
            fragment.outbounds.append(outbound)
            fragment.route_rules.extend(
                (
                    {"auth_user": [subject.email], "outbound": tag},
                    {"auth_user": [subject.email], "action": "reject"},
                )
            )
        return tuple(restored_users), fragment

    def __repr__(self) -> str:
        return "CascadeRestoreContext(<protected>)"


__all__ = ["CascadeRestoreContext"]
