"""Pure connection-attribution rules for the traffic daemon.

The daemon deliberately knows only how to collect a journal snapshot.  This
module turns that snapshot into protocol-neutral evidence and resolves one
Clash connection through an injectable strategy.  A new protocol that exposes
``metadata.user`` works automatically; protocols with unusual attribution can
provide one small resolver without changing the accounting loop.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hydra.core.state_models import AppState
from hydra.utils.plugin_identity import snell_user_tag


Address = tuple[str, str]
Connection = Mapping[str, Any]
UserResolver = Callable[[Connection, AppState, "TrafficEvidence"], str | None]

_CONTEXT_RE = re.compile(r"INFO\s+\[(\d+)\s+[^\]]+\]")


@dataclass(frozen=True)
class TrafficEvidence:
    """Indexes derived from one Sing-box journal snapshot."""

    source_ports: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    sources: Mapping[str, Mapping[Address, str]] = field(default_factory=dict)
    destinations: Mapping[
        str,
        Mapping[Address, str | None],
    ] = field(default_factory=dict)
    connection_ids: Mapping[str, Mapping[str, str]] = field(
        default_factory=dict,
    )

    @property
    def protocols(self) -> frozenset[str]:
        return frozenset(
            {
                *self.source_ports,
                *self.sources,
                *self.destinations,
                *self.connection_ids,
            },
        )


@dataclass(frozen=True)
class ConnectionIdentity:
    protocol: str
    user: str = ""


def parse_anytls_users(lines: Sequence[str]) -> dict[str, str]:
    context_ports: dict[str, str] = {}
    context_users: dict[str, str] = {}
    for line in lines:
        if "inbound/anytls" not in line.lower():
            continue
        context = _CONTEXT_RE.search(line)
        if not context:
            continue
        context_id = context.group(1)
        source = re.search(
            r"inbound connection from 127\.0\.0\.1:(\d+)",
            line,
            re.IGNORECASE,
        )
        if source:
            context_ports[context_id] = source.group(1)
            continue
        user = re.search(
            r"inbound/anytls\[[^\]]+\]:\s+\[([^\]]+)\]\s+"
            r"inbound connection to",
            line,
            re.IGNORECASE,
        )
        if user:
            context_users[context_id] = user.group(1)
    return {
        context_ports[context_id]: user
        for context_id, user in context_users.items()
        if context_id in context_ports
    }


def _record_destination(
    destination_users: dict[Address, str | None],
    *,
    host: str,
    port: str,
    user: str,
) -> None:
    key = (host.strip("[]").lower(), port)
    previous = destination_users.get(key)
    if previous is not None and previous != user:
        # Destination-only attribution becomes unsafe when several users reach
        # the same endpoint.  Connection-id evidence can still disambiguate it.
        destination_users[key] = None
    elif key not in destination_users:
        destination_users[key] = user


def parse_destination_users(
    lines: Sequence[str],
    *,
    protocol: str,
) -> tuple[dict[Address, str | None], dict[str, str]]:
    destination_users: dict[Address, str | None] = {}
    connection_users: dict[str, str] = {}
    if protocol == "trusttunnel":
        pattern = re.compile(
            r"inbound/trusttunnel\[[^\]]+\]:\s+\[([^\]]+)\]\s+"
            r"inbound connection to\s+"
            r"([a-zA-Z0-9._-]+|\[[0-9a-fA-F:]+\]):(\d+)",
            re.IGNORECASE,
        )
    elif protocol == "shadowtls":
        pattern = re.compile(
            r"inbound/(?:shadowtls|trojan)"
            r"\[[^\]]*shadowtls[^\]]*\]:\s+"
            r"\[([^\]]+)\]\s+inbound connection to\s+"
            r"([a-zA-Z0-9._-]+|\[[0-9a-fA-F:]+\]):(\d+)",
            re.IGNORECASE,
        )
    else:
        raise ValueError(f"unsupported destination evidence: {protocol}")

    for line in lines:
        if protocol not in line.lower():
            continue
        match = pattern.search(line)
        if not match:
            continue
        user, host, port = match.groups()
        context = _CONTEXT_RE.search(line)
        if context:
            connection_users[context.group(1)] = user
        _record_destination(
            destination_users,
            host=host,
            port=port,
            user=user,
        )
    return destination_users, connection_users


def _store_source(
    result: dict[Address, str],
    source: Address,
    user: str,
) -> None:
    result[source] = user
    if source[0].startswith("::ffff:"):
        result[(source[0][7:], source[1])] = user


def parse_mieru_users(lines: Sequence[str]) -> dict[Address, str]:
    context_sources: dict[str, Address] = {}
    context_users: dict[str, str] = {}
    address_pattern = re.compile(
        r"INFO\s+\[(\d+)\s+[^\]]+\]\s+"
        r"inbound/mieru\[[^\]]+\]:\s+inbound\s+(?:TCP|UDP)\s+"
        r"connection\s+from\s+\[?([a-zA-Z0-9.:-]+)\]?:(\d+)",
        re.IGNORECASE,
    )
    user_pattern = re.compile(
        r"INFO\s+\[(\d+)\s+[^\]]+\]\s+"
        r"inbound/mieru\[[^\]]+\]:\s+\[([^\]]+)\]\s+"
        r"inbound\s+(?:TCP|UDP)\s+connection",
        re.IGNORECASE,
    )
    for line in lines:
        if "inbound/mieru" not in line.lower():
            continue
        address = address_pattern.search(line)
        if address:
            context_sources[address.group(1)] = (
                address.group(2).lower(),
                address.group(3),
            )
            continue
        user = user_pattern.search(line)
        if user:
            context_users[user.group(1)] = user.group(2)

    result: dict[Address, str] = {}
    for context_id, user in context_users.items():
        source = context_sources.get(context_id)
        if source:
            _store_source(result, source, user)
    return result


def parse_hysteria2_users(lines: Sequence[str]) -> dict[Address, str]:
    context_sources: dict[str, Address] = {}
    context_users: dict[str, str] = {}
    for line in lines:
        if "inbound/hysteria2" not in line.lower():
            continue
        context = _CONTEXT_RE.search(line)
        if not context:
            continue
        context_id = context.group(1)
        source = re.search(
            r"inbound (?:packet )?connection from\s+"
            r"(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9._:-]+):(\d+)",
            line,
            re.IGNORECASE,
        )
        if source:
            context_sources[context_id] = (
                source.group(1).strip("[]").lower(),
                source.group(2),
            )
            continue
        user = re.search(
            r"inbound/hysteria2\[[^\]]+\]:\s+\[([^\]]+)\]\s+"
            r"inbound (?:packet )?connection to",
            line,
            re.IGNORECASE,
        )
        if user:
            context_users[context_id] = user.group(1)

    result: dict[Address, str] = {}
    for context_id, user in context_users.items():
        source = context_sources.get(context_id)
        if source:
            _store_source(result, source, user)
    return result


def evidence_from_journal(lines: Sequence[str]) -> TrafficEvidence:
    trust_destinations, trust_connections = parse_destination_users(
        lines,
        protocol="trusttunnel",
    )
    shadow_destinations, shadow_connections = parse_destination_users(
        lines,
        protocol="shadowtls",
    )
    return TrafficEvidence(
        source_ports={"anytls": parse_anytls_users(lines)},
        sources={
            "mieru": parse_mieru_users(lines),
            "hysteria2": parse_hysteria2_users(lines),
        },
        destinations={
            "trusttunnel": trust_destinations,
            "shadowtls": shadow_destinations,
        },
        connection_ids={
            "trusttunnel": trust_connections,
            "shadowtls": shadow_connections,
        },
    )


def _snell_user(
    connection: Connection,
    state: AppState,
    _evidence: TrafficEvidence,
) -> str | None:
    metadata = connection.get("metadata", {})
    inbound_tag = str(
        metadata.get("inboundTag", "") or metadata.get("type", ""),
    )
    return next(
        (
            user.email
            for user in state.users
            if snell_user_tag(user) in inbound_tag
        ),
        None,
    )


@dataclass(frozen=True)
class ConnectionAttributor:
    """Resolve protocol and user without a central protocol branch chain."""

    aliases: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    resolvers: Mapping[str, UserResolver] = field(
        default_factory=lambda: {"snell": _snell_user},
    )

    def identify(
        self,
        connection: Connection,
        state: AppState,
        evidence: TrafficEvidence,
    ) -> ConnectionIdentity:
        metadata = connection.get("metadata", {})
        inbound_tag = str(
            metadata.get("inboundTag", "") or metadata.get("type", ""),
        ).lower()
        protocol = self._protocol_for(inbound_tag, state, evidence)
        if not protocol:
            return ConnectionIdentity("unknown")

        user = str(metadata.get("user") or "")
        if not user:
            user = self._evidence_user(
                protocol,
                connection,
                evidence,
            )
        if not user and protocol in self.resolvers:
            user = self.resolvers[protocol](connection, state, evidence) or ""
        return ConnectionIdentity(protocol, user)

    def _protocol_for(
        self,
        inbound_tag: str,
        state: AppState,
        evidence: TrafficEvidence,
    ) -> str:
        names = {*state.protocols, *evidence.protocols, *self.aliases}
        candidates = (
            (name, name, *self.aliases.get(name, ()))
            for name in names
        )
        matches = [
            name
            for name, *tokens in candidates
            if any(token.lower() in inbound_tag for token in tokens)
        ]
        return max(matches, key=len, default="")

    @staticmethod
    def _evidence_user(
        protocol: str,
        connection: Connection,
        evidence: TrafficEvidence,
    ) -> str:
        metadata = connection.get("metadata", {})
        connection_id = str(connection.get("id") or "")
        user = evidence.connection_ids.get(protocol, {}).get(connection_id)
        if user:
            return user

        source_port = str(metadata.get("sourcePort", ""))
        user = evidence.source_ports.get(protocol, {}).get(source_port)
        if user:
            return user

        source = (
            str(metadata.get("sourceIP", "")).lower(),
            source_port,
        )
        user = evidence.sources.get(protocol, {}).get(source)
        if user:
            return user

        destination = (
            str(
                metadata.get("host")
                or metadata.get("destinationIP", ""),
            ).lower(),
            str(metadata.get("destinationPort", "")),
        )
        return (
            evidence.destinations.get(protocol, {}).get(destination)
            or ""
        )


DEFAULT_ATTRIBUTOR = ConnectionAttributor(
    aliases={
        "amneziawg": ("awg",),
        "snell": ("snell-",),
    },
)


__all__ = [
    "ConnectionAttributor",
    "ConnectionIdentity",
    "DEFAULT_ATTRIBUTOR",
    "TrafficEvidence",
    "UserResolver",
    "evidence_from_journal",
    "parse_anytls_users",
    "parse_destination_users",
    "parse_hysteria2_users",
    "parse_mieru_users",
]
