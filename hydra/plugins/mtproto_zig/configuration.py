"""Pure mtproto.zig TOML projection."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import cast

from hydra.contracts import ConfigFragment, JsonValue
from hydra.contracts.hostnames import normalize_hostname
from hydra.core.sni_router import needs_mux
from hydra.core.state_models import AppState, PluginState
from hydra.plugins.context import PluginStateAccess

from .constants import (
    INTERNAL_PORT,
    METRICS_PORT,
    PUBLIC_PORT,
    ROUTE_KEY,
    WEB_MODES,
    WEB_RELAY_PORT,
    WEB_ROUTE_KEY,
    WEB_WS_PATH,
)
from .credentials import bridge_capability, derive_secret, derive_username


def route_metadata() -> dict[str, JsonValue]:
    return {
        "kind": "tls_passthrough",
        "internal_port": INTERNAL_PORT,
        "sni_config": "domain",
    }


def web_route_metadata() -> dict[str, JsonValue]:
    """Declarative TLS-terminating route for the dedicated WEB bridge domain.

    The managed frontend terminates TLS for this name and forwards the decrypted
    HTTP/WebSocket stream to the loopback relay, so the FakeTLS cover domain and
    the WEB domain stay two independent SNI routes.
    """
    return {
        "kind": "http_reverse_proxy",
        "internal_port": WEB_RELAY_PORT,
        "sni_config": "web_domain",
        "cert_config": "web_cert_file",
        "key_config": "web_key_file",
    }


def normalize_web_mode(value: object) -> str:
    """Return a supported WEB mode or reject unknown desired state."""
    mode = str(value or "off").strip().lower()
    if mode not in WEB_MODES:
        raise ValueError("Режим WEB MTProto Zig: допустимы off, hybrid или web-only")
    return mode


def web_mode(config: Mapping[str, JsonValue]) -> str:
    return normalize_web_mode(config.get("web_mode", "off"))


def web_domain(config: Mapping[str, JsonValue]) -> str:
    return str(config.get("web_domain", "")).strip().lower().rstrip(".")


def bridge_capability_for(state: PluginStateAccess) -> str:
    """Build the WEB bridge probe capability from the first active user."""
    protocol = state.protocols.get("mtproto_zig")
    config = protocol.config if protocol else {}
    host = web_domain(config)
    for user in state.users:
        if not user.blocked:
            return bridge_capability(derive_secret(user.uuid), host)
    return ""


def _last_label_is_numeric(host: str) -> bool:
    """The WHATWG "ends in a number" rule upstream mirrors to reject IPv4 forms.

    A final label of ASCII digits, or a ``0x``-prefixed hex label, means the
    host is really an IP address in some notation; Telegram Desktop refuses it.
    """
    label = host.rsplit(".", 1)[-1]
    if not label:
        return False
    if label[:2].lower() == "0x":
        rest = label[2:]
        return bool(rest) and all(character in "0123456789abcdefABCDEF" for character in rest)
    return label.isascii() and label.isdigit()


def normalize_web_domain(value: object) -> str:
    """Require a real DNS name for the relay.

    Telegram Desktop rejects an IP address (including numeric and hex-looking
    forms) or a single label, and the borrowed FakeTLS cover domain belongs to a
    third party, so the WEB host is always a dedicated operator-owned name.
    """
    host = normalize_hostname(value, field="Домен WEB-релея")
    if _last_label_is_numeric(host):
        raise ValueError("Домен WEB-релея должен быть доменным именем, а не IP-адресом")
    return host


def normalize_cover_domain(value: object) -> str:
    """Require a real DNS name for the borrowed FakeTLS cover host.

    The cover name is somebody else's site and the SNI router refuses to give
    one name to two backends, so it is validated exactly like the WEB host:
    IP literals, including numeric and hex-looking forms, are not accepted.
    """
    host = normalize_hostname(value, field="Домен FakeTLS")
    if _last_label_is_numeric(host):
        raise ValueError("Домен FakeTLS должен быть доменным именем, а не IP-адресом")
    return host


def web_active(config: Mapping[str, JsonValue]) -> bool:
    return web_mode(config) != "off"


def _confirmed(value: object) -> bool:
    """Accept a real boolean and the string form a headless caller passes."""
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _ensure_passthrough_route(config: dict, changed: bool) -> bool:
    """Re-declare the FakeTLS passthrough route after a WEB-only period."""
    if isinstance(config.get(ROUTE_KEY), dict):
        return changed
    config[ROUTE_KEY] = route_metadata()
    return True


def set_cover_domain(
    state: PluginStateAccess,
    domain: str,
    confirm_change: object = False,
) -> bool:
    """Persist the FakeTLS cover domain without touching the WEB relay domain.

    The cover host is embedded in every issued FakeTLS secret
    (``ee<secret><domain hex>``), so changing it invalidates those links and
    needs explicit confirmation from any caller, including a headless one. The
    name is validated before any mutation, and a collision with the WEB relay
    host is refused here so the operator sees the conflict instead of the raw
    SNI-router error.
    """
    protocol = state.protocols.setdefault("mtproto_zig", PluginState())
    host = normalize_cover_domain(domain)
    current = str(protocol.config.get("domain", "")).strip().lower().rstrip(".")
    relay = web_domain(protocol.config)
    if relay and host == relay:
        raise ValueError(
            f"Домен FakeTLS совпадает с доменом WEB-релея {host}: один домен не может принадлежать двум маршрутам",
        )
    if host == current:
        return False
    if current and not _confirmed(confirm_change):
        raise ValueError(
            "Смена домена FakeTLS делает нерабочими все выданные FakeTLS-ссылки "
            "(домен вшит в секрет): передайте confirm_change=true",
        )
    protocol.config["domain"] = host
    return True


def set_web_settings(
    state: PluginStateAccess,
    mode: str,
    domain: str = "",
    confirm_host_change: object = False,
) -> bool:
    """Persist the WEB access mode and the route set it requires.

    A non-``off`` mode needs its own operator-controlled DNS name: Telegram
    Desktop rejects IPs and single labels, and the borrowed FakeTLS cover domain
    belongs to a third party. ``web-only`` additionally drops the FakeTLS
    passthrough route, because the frontend otherwise keeps forwarding direct
    traffic from its own loopback address, which the relay trusts as a carrier
    source. Changing an already distributed WEB domain invalidates every issued
    link, so it needs explicit confirmation from any caller, including a headless
    one.
    """
    normalized = normalize_web_mode(mode)
    protocol = state.protocols.setdefault("mtproto_zig", PluginState())
    current_mode = web_mode(protocol.config)
    current_domain = web_domain(protocol.config)
    if normalized == "off":
        changed = protocol.config.pop(WEB_ROUTE_KEY, None) is not None
        changed = protocol.config.pop("web_domain", None) is not None or changed
        changed = current_mode != "off" or changed
        protocol.config["web_mode"] = "off"
        return _ensure_passthrough_route(protocol.config, changed)
    host = normalize_web_domain(domain)
    if current_domain and current_domain != host and not _confirmed(confirm_host_change):
        raise ValueError(
            "Смена домена WEB-релея делает нерабочими все выданные WEB-ссылки: передайте confirm_host_change=true",
        )
    changed = (
        current_mode != normalized or current_domain != host or not isinstance(protocol.config.get(WEB_ROUTE_KEY), dict)
    )
    protocol.config["web_mode"] = normalized
    protocol.config["web_domain"] = host
    protocol.config[WEB_ROUTE_KEY] = web_route_metadata()
    if normalized == "web-only":
        # Tombstone, don't delete: the command apply path re-runs
        # normalize_protocol_config, whose config_defaults setdefault only fills
        # *missing* keys — an explicit None survives, a deleted key gets the
        # FakeTLS route back. Resurrecting it made plan_configuration reject
        # web-only for the route it had just removed. The router and the
        # web-only guard both treat a non-Mapping value as "no route".
        removed = isinstance(protocol.config.get(ROUTE_KEY), Mapping)
        protocol.config[ROUTE_KEY] = None
        return removed or changed
    return _ensure_passthrough_route(protocol.config, changed)


def effective_listener(state: PluginStateAccess) -> tuple[str, int]:
    return ("127.0.0.1", INTERNAL_PORT) if needs_mux(cast(AppState, state)) else ("::", PUBLIC_PORT)


def _toml_key(name: str) -> str:
    """Quote a user key: derived usernames are base64 and may hold +, / or =.

    An unquoted key with those characters is a TOML parse error, which makes
    the whole mtproto.zig config unusable.
    """
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _web_section(domain: str, backend: str, *, only: bool, public_dir: str = "") -> list[str]:
    section = [
        "[web]",
        "enabled = true",
        f"only = {'true' if only else 'false'}",
        'listen = "127.0.0.1"',
        f"port = {WEB_RELAY_PORT}",
        f'backend = "{backend}"',
        f'domain = "{domain}"',
    ]
    if public_dir:
        section.append(f'public_dir = "{public_dir}"')
    section += [
        f'ws_path = "{WEB_WS_PATH}"',
        # The managed frontend forwards one raw decrypted stream, so no trusted
        # header carries the client address. Declaring one would credit every
        # relayed user with the frontend's loopback address.
        "trust_forwarded_for = false",
    ]
    return section


def build_toml(
    *,
    address: str,
    port: int,
    domain: str,
    users: dict[str, str],
    web_domain: str = "",
    web_only: bool = False,
    public_dir: str = "",
) -> str:
    lines = [
        "[server]",
        f"port = {port}",
        f'bind_address = "{address}"',
        f"public_port = {PUBLIC_PORT}",
        "",
        "[censorship]",
        f'tls_domain = "{domain}"',
        "mask = true",
        "fake_tls_only = true",
        "",
        "[access.users]",
        *(f'{_toml_key(name)} = "{secret}"' for name, secret in sorted(users.items())),
        "",
        "[metrics]",
        "enabled = true",
        'host = "127.0.0.1"',
        f"port = {METRICS_PORT}",
    ]
    if web_domain:
        backend_host = "127.0.0.1" if address in {"::", "0.0.0.0"} else address
        lines += [
            "",
            *_web_section(
                web_domain,
                f"{backend_host}:{port}",
                only=web_only,
                public_dir=public_dir,
            ),
        ]
    lines += ["", "[upstream]", 'type = "auto"']
    return "\n".join(lines) + "\n"


def plan_configuration(
    state: PluginStateAccess,
    *,
    web_only: bool = False,
    public_dir: str = "",
) -> tuple[str, ConfigFragment]:
    protocol = state.protocols.get("mtproto_zig")
    config = protocol.config if protocol else {}
    domain = str(config.get("domain", "")).strip().lower().rstrip(".")
    if not domain:
        raise ValueError("MTProto Zig requires a protocol-owned domain")
    mode = web_mode(config)
    relay_domain = web_domain(config)
    if mode != "off":
        if not relay_domain:
            raise ValueError("Для WEB-режима MTProto Zig нужен отдельный домен релея")
        if not isinstance(config.get(WEB_ROUTE_KEY), Mapping):
            raise ValueError("Маршрут WEB MTProto Zig отсутствует в состоянии")
    if mode == "web-only" and isinstance(config.get(ROUTE_KEY), Mapping):
        # The frontend would keep forwarding direct FakeTLS traffic from its own
        # loopback address, which the relay trusts as a carrier source.
        raise ValueError("Режим «только WEB» требует снятого маршрута FakeTLS")
    address, port = effective_listener(state)
    users = {derive_username(user.uuid): derive_secret(user.uuid) for user in state.users if not user.blocked}
    return (
        build_toml(
            address=address,
            port=port,
            domain=domain,
            users=users,
            web_domain=relay_domain if mode != "off" else "",
            web_only=web_only and mode == "web-only",
            public_dir=public_dir,
        ),
        ConfigFragment(),
    )
