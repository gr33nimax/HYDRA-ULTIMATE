"""Validation and desired-state policy for TrustTunnel."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import PluginState
from hydra.plugins.context import PluginStateAccess

from .constants import DEFAULT_TRANSPORT, VALID_TRANSPORTS


def transport(protocol: PluginState | None) -> str:
    value = (
        protocol.config.get("transport", DEFAULT_TRANSPORT)
        if protocol and protocol.config
        else DEFAULT_TRANSPORT
    )
    return value if value in VALID_TRANSPORTS else DEFAULT_TRANSPORT


def validate_config(
    state: PluginStateAccess,
    *,
    require_cert: bool,
    prospective_enable: bool,
    resolve_certs: Callable[
        [str, PluginState | None],
        tuple[str, str],
    ],
    transport_of: Callable[[PluginState | None], str],
) -> list[str]:
    """Return desired-state errors without changing runtime or persistence."""
    protocol = state.protocols.get("trusttunnel")
    if not protocol:
        return ["состояние TrustTunnel отсутствует"]

    errors = []
    configured_transport = protocol.config.get(
        "transport",
        DEFAULT_TRANSPORT,
    )
    if configured_transport not in VALID_TRANSPORTS:
        errors.append(f"неизвестный транспорт: {configured_transport}")

    domain = protocol.config.get("domain", "").strip()
    if not domain:
        errors.append("домен TrustTunnel не задан")
    else:
        naive = state.protocols.get("naive")
        if naive and naive.enabled and state.network.domain == domain:
            errors.append(f"домен {domain} уже используется NaiveProxy")
        anytls = state.protocols.get("anytls")
        if (
            anytls
            and anytls.enabled
            and anytls.config.get("domain") == domain
        ):
            errors.append(f"домен {domain} уже используется anytls")

    if require_cert and domain:
        cert_file, key_file = resolve_certs(domain, protocol)
        if not cert_file or not key_file:
            errors.append(f"TLS-сертификат для {domain} не найден")

    if transport_of(protocol) in ("quic", "both"):
        try:
            from hydra.core.sni_router import get_quic_owner

            get_quic_owner(
                state,
                prospective=(
                    "trusttunnel"
                    if prospective_enable
                    else None
                ),
            )
        except ValueError as exc:
            errors.append(str(exc))
    return errors


def set_transport(
    state: PluginStateAccess,
    new_transport: str,
    *,
    validate: Callable[..., list[str]],
) -> bool:
    """Update desired transport, rolling back the in-memory value on error."""
    if new_transport not in VALID_TRANSPORTS:
        return False
    protocol = state.protocols.get("trusttunnel")
    if protocol is None:
        return False

    previous = protocol.config.get("transport")
    protocol.config["transport"] = new_transport
    errors = validate(state, require_cert=protocol.enabled)
    if not errors:
        return True
    if previous is None:
        protocol.config.pop("transport", None)
    else:
        protocol.config["transport"] = previous
    return False
