"""Pure mtproto.zig TOML projection."""

from __future__ import annotations

from typing import cast

from hydra.contracts import ConfigFragment, JsonValue
from hydra.core.sni_router import needs_mux
from hydra.core.state_models import AppState
from hydra.plugins.context import PluginStateAccess

from .constants import INTERNAL_PORT, METRICS_PORT, PUBLIC_PORT, ROUTE_KEY
from .credentials import derive_secret, derive_username


def route_metadata() -> dict[str, JsonValue]:
    return {
        "kind": "tls_passthrough",
        "internal_port": INTERNAL_PORT,
        "sni_config": "domain",
    }


def effective_listener(state: PluginStateAccess) -> tuple[str, int]:
    return ("127.0.0.1", INTERNAL_PORT) if needs_mux(cast(AppState, state)) else ("::", PUBLIC_PORT)


def _toml_key(name: str) -> str:
    """Quote a user key: derived usernames are base64 and may hold +, / or =.

    An unquoted key with those characters is a TOML parse error, which makes
    the whole mtproto.zig config unusable.
    """
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_toml(*, address: str, port: int, domain: str, users: dict[str, str]) -> str:
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
        "",
        "[upstream]",
        'type = "auto"',
    ]
    return "\n".join(lines) + "\n"


def plan_configuration(state: PluginStateAccess) -> tuple[str, ConfigFragment]:
    protocol = state.protocols.get("mtproto_zig")
    config = protocol.config if protocol else {}
    domain = str(config.get("domain", "")).strip().lower().rstrip(".")
    if not domain:
        raise ValueError("MTProto Zig requires a protocol-owned domain")
    address, port = effective_listener(state)
    users = {derive_username(user.uuid): derive_secret(user.uuid) for user in state.users if not user.blocked}
    return build_toml(address=address, port=port, domain=domain, users=users), ConfigFragment()
