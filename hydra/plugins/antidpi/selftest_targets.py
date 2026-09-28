"""Target discovery for the AntiScan self-test.

Only protocols with a fixture-proven adapter are probed.  Snell is a direct
TCP listener, so a malformed local connection reaches the same parser that
handles a real client and produces the same protocol-owned rejection.  The
removed protocols have no attributable enforcement event, so probing them
would only recreate the noise the contraction deleted.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from hydra.core.state_models import AppState

SUPPORTED_PROTOCOLS = ("snell",)
JOURNAL_UNITS = {
    "snell": ("sing-box",),
}


@dataclass(frozen=True)
class Target:
    transport: str
    port: int
    host: str = "127.0.0.1"
    sni: str = ""


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from untrusted plugin config, or ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return int(value.strip())
        except (TypeError, ValueError):
            return default
    return default


def targets(
    state: AppState,
    protocol: str,
    *,
    effective_port: Callable[[str, AppState], int],
) -> list[Target]:
    """Return local endpoints that exercise one enabled protocol parser."""
    del effective_port  # only direct listeners need a local probe
    if protocol != "snell":
        return []
    plugin_state = state.protocols.get(protocol)
    config = plugin_state.config if plugin_state else {}
    ports = {_as_int(user.credentials.get("snell", {}).get("port", 0)) for user in state.users if not user.blocked}
    ports.discard(0)
    if not ports:
        # No user record names the listener, so fall back to the inbound's own
        # configuration.  A self-test must be able to probe a running listener
        # even when the port is only declared in the transport config.
        if plugin_state is not None:
            ports.add(_as_int(plugin_state.port))
        if not ports and isinstance(config, dict):
            ports.add(_as_int(config.get("port", 0)))
    ports.discard(0)
    return [Target("tcp", port) for port in sorted(ports)[:3]]
