"""Read-only status and safe user representations.

Status rendering must distinguish persisted configuration from runtime state.
The helpers in this module intentionally do not mutate or save application
state, which keeps diagnostics safe to call from automation and the TUI.
"""
from __future__ import annotations

from dataclasses import asdict

from hydra.core.state import AppState, User


def public_user(user: User) -> dict:
    """Return user metadata without exposing protocol secrets."""
    payload = asdict(user)
    payload.pop("credentials", None)
    payload["protocols"] = sorted(user.credentials)
    return payload


def build_status(state: AppState) -> dict:
    """Build a JSON-safe status snapshot with effective runtime flags."""
    from hydra.plugins.registry import status_all

    plugins = status_all(state)
    from hydra.core.runtime_state import RuntimeSnapshot
    runtime = RuntimeSnapshot.from_statuses(plugins)
    network = asdict(state.network)
    dnscrypt = plugins.get("dnscrypt", {})
    # Older state files may have a stale network flag while the dedicated
    # dnscrypt-proxy service is enabled and healthy. Keep both values visible,
    # but expose the effective state under the established field name.
    network["configured_dnscrypt_enabled"] = network["dnscrypt_enabled"]
    network["dnscrypt_enabled"] = bool(
        dnscrypt.get("enabled") or dnscrypt.get("running")
    )
    return {
        "version": state.version,
        "users": len(state.users),
        "network": network,
        "plugins": plugins,
        "runtime": runtime.as_dict(),
    }
