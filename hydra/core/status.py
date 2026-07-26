"""Read-only status and safe user representations.

Status rendering must distinguish persisted configuration from runtime state.
The helpers in this module intentionally do not mutate or save application
state, which keeps diagnostics safe to call from automation and the TUI.
"""
from __future__ import annotations

from dataclasses import asdict

from hydra.core.runtime_state import PluginStatusReader, RuntimeSnapshot
from hydra.core.state_models import AppState, User


def public_user(user: User) -> dict:
    """Return user metadata without exposing protocol secrets."""
    payload = asdict(user)
    payload.pop("credentials", None)
    devices = payload.pop("devices", {}) or {}
    payload["devices_registered"] = len(devices)
    # The identifier is a salted hash of what the client reported; a short
    # prefix is enough to recognise a device without publishing the full id.
    payload["devices"] = [
        {
            "id": str(device_id)[:12],
            "source": str(record.get("source", "")),
            "client": str(record.get("user_agent", "")),
            "address": str(record.get("address", "")),
            "first_seen": str(record.get("first_seen", "")),
            "last_seen": str(record.get("last_seen", "")),
        }
        for device_id, record in sorted(
            devices.items(),
            key=lambda item: str(item[1].get("last_seen", "")),
            reverse=True,
        )
        if isinstance(record, dict)
    ]
    payload["protocols"] = sorted(user.credentials)
    return payload


def build_status(
    state: AppState,
    status_reader: PluginStatusReader,
) -> dict:
    """Build a JSON-safe status snapshot with effective runtime flags."""
    plugins = status_reader(state)
    runtime = RuntimeSnapshot.from_statuses(plugins)
    network = asdict(state.network)
    network["clash_api_auth_configured"] = bool(
        network.pop("clash_api_secret", ""),
    )
    dnscrypt = plugins.get("dnscrypt", {})
    configured_dnscrypt = state.protocols.get("dnscrypt")
    # Keep the established status fields while deriving desired and effective
    # values from their respective single sources of truth.
    network["configured_dnscrypt_enabled"] = bool(
        configured_dnscrypt and configured_dnscrypt.enabled
    )
    network["dnscrypt_enabled"] = bool(
        dnscrypt.get("enabled") or dnscrypt.get("running")
    )
    from hydra.core.sni_router import audit_routes
    tls_mux = audit_routes(state).as_dict()
    return {
        "version": state.version,
        "users": len(state.users),
        "network": network,
        "plugins": plugins,
        "runtime": runtime.as_dict(),
        "tls_mux": tls_mux,
        "certificates": {
            "checked_at": str(state.install.get("certificates_last_check", "")),
            "entries": list(state.install.get("certificates_report", []) or []),
        },
    }
