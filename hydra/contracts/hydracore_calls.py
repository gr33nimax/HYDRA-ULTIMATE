"""Minimal Hydracore VPS capability contract for native VK Calls."""
from __future__ import annotations

HYDRACORE_CORE_ID = "io.hydrabox.hydracore"


def supports_vps_calls(payload: object) -> bool:
    """Accept any valid Hydracore VPS build providing the native vk_parasite transport."""
    if not isinstance(payload, dict) or payload.get("api_version") != 2:
        return False
    identity = payload.get("identity", {})
    features = payload.get("features", {})
    protocols = payload.get("protocols", {})
    modes = protocols.get("call_modes", ()) if isinstance(protocols, dict) else ()
    return bool(
        isinstance(identity, dict)
        and identity.get("core_id") == HYDRACORE_CORE_ID
        and identity.get("role") == "vps"
        and isinstance(features, dict)
        and features.get("call_vk_parasite") is True
        and isinstance(modes, list)
        and "vk_parasite" in modes
    )


__all__ = [
    "HYDRACORE_CORE_ID",
    "supports_vps_calls",
]
