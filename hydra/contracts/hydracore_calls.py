"""Minimal HydraCore VPS contract for native VK Calls."""

from __future__ import annotations

HYDRACORE_CORE_ID = "io.hydrabox.hydracore"
HYDRACORE_VPS_CONTRACT_VERSION = 1


def supports_vps_contract(payload: object) -> bool:
    """Accept the one VPS runtime shape that can run native vk_parasite Calls."""
    return bool(
        isinstance(payload, dict)
        and payload.get("contract_version") == HYDRACORE_VPS_CONTRACT_VERSION
        and payload.get("core_id") == HYDRACORE_CORE_ID
        and payload.get("role") == "vps"
        and payload.get("calls_mode") == "vk_parasite"
    )


__all__ = [
    "HYDRACORE_CORE_ID",
    "HYDRACORE_VPS_CONTRACT_VERSION",
    "supports_vps_contract",
]
