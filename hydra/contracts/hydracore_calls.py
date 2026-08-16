"""Exact Hydracore VPS capability contract for native VK Calls."""
from __future__ import annotations

HYDRACORE_CORE_ID = "io.hydrabox.hydracore"
HYDRACORE_CORE_NAME = "HydraCore"
HYDRACORE_CALLS_WIRE = 9

_REQUIRED_SERVER_FEATURES = (
    "call_vk_parasite",
    "call_vk_four_lane_kcp",
    "call_vk_pre_kcp_admission",
    "call_vk_relay_flow_control",
    "call_vk_worker_hot_swap",
    "call_vk_flow_migration",
    "call_vk_turn_tcp_fallback",
    "call_vk_transport_health",
    "call_vk_parasite_server",
)


def supports_exact_vps_calls(payload: object) -> bool:
    """Accept only the coordinated wire-9 VPS build, never a close alias."""
    if not isinstance(payload, dict) or payload.get("api_version") != 2:
        return False
    identity = payload.get("identity", {})
    features = payload.get("features", {})
    protocols = payload.get("protocols", {})
    modes = protocols.get("call_modes", ()) if isinstance(protocols, dict) else ()
    wire = (
        protocols.get("call_vk_parasite_wire", {})
        if isinstance(protocols, dict)
        else {}
    )
    return bool(
        isinstance(identity, dict)
        and identity.get("core_id") == HYDRACORE_CORE_ID
        and identity.get("core_name") == HYDRACORE_CORE_NAME
        and identity.get("role") == "vps"
        and isinstance(features, dict)
        and all(features.get(name) is True for name in _REQUIRED_SERVER_FEATURES)
        and features.get("call_vk_parasite_client") is False
        and features.get("call_vk_eight_lane_kcp") is False
        and isinstance(modes, list)
        and modes == ["vk_parasite"]
        and isinstance(wire, dict)
        and wire.get("min") == HYDRACORE_CALLS_WIRE
        and wire.get("max") == HYDRACORE_CALLS_WIRE
    )


__all__ = [
    "HYDRACORE_CALLS_WIRE",
    "HYDRACORE_CORE_ID",
    "HYDRACORE_CORE_NAME",
    "supports_exact_vps_calls",
]
