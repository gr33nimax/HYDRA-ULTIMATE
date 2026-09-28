"""HydraCore contracts that a VPS runtime must satisfy for native VK Calls."""

from __future__ import annotations

HYDRACORE_CORE_ID = "io.hydrabox.hydracore"
HYDRACORE_VPS_CONTRACT_VERSION = 1
HYDRACORE_API_VERSION = 2


def supports_vps_contract(payload: object) -> bool:
    """Accept the one VPS runtime shape that can run native vk_parasite Calls."""
    return bool(
        isinstance(payload, dict)
        and payload.get("contract_version") == HYDRACORE_VPS_CONTRACT_VERSION
        and payload.get("core_id") == HYDRACORE_CORE_ID
        and payload.get("role") == "vps"
        and payload.get("calls_mode") == "vk_parasite"
    )


def supports_legacy_vps_capabilities(payload: object) -> bool:
    """Accept the capability document a core printed before the contract replaced it.

    Such a core still speaks the wire HYDRA uses, but it cannot print a document that did not
    exist when it was built. Reading only the contract turned a working server into one that
    cannot update at all: the gate asked the installed core for a shape it can never produce,
    and reported the refusal as a missing wire version the core in fact speaks.

    This is the same bar the previous HYDRA applied — identity, the VPS role, the native
    vk_parasite mode — and nothing weaker.
    """
    if not isinstance(payload, dict) or payload.get("api_version") != HYDRACORE_API_VERSION:
        return False
    identity = payload.get("identity")
    features = payload.get("features")
    protocols = payload.get("protocols")
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


def supports_native_vk_calls(payload: object) -> bool:
    """Either document: the product contract, or the capability answer that preceded it."""
    return supports_vps_contract(payload) or supports_legacy_vps_capabilities(payload)


__all__ = [
    "HYDRACORE_API_VERSION",
    "HYDRACORE_CORE_ID",
    "HYDRACORE_VPS_CONTRACT_VERSION",
    "supports_legacy_vps_capabilities",
    "supports_native_vk_calls",
    "supports_vps_contract",
]
