"""Health verification for both VLESS security modes."""
from __future__ import annotations

from hydra.plugins.base import HealthResult
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.vless_xhttp.security import (
    DECOY_ROUTE_KEY,
    handshake_target,
    is_reality,
)


INBOUND_TAG = "vless-xhttp-in"


def check(state: PluginStateAccess) -> HealthResult:
    """Verify the runtime actually serves the desired VLESS endpoint."""
    from hydra.core import singbox

    protocol = state.protocols.get("vless")
    config = protocol.config if protocol is not None else {}
    checks = {
        "sing_box": singbox.is_running(),
        "vless_xhttp_inbound": singbox.has_configured_inbound(INBOUND_TAG),
    }
    if is_reality(config):
        return _reality(state, config, checks)
    return _certificate(state, config, checks)


def _reality(
    state: PluginStateAccess,
    config: dict,
    checks: dict[str, bool],
) -> HealthResult:
    """Reality owns the handshake; only routing to it can be verified here."""
    try:
        handshake = handshake_target(config)
    except ValueError as exc:
        return HealthResult(False, str(exc), "error", checks)

    from hydra.core import sni_router

    behind_mux = sni_router.needs_mux(state)
    checks["reality_keys"] = bool(
        str(config.get("reality_private_key", "")).strip()
        and str(config.get("reality_public_key", "")).strip(),
    )
    detail = ""
    if behind_mux:
        checks["caddy_l4"] = sni_router.is_active()
        route_active = False
        if all(checks.values()):
            audit = sni_router.audit_routes(state)
            route_active = audit.ok and handshake in audit.actual
        checks["caddy_route"] = route_active
    healthy = all(checks.values())
    if not checks["sing_box"]:
        detail = "sing-box service is not active"
    elif not checks["vless_xhttp_inbound"]:
        detail = "VLESS inbound is missing from Sing-Box config"
    elif not checks["reality_keys"]:
        detail = "Reality keypair is missing from the desired state"
    elif behind_mux and not checks.get("caddy_l4"):
        detail = "Caddy L4 service is not active"
    elif behind_mux and not checks.get("caddy_route"):
        detail = f"Caddy does not route SNI {handshake} to VLESS Reality"
    return HealthResult(
        healthy,
        detail,
        "ok" if healthy else "error",
        checks,
    )


def _certificate(
    state: PluginStateAccess,
    config: dict,
    checks: dict[str, bool],
) -> HealthResult:
    """Certificate mode depends on Caddy terminating TLS for the domain."""
    from hydra.core import sni_router

    domain = str(config.get("domain", "")).strip().lower().rstrip(".")
    route = config.get(DECOY_ROUTE_KEY)
    checks["caddy_l4"] = sni_router.is_active()
    route_declared = (
        isinstance(route, dict)
        and route.get("kind") == "http_path_proxy"
    )
    route_active = False
    tls_healthy = False
    tls_detail = ""
    if all(checks.values()) and route_declared:
        audit = sni_router.audit_routes(state)
        route_active = audit.ok and bool(domain) and domain in audit.actual
        if route_active:
            tls_healthy, tls_detail = sni_router.probe_tls_route(domain)
    checks["caddy_route"] = route_active
    checks["tls_handshake"] = tls_healthy
    healthy = all(checks.values()) and route_declared
    detail = ""
    if not checks["sing_box"]:
        detail = "sing-box service is not active"
    elif not checks["vless_xhttp_inbound"]:
        detail = "VLESS XHTTP inbound is missing from Sing-Box config"
    elif not checks["caddy_l4"]:
        detail = "Caddy L4 service is not active"
    elif not route_declared:
        detail = "VLESS XHTTP Caddy route metadata is missing"
    elif not route_active:
        detail = (
            "VLESS XHTTP Caddy route is not active for "
            f"{domain or 'configured domain'}"
        )
    elif not tls_healthy:
        detail = f"VLESS XHTTP TLS route failed: {tls_detail}"
    return HealthResult(
        healthy,
        detail,
        "ok" if healthy else "error",
        checks,
    )


__all__ = ["INBOUND_TAG", "check"]
