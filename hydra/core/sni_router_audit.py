"""Read-only consistency auditing for persisted and rendered SNI routes."""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from hydra.core.sni_router_planning import CaddyRouteAudit
from hydra.core.state_models import AppState


def _collect_sni(node: object, actual: set[str]) -> None:
    if isinstance(node, dict):
        match = node.get("match")
        if isinstance(match, list):
            for matcher in match:
                if not isinstance(matcher, dict):
                    continue
                tls = matcher.get("tls")
                if isinstance(tls, dict) and isinstance(tls.get("sni"), list):
                    actual.update(str(value) for value in tls["sni"] if value)
        for value in node.values():
            _collect_sni(value, actual)
    elif isinstance(node, list):
        for value in node:
            _collect_sni(value, actual)


def audit_routes(
    state: AppState,
    *,
    config_path: Path,
    service_name: str,
    collect_backends: Callable[[AppState], list[dict]],
    needs_mux: Callable[[AppState], bool],
    is_active: Callable[[], bool],
) -> CaddyRouteAudit:
    """Compare persisted routes with the rendered artifact without mutating host state."""
    backends = collect_backends(state)
    expected = tuple(
        sorted(
            {
                str(item["domain"])
                for item in backends
                if item.get("domain")
            }
        )
    )
    required = needs_mux(state)
    if not required:
        return CaddyRouteAudit(
            ok=True,
            required=False,
            config_present=config_path.exists(),
            service_active=None,
            expected=expected,
            actual=(),
        )

    errors: list[str] = []
    actual: set[str] = set()
    config_present = config_path.is_file()
    if config_present:
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            tls_mux = (
                config.get("apps", {})
                .get("layer4", {})
                .get("servers", {})
                .get("tls_mux", {})
            )
            _collect_sni(tls_mux, actual)
        except (OSError, ValueError, TypeError) as exc:
            errors.append(f"invalid Caddy config: {exc}")
    else:
        errors.append(f"Caddy config missing: {config_path}")

    expected_set = set(expected)
    missing = tuple(sorted(expected_set - actual))
    stale = tuple(sorted(actual - expected_set))
    certificate_errors: list[str] = []
    for backend in backends:
        if backend["name"] not in {"anytls", "trusttunnel", "hysteria2"}:
            continue
        for key in ("cert_file", "key_file"):
            certificate = str(backend.get(key) or "")
            if not certificate:
                certificate_errors.append(
                    f"{backend['domain']}: {key} is not configured"
                )
            elif not Path(certificate).is_file():
                certificate_errors.append(
                    f"{backend['domain']}: {key} missing ({certificate})"
                )

    try:
        service_active: bool | None = is_active()
    except Exception as exc:
        service_active = None
        errors.append(f"cannot check {service_name}: {exc}")
    if service_active is False:
        errors.append(f"{service_name} is not active")

    return CaddyRouteAudit(
        ok=not (missing or stale or certificate_errors or errors),
        required=True,
        config_present=config_present,
        service_active=service_active,
        expected=expected,
        actual=tuple(sorted(actual)),
        missing=missing,
        stale=stale,
        certificate_errors=tuple(certificate_errors),
        errors=tuple(errors),
    )


__all__ = ["audit_routes"]
