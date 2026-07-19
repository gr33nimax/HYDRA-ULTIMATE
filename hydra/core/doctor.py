"""Read-only host readiness checks for support and automation."""
from __future__ import annotations

import os
import sys
from dataclasses import asdict
from pathlib import Path

from hydra.core.host import HOST
from hydra.core.state import AppState, STATE_DIR, validate_state
from hydra.core.runtime_state import RuntimeSnapshot


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> dict:
    return {"name": name, "ok": bool(ok), "required": required, "detail": detail}


def run_doctor(state: AppState) -> dict:
    """Return JSON-safe diagnostics without changing host state."""
    checks: list[dict] = []
    try:
        validate_state(state)
        checks.append(_check("state", True, f"schema {state.version}"))
    except Exception as exc:
        checks.append(_check("state", False, str(exc)))

    checks.append(_check(
        "python",
        sys.version_info >= (3, 10),
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    ))
    for command, required in (
        ("systemctl", os.name != "nt"),
        ("sing-box", False),
        ("nft", False),
        ("iptables", False),
    ):
        resolved = HOST.which(command)
        checks.append(_check(command, bool(resolved), resolved or "not found", required=required))

    state_dir = Path(STATE_DIR)
    writable = state_dir.exists() and os.access(state_dir, os.R_OK | os.W_OK)
    checks.append(_check(
        "state_directory",
        writable,
        f"{state_dir} ({'read/write' if writable else 'unavailable'})",
    ))
    try:
        from hydra.core.sni_router import audit_routes

        mux = audit_routes(state)
        if mux.ok:
            detail = "not required" if not mux.required else f"{len(mux.actual)} SNI routes"
        else:
            problems = [*mux.missing, *mux.stale, *mux.certificate_errors, *mux.errors]
            detail = "; ".join(problems) or "route audit failed"
        checks.append(_check("caddy_routes", mux.ok, detail, required=mux.required))
    except Exception as exc:
        checks.append(_check("caddy_routes", False, str(exc), required=True))
    required_failures = [item["name"] for item in checks if item["required"] and not item["ok"]]
    warnings = [item["name"] for item in checks if not item["required"] and not item["ok"]]
    reconciliation: dict = {"planned": [], "drift": {}}
    try:
        from hydra.core import orchestrator
        from hydra.plugins import registry
        from hydra.services.protocols import ProtocolService

        statuses = registry.status_all(state)
        runtime = RuntimeSnapshot.from_statuses(statuses)
        service = ProtocolService(orchestrator, registry).reconciliation()
        actions = service.plan(state)
        reconciliation = {
            "planned": [asdict(action) for action in actions],
            "drift": {
                name: drift
                for name, drift in runtime.drifts().items()
            },
        }
    except Exception as exc:
        # Diagnostics must remain useful even if an optional plugin is broken.
        reconciliation = {"planned": [], "drift": {}, "error": str(exc) or exc.__class__.__name__}
    return {
        "ok": not required_failures,
        "required_failures": required_failures,
        "warnings": warnings,
        "checks": checks,
        "reconciliation": reconciliation,
    }
