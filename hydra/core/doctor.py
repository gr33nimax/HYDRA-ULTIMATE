"""Read-only host readiness checks for support and automation."""
from __future__ import annotations

import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from hydra.core.host import HOST
from hydra.core.state import STATE_DIR
from hydra.core.state_models import AppState, validate_state
from hydra.core.runtime_state import RuntimeSnapshot


class _ReconciliationPlanner(Protocol):
    def plan(self, state: AppState) -> list[object]: ...


class DoctorProtocolOperations(Protocol):
    """Read-only protocol view supplied by an application adapter."""

    def statuses(self, state: AppState | None = None) -> dict[str, dict]: ...
    def reconciliation(self) -> _ReconciliationPlanner: ...


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> dict:
    return {"name": name, "ok": bool(ok), "required": required, "detail": detail}


def _summary(checks: list[dict]) -> dict:
    required_failures = [
        item["name"]
        for item in checks
        if item["required"] and not item["ok"]
    ]
    warnings = [
        item["name"]
        for item in checks
        if not item["required"] and not item["ok"]
    ]
    return {
        "ok": not required_failures,
        "required_failures": required_failures,
        "warnings": warnings,
        "checks": checks,
    }


def run_host_preflight(state: AppState) -> dict:
    """Check host prerequisites not covered by configuration planning."""
    del state
    checks: list[dict] = []
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
        checks.append(
            _check(
                command,
                bool(resolved),
                resolved or "not found",
                required=required,
            ),
        )

    state_dir = Path(STATE_DIR)
    writable = state_dir.exists() and os.access(
        state_dir,
        os.R_OK | os.W_OK,
    )
    checks.append(_check(
        "state_directory",
        writable,
        f"{state_dir} ({'read/write' if writable else 'unavailable'})",
    ))
    return _summary(checks)


def run_doctor(
    state: AppState,
    protocols: DoctorProtocolOperations | None = None,
) -> dict:
    """Compatibility report combining the formerly separate read models."""
    checks: list[dict] = []
    try:
        validate_state(state)
        checks.append(_check("state", True, f"schema {state.version}"))
    except Exception as exc:
        checks.append(_check("state", False, str(exc)))

    checks.extend(run_host_preflight(state)["checks"])
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
    summary = _summary(checks)
    reconciliation: dict = {"planned": [], "drift": {}}
    if protocols is None:
        return {
            **summary,
            "reconciliation": reconciliation,
        }
    try:
        statuses = protocols.statuses(state)
        runtime = RuntimeSnapshot.from_statuses(statuses)
        service = protocols.reconciliation()
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
        **summary,
        "reconciliation": reconciliation,
    }
