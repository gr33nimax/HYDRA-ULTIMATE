"""Read-only host readiness checks for support and automation."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from hydra.core.host import HOST
from hydra.core.state import AppState, STATE_DIR, validate_state


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
    required_failures = [item["name"] for item in checks if item["required"] and not item["ok"]]
    warnings = [item["name"] for item in checks if not item["required"] and not item["ok"]]
    return {
        "ok": not required_failures,
        "required_failures": required_failures,
        "warnings": warnings,
        "checks": checks,
    }
