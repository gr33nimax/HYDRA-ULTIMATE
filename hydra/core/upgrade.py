"""Side-effect-free upgrade readiness checks."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from hydra import __version__
from hydra.core.state import AppState, SCHEMA_VERSION, validate_state
from hydra.core.host import HOST
from hydra.utils.commands import CommandError


def check_upgrade(state: AppState, project_dir: Path | None = None) -> dict:
    """Check whether local state and checkout are safe to upgrade."""
    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str, required: bool = True) -> None:
        checks.append({"name": name, "ok": bool(ok), "required": required, "detail": detail})

    try:
        validate_state(state)
        record("state", state.version <= SCHEMA_VERSION, f"schema {state.version}, supported {SCHEMA_VERSION}")
    except Exception as exc:
        record("state", False, str(exc))
    record("python", sys.version_info >= (3, 10), sys.version.split()[0])

    root = Path(project_dir) if project_dir else Path(__file__).resolve().parents[2]
    if (root / ".git").exists() and HOST.which("git"):
        try:
            result = HOST.run(
                ["git", "-C", root, "status", "--porcelain"],
                text=True,
                timeout=10,
                env=os.environ.copy(),
            )
            clean = result.returncode == 0 and not result.stdout.strip()
            record("git_worktree", clean, "clean" if clean else "local changes detected")
        except CommandError as exc:
            record("git_worktree", False, str(exc))
    else:
        record("git_worktree", True, "archive installation; git check skipped", required=False)

    failures = [item["name"] for item in checks if item["required"] and not item["ok"]]
    return {
        "ready": not failures,
        "current_version": __version__,
        "state_schema": state.version,
        "backup_required": True,
        "failures": failures,
        "checks": checks,
    }
