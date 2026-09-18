"""Side-effect-free upgrade readiness checks."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from hydra import __version__
from hydra.core.state_format import STATE_FORMAT_VERSION
from hydra.core.state_models import AppState, validate_state
from hydra.core.host import HOST
from hydra.utils.commands import CommandError


def _dirty_worktree_detail(entries: list[str], limit: int = 5) -> str:
    """Name what makes the checkout dirty: an operator cannot clean what is unnamed."""
    shown = ", ".join(entries[:limit])
    remaining = len(entries) - limit
    suffix = f" (+{remaining} more)" if remaining > 0 else ""
    return f"local changes detected: {shown}{suffix}"


def check_upgrade(state: AppState, project_dir: Path | None = None) -> dict:
    """Check whether local state and checkout are safe to upgrade."""
    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str, required: bool = True) -> None:
        checks.append({"name": name, "ok": bool(ok), "required": required, "detail": detail})

    try:
        validate_state(state)
        record(
            "state",
            state.format_version == STATE_FORMAT_VERSION,
            f"format {state.format_version}, supported {STATE_FORMAT_VERSION}",
        )
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
            entries = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            clean = result.returncode == 0 and not entries
            record("git_worktree", clean, "clean" if clean else _dirty_worktree_detail(entries))
        except CommandError as exc:
            record("git_worktree", False, str(exc))
    else:
        record("git_worktree", True, "archive installation; git check skipped", required=False)

    failures = [item["name"] for item in checks if item["required"] and not item["ok"]]
    return {
        "ready": not failures,
        "current_version": __version__,
        # Kept for compatibility with existing machine-readable CLI consumers.
        "state_schema": state.format_version,
        "backup_required": True,
        "failures": failures,
        "checks": checks,
    }
