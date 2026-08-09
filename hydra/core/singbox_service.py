"""Small service-observation helpers for the Sing-Box compatibility facade."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Callable

from hydra.core.state_kernel_models import KERNEL_HYDRACORE
from hydra.utils.commands import redact_text


def custom_kernel_selected(version: str | None, state_loader: Callable[[], Any]) -> bool:
    """Detect either an installed or desired custom core without mutating state."""
    if "hydracore" in (version or "").lower():
        return True
    try:
        return state_loader().kernel.provider == KERNEL_HYDRACORE
    except Exception:
        return False


def inspect_current_config(
    config_path: Path,
    find_binary: Callable[[], Path | None],
    run: Callable[..., Any],
) -> tuple[bool | None, str]:
    """Validate the installed config and redact the candidate's error detail."""
    if not config_path.exists():
        return None, ""
    binary = find_binary()
    if binary is None:
        return None, ""
    try:
        checked = run([str(binary), "check", "-c", str(config_path)])
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if checked.returncode == 0:
        return True, ""
    output = str(checked.stderr or checked.stdout or "unknown error").strip()
    return False, redact_text(output.splitlines()[-1] if output else "unknown error")


def configured_inbound_exists(config_path: Path, tag: str) -> bool:
    """Inspect the applied artifact for a single inbound tag."""
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return False
    return any(
        isinstance(inbound, dict) and inbound.get("tag") == tag
        for inbound in config.get("inbounds", [])
    )


def failure_detail(run: Callable[..., Any]) -> str:
    """Return a short systemd journal detail suitable for TUI and logs."""
    try:
        result = run(
            ["journalctl", "-u", "sing-box", "-n", "8", "--no-pager"],
            timeout=5,
        )
        output = result.stdout or result.stderr or ""
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if lines:
            return redact_text(lines[-1])
    except (OSError, subprocess.SubprocessError):
        pass
    return "служба не перешла в стабильное состояние"


__all__ = [
    "configured_inbound_exists",
    "custom_kernel_selected",
    "failure_detail",
    "inspect_current_config",
]
