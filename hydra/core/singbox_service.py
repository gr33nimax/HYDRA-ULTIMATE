"""Small service-observation helpers for the Sing-Box compatibility facade."""
from __future__ import annotations

import subprocess
from typing import Any, Callable


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
            return lines[-1]
    except (OSError, subprocess.SubprocessError):
        pass
    return "служба не перешла в стабильное состояние"


__all__ = ["failure_detail"]
