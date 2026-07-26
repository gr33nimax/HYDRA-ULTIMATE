"""Stable paths for a managed HYDRA installation.

Release directories may change during an atomic upgrade.  Persistent unit
files must therefore point at the stable ``/opt/hydra`` entrypoint instead of
the physical directory behind that symlink.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


DEFAULT_INSTALL_ROOT = Path("/opt/hydra")
INSTALL_ROOT_ENV = "HYDRA_INSTALL_DIR"


def project_root(fallback: str | Path | None = None) -> Path:
    """Return the stable runtime root, with a repository fallback for tests."""
    configured = os.environ.get(INSTALL_ROOT_ENV, "").strip()
    if configured:
        return Path(configured)
    if (DEFAULT_INSTALL_ROOT / "main.py").is_file():
        return DEFAULT_INSTALL_ROOT
    if fallback is not None:
        return Path(fallback)
    return Path(__file__).resolve().parents[2]


def python_executable(root: str | Path | None = None) -> Path:
    """Return the managed virtualenv interpreter when it is available."""
    active_root = project_root(root) if root is not None else project_root()
    candidate = active_root / ".venv" / "bin" / "python"
    if candidate.is_file():
        return candidate
    return Path(sys.executable)


__all__ = [
    "DEFAULT_INSTALL_ROOT",
    "INSTALL_ROOT_ENV",
    "project_root",
    "python_executable",
]
