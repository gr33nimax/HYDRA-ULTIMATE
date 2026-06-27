"""
Единый поиск корня установки HYDRA (main.py + vless_installer/).

Используется systemd-юнитами, sync-agent, cron и ботами вместо хардкода
/opt/vless-ultimate.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Порядок: bootstrap default, затем типичные пути разработки/форка.
INSTALL_ROOT_CANDIDATES: tuple[str, ...] = (
    "/opt/vless-ultimate",
    "/opt/HYDRA-ULTIMATE",
    "/root/HYDRA-ULTIMATE",
    "/root/VLESS-Ultimate-Installer",
    "/opt/VLESS-Ultimate-Installer",
)

_MARKER_FILES: tuple[str, ...] = (
    "main.py",
    "vless_installer/__init__.py",
    "vless_installer/_core.py",
)


def _is_install_root(path: Path) -> bool:
    if not path.is_dir():
        return False
    return all((path / name).exists() for name in _MARKER_FILES)


def find_install_root(*, prefer: Path | None = None) -> Path | None:
    """
    Возвращает каталог с main.py и пакетом vless_installer, или None.
    """
    checked: list[Path] = []

    def _try(path: Path) -> Path | None:
        try:
            resolved = path.resolve()
        except OSError:
            return None
        if resolved in checked:
            return None
        checked.append(resolved)
        return resolved if _is_install_root(resolved) else None

    if prefer is not None:
        hit = _try(prefer)
        if hit:
            return hit

    # Текущий репозиторий (разработка / pip -e).
    pkg_dir = Path(__file__).resolve().parent
    for ancestor in (pkg_dir.parent, pkg_dir.parent.parent):
        hit = _try(ancestor)
        if hit:
            return hit

    # main.py в argv (cron, systemd WorkingDirectory).
    for arg in sys.argv:
        p = Path(arg)
        if p.name == "main.py" and p.is_file():
            hit = _try(p.parent)
            if hit:
                return hit

    env = os.environ.get("HYDRA_INSTALL_ROOT", "").strip()
    if env:
        hit = _try(Path(env))
        if hit:
            return hit

    for candidate in INSTALL_ROOT_CANDIDATES:
        hit = _try(Path(candidate))
        if hit:
            return hit

    return None


def require_install_root(*, prefer: Path | None = None) -> Path:
    root = find_install_root(prefer=prefer)
    if root is None:
        raise FileNotFoundError(
            "Корень установки HYDRA не найден. "
            f"Ожидается main.py в одном из: {', '.join(INSTALL_ROOT_CANDIDATES)}"
        )
    return root


def main_py_path(*, prefer: Path | None = None) -> Path:
    return require_install_root(prefer=prefer) / "main.py"


def pythonpath_env(*, prefer: Path | None = None) -> str:
    return str(require_install_root(prefer=prefer))


def module_path(relative: str, *, prefer: Path | None = None) -> Path:
    """Путь к файлу внутри vless_installer/, напр. modules/hydra_sync_agent.py."""
    root = require_install_root(prefer=prefer)
    rel = relative.replace("\\", "/").lstrip("/")
    if rel.startswith("vless_installer/"):
        rel = rel[len("vless_installer/") :]
    return root / "vless_installer" / rel


def ensure_sys_path(*, prefer: Path | None = None) -> Path:
    """Добавляет корень установки в sys.path, если его там ещё нет."""
    root = require_install_root(prefer=prefer)
    s = str(root)
    if s not in sys.path:
        sys.path.insert(0, s)
    return root
