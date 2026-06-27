#!/usr/bin/env python3
"""
vless_installer/modules/hydra_sync_agent.py
───────────────────────────────────────────────────────────────────────────────
Периодический агент фоновой проверки лимитов трафика и TTL для пользователей.
Запускается через systemd.timer каждые 5 минут.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _bootstrap_install_path() -> None:
    """Находит корень HYDRA даже при запуске через systemd/cron."""
    candidates: list[Path] = []

    env = os.environ.get("HYDRA_INSTALL_ROOT", "").strip()
    if env:
        candidates.append(Path(env))

    here = Path(__file__).resolve()
    candidates.append(here.parents[2])

    for extra in sys.path:
        if extra:
            candidates.append(Path(extra))

    seen: set[Path] = set()
    for raw in candidates:
        try:
            path = raw.resolve()
        except OSError:
            continue
        if path in seen:
            continue
        seen.add(path)
        if (path / "main.py").exists() and (path / "vless_installer/__init__.py").exists():
            s = str(path)
            if s not in sys.path:
                sys.path.insert(0, s)
            os.environ.setdefault("HYDRA_INSTALL_ROOT", s)
            return

    try:
        from vless_installer.runtime_paths import find_install_root

        root = find_install_root()
        if root:
            s = str(root)
            if s not in sys.path:
                sys.path.insert(0, s)
            os.environ.setdefault("HYDRA_INSTALL_ROOT", s)
            return
    except Exception:
        pass

    raise SystemExit(
        "Корень установки HYDRA не найден. "
        "Задайте HYDRA_INSTALL_ROOT или PYTHONPATH на каталог с main.py."
    )


_bootstrap_install_path()

try:
    from vless_installer.modules.user_lifecycle import check_and_sync_all_users_limits

    check_and_sync_all_users_limits()
except Exception as e:
    print(f"Error running sync agent: {e}", file=sys.stderr)
    sys.exit(1)
