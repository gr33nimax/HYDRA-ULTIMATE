#!/usr/bin/env python3
"""
HYDRA v3.0.0 — Multi-Protocol Proxy Manager
====================================================

Точка входа. Запуск: sudo python3 main.py

Архитектура:
  main.py → TUI (hydra.ui.menus) → Ядро (hydra.core) + Плагины (hydra.plugins)

Никаких exec(), никаких глобальных переменных.
"""

import sys
import os
from pathlib import Path

# Добавляем корень проекта в PYTHONPATH (resolve — чтобы работал и symlink `hydra`)
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def check_root() -> None:
    """Проверяет права root."""
    if os.name == "nt":
        return
    if os.geteuid() != 0:
        print("ERROR: Запустите от root: sudo python3 main.py", file=sys.stderr)
        sys.exit(1)


def check_python() -> None:
    """Проверяет версию Python."""
    if sys.version_info < (3, 10):
        print("ERROR: Требуется Python 3.10+", file=sys.stderr)
        sys.exit(1)


def _is_managed_node_install() -> bool:
    marker = Path("/etc/hydra/managed-node/identity.json")
    return marker.exists() or marker.is_symlink()


def main() -> None:
    """Главная точка входа."""
    if len(sys.argv) > 1:
        if _is_managed_node_install():
            arguments = sys.argv[1:]
            if arguments == ["uninstall", "--yes"]:
                check_root()
            elif arguments != ["--version"]:
                print("ERROR: на управляемой ноде разрешены только version и подтверждённый uninstall", file=sys.stderr)
                raise SystemExit(2)
        from hydra.cli import main as cli_main

        raise SystemExit(cli_main(sys.argv[1:]))
    check_root()
    check_python()
    if _is_managed_node_install():
        from hydra.bootstrap import production_application
        from hydra.core.state import load_state
        from hydra.ui._menus.node_emergency import run_node_emergency_menu

        run_node_emergency_menu(load_state(), production_application())
        return

    from hydra.core.state import load_state
    from hydra.bootstrap import production_application
    from hydra.ui.menus import main_menu

    try:
        state = load_state()
    except Exception as e:
        print(f"ERROR: Не удалось загрузить состояние: {e}", file=sys.stderr)
        sys.exit(1)

    application = production_application()

    # A git/bootstrap update may replace daemon code without changing user
    # settings. Reconcile its revision-tagged unit once on TUI startup so the
    # new process is picked up without forcing restarts on every apply_config.
    if os.name != "nt":
        try:
            application.reconcile_background_services(state)
        except Exception:
            pass

    try:
        main_menu(state, application)
    except KeyboardInterrupt:
        print(f"\nДо свидания! 👋")
        sys.exit(0)
    except Exception as e:
        print(f"\n[CRITICAL] Неожиданная ошибка: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
