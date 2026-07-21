#!/usr/bin/env python3
"""
HYDRA v2.5.2-dev — Multi-Protocol Proxy Manager
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


def main() -> None:
    """Главная точка входа."""
    if len(sys.argv) > 1:
        from hydra.cli import main as cli_main
        raise SystemExit(cli_main(sys.argv[1:]))
    check_root()
    check_python()

    from hydra.core.state import load_state
    from hydra.ui.menus import main_menu

    try:
        state = load_state()
    except Exception as e:
        print(f"ERROR: Не удалось загрузить состояние: {e}", file=sys.stderr)
        sys.exit(1)

    # A git/bootstrap update may replace daemon code without changing user
    # settings. Reconcile its revision-tagged unit once on TUI startup so the
    # new process is picked up without forcing restarts on every apply_config.
    if os.name != "nt":
        try:
            from hydra.core.orchestrator import reconcile_traffic_daemon
            reconcile_traffic_daemon(state)
        except Exception:
            pass

    try:
        main_menu(state)
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
