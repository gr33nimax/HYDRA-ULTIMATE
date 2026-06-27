"""
HYDRA CLI entry — headless flags and interactive main loop.

Imported by main.py instead of exec(_core).
"""
from __future__ import annotations

import json
import os
import sys
import time as _time
from datetime import datetime as _datetime
from pathlib import Path

# Load core runtime (monkey-patches input(), defines panel API)
import vless_installer._core as core

from vless_installer._core import (  # noqa: F401 — re-export for main.py compat
    ASN_CACHE_DB,
    CYAN,
    DIM,
    GREEN,
    LOG_FILE,
    NC,
    RED,
    TOTAL_CPU,
    TOTAL_RAM,
    WHITE,
    BOLD,
    YELLOW,
    _asn_cache_connect,
    _asn_cache_delete,
    _autoban_run_once,
    _init_pkg_mgr,
    _scheduled_backup_run,
    _smart_recover,
    _traffic_snapshot_save,
    _ttl_check_and_expire,
    die,
    do_quick_status,
    ensure_startup_dependencies,
    get_server_country_cached,
    info,
    log_to_file,
    main_menu,
    print_banner,
)

_CHECKPOINT_FILE = Path("/var/lib/xray-installer/checkpoint.json")
_MAX_RETRIES = 5


def _legacy_cli_disabled(feature: str) -> None:
    print(
        f"[HYDRA] {feature}: недоступно (legacy-модуль удалён в HYDRA-only сборке)",
        file=sys.stderr,
    )
    sys.exit(0)


def _checkpoint_save(stage: str) -> None:
    try:
        _CHECKPOINT_FILE.write_text(
            json.dumps({"stage": stage, "ts": _datetime.now().isoformat()})
        )
    except Exception:
        pass


def _checkpoint_clear() -> None:
    try:
        _CHECKPOINT_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def run_headless(argv: list[str] | None = None) -> bool:
    """
    Handle CLI flags. Returns True if the process should exit (flag handled).
  """
    argv = argv if argv is not None else sys.argv

    if "--switch-mode-a" in argv or "--switch-mode-b" in argv:
        print("[HYDRA] --switch-mode-a/b: удалено (каскад VLESS не поддерживается)", file=sys.stderr)
        sys.exit(1)

    if "--clear-asn-cache" in argv:
        idx = argv.index("--clear-asn-cache")
        target = argv[idx + 1].strip() if idx + 1 < len(argv) else "all"
        if target.lower() in ("all", ""):
            try:
                if ASN_CACHE_DB.exists():
                    conn = _asn_cache_connect()
                    rows = conn.execute("SELECT key FROM prefix_cache").fetchall()
                    conn.execute("DELETE FROM prefix_cache")
                    conn.commit()
                    conn.close()
                    print(f"[ASN кэш] Удалено {len(rows)} записей из {ASN_CACHE_DB}")
                else:
                    print("[ASN кэш] БД не существует — нечего сбрасывать")
            except Exception as e:
                print(f"[ASN кэш] Ошибка: {e}", file=sys.stderr)
                sys.exit(1)
        elif target.lower() in ("ru", "ru_delegated"):
            _asn_cache_delete("ru_delegated")
            print("[ASN кэш] Удалена запись 'ru_delegated'")
        else:
            asn = target.upper()
            if not asn.startswith("AS"):
                asn = f"AS{asn}"
            _asn_cache_delete(f"asn:{asn}")
            print(f"[ASN кэш] Удалена запись 'asn:{asn}'")
        sys.exit(0)

    if "--warp-sync-routes" in argv:
        if os.geteuid() != 0:
            print("ERROR: требуются права root", file=sys.stderr)
            sys.exit(1)
        from vless_installer.modules.warp_universal import sync_routes
        sync_routes()
        sys.exit(0)

    if "--update-ru-subnets" in argv or "--update-as-direct" in argv:
        _legacy_cli_disabled("Xray routing (RU subnets / AS-direct)")

    if "--dpi-check" in argv:
        if os.geteuid() != 0:
            print("ERROR: требуются права root", file=sys.stderr)
            sys.exit(1)
        _legacy_cli_disabled("DPI detector")

    if "--smart-balance" in argv:
        if os.geteuid() != 0:
            print("ERROR: требуются права root", file=sys.stderr)
            sys.exit(1)
        _legacy_cli_disabled("Smart Balancer")

    if "--pinned-fallback-check" in argv:
        if os.geteuid() != 0:
            print("ERROR: требуются права root", file=sys.stderr)
            sys.exit(1)
        _legacy_cli_disabled("Pinned fallback")

    if any(a.startswith("--h2-") for a in argv):
        _legacy_cli_disabled("Hysteria2")

    if "--status" in argv:
        _init_pkg_mgr()
        do_quick_status()
        sys.exit(0)

    if "--autoban" in argv:
        if os.geteuid() != 0:
            sys.exit(1)
        _autoban_run_once()
        sys.exit(0)

    if "--traffic-snapshot" in argv:
        if os.geteuid() != 0:
            print("ERROR: требуются права root", file=sys.stderr)
            sys.exit(1)
        _traffic_snapshot_save()
        sys.exit(0)

    if "--scheduled-backup" in argv:
        if os.geteuid() != 0:
            print("ERROR: требуются права root", file=sys.stderr)
            sys.exit(1)
        _scheduled_backup_run()
        sys.exit(0)

    if "--tg-event" in argv:
        from vless_installer.modules.tg_bot import tg_notify_event
        idx = argv.index("--tg-event")
        if idx + 2 < len(argv):
            tg_notify_event(argv[idx + 1], argv[idx + 2])
        elif idx + 1 < len(argv):
            tg_notify_event(argv[idx + 1])
        sys.exit(0)

    if "--ttl-check" in argv:
        if os.geteuid() != 0:
            print("ERROR: требуются права root", file=sys.stderr)
            sys.exit(1)
        removed = _ttl_check_and_expire()
        if removed:
            print(f"[TTL] Удалено {removed} пользователей с истёкшим сроком")
        else:
            print("[TTL] Истёкших пользователей нет")
        sys.exit(0)

    if "--ingress-geoip-update" in argv:
        if os.geteuid() != 0:
            print("ERROR: требуются права root", file=sys.stderr)
            sys.exit(1)
        from vless_installer.modules.ingress_geoip import (
            _ingress_enable,
            _ingress_remove,
            _ingress_state_load,
        )
        st = _ingress_state_load()
        if not st.get("enabled"):
            print("[ingress-geoip] Блокировка не включена — пропуск")
            sys.exit(0)
        port = st.get("port", 443)
        print(f"[ingress-geoip] Обновляю РФ-подсети, порт {port}...")
        _ingress_remove()
        _ingress_enable(port)
        print("[ingress-geoip] Готово")
        sys.exit(0)

    return False


def run_interactive() -> None:
    """Main TUI loop with package-recovery retries."""
    from vless_installer import __version__

    for attempt in range(_MAX_RETRIES + 1):
        try:
            if attempt == 0:
                _init_pkg_mgr()
                if os.geteuid() != 0:
                    die(f"Запустите от root: sudo python3 {sys.argv[0]}")
                _checkpoint_save("ensure_startup_dependencies")
                ensure_startup_dependencies()
                print_banner()
                print()
                _cc, _cn, _flag = get_server_country_cached()
                info(
                    f"HYDRA Multi-Proxy Manager v{__version__} | "
                    f"RAM: {TOTAL_RAM}MB | CPU: {TOTAL_CPU} | {_flag} {_cn} ({_cc})"
                )
                print()
                _time.sleep(1)
            else:
                print()
                info(f"Повторная попытка после установки пакета (попытка {attempt}/{_MAX_RETRIES})...")
                print()

            _checkpoint_save("main_menu")
            main_menu()
            _checkpoint_clear()
            break

        except KeyboardInterrupt:
            print()
            print(f"{GREEN}До свидания! 👋{NC}")
            log_to_file("INFO", "Скрипт завершён пользователем (Ctrl+C)")
            _checkpoint_clear()
            sys.exit(0)

        except FileNotFoundError as fnf:
            if not _smart_recover(fnf):
                print()
                print(f"{RED}Восстановление невозможно. Скрипт остановлен.{NC}")
                print(f"{DIM}Лог: {LOG_FILE}{NC}")
                sys.exit(1)
            print()
            print(f"{CYAN}{'═' * 64}{NC}")
            print(f"{CYAN}  Пакет установлен. Как продолжить?{NC}")
            print(f"{CYAN}{'═' * 64}{NC}")
            print(f"  {DIM}[{NC}{WHITE}{BOLD}C{NC}{DIM}]{NC}  {GREEN}Продолжить с текущего места{NC}")
            print(f"  {DIM}[{NC}{WHITE}{BOLD}R{NC}{DIM}]{NC}  Начать установку заново (с нуля)")
            print(f"  {DIM}[{NC}{RED}{BOLD}Q{NC}{DIM}]{NC}  Выйти")
            print()
            try:
                cont = input(f"{CYAN}  Выбор [C/R/Q]:{NC} ").strip().upper()
            except (KeyboardInterrupt, EOFError):
                cont = "Q"
            if cont == "Q":
                print(f"{YELLOW}Выход.{NC}")
                sys.exit(1)
            if cont == "R":
                info("Перезапуск установки с нуля...")
                _checkpoint_clear()
                os.execv(sys.executable, [sys.executable] + sys.argv)
            else:
                info("Продолжаю с текущего места...")
                continue

        except SystemExit:
            raise

        except Exception as exc:
            import traceback as tb
            print()
            print(f"{RED}[CRITICAL]{NC} Неожиданная ошибка: {exc}")
            print(f"{DIM}{tb.format_exc()}{NC}")
            log_to_file("ERROR", f"Неожиданная ошибка: {exc}\n{tb.format_exc()}")
            print(f"{DIM}Лог: {LOG_FILE}{NC}")
            sys.exit(1)
    else:
        print()
        print(f"{RED}[ERROR]{NC} Исчерпан лимит авто-восстановлений ({_MAX_RETRIES}).")
        print(f"{YELLOW}[HINT]{NC}  Запустите ensure_startup_dependencies() вручную или")
        print(f"         проверьте лог: {LOG_FILE}")
        sys.exit(1)


def main(argv: list[str] | None = None) -> None:
    if argv is not None:
        sys.argv = argv
    run_headless()
    run_interactive()
