"""
vless_installer/modules/hydra_setup.py
──────────────────────────────────────────────────────────────────────────────
Мастер установки HYDRA и полное удаление стека (Naive, Mieru, AWG, боты, sub).

Точки входа из _core.py:
    do_hydra_setup_wizard()
    do_hydra_uninstall()
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from vless_installer.modules.box_renderer import (
    _box_back,
    _box_bottom,
    _box_info,
    _box_item,
    _box_row,
    _box_sep,
    _box_top,
    _box_warn,
)

_STATE_FILE = Path("/var/lib/xray-installer/state.json")
_BACKUP_DIR = Path("/var/lib/xray-installer/backups")


def _c() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED="\x1b[0;31m", GREEN="\x1b[0;32m", YELLOW="\x1b[1;33m",
            CYAN="\x1b[0;36m", BLUE="\x1b[0;34m", BOLD="\x1b[1m",
            DIM="\x1b[2m", NC="\x1b[0m",
        )
    return {k: "" for k in ("RED", "GREEN", "YELLOW", "CYAN", "BLUE", "BOLD", "DIM", "NC")}


_C = _c()
RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC = (
    _C["RED"], _C["GREEN"], _C["YELLOW"], _C["CYAN"],
    _C["BLUE"], _C["BOLD"], _C["DIM"], _C["NC"],
)


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, **kw)


def _ask_yn(prompt: str, default_yes: bool = True) -> bool:
    hint = "Y/n" if default_yes else "y/N"
    try:
        ans = input(f"{CYAN}{prompt} [{hint}]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return False
    if not ans:
        return default_yes
    return ans in ("y", "yes", "д", "да")


def _pause() -> None:
    try:
        input(f"\n{BLUE}Нажмите Enter...{NC}")
    except KeyboardInterrupt:
        pass


def _get_core():
    import importlib
    return importlib.import_module("vless_installer._core")


def _step_optimize() -> None:
    core = _get_core()
    _box_info("Применение sysctl / limits...")
    print()
    core.apply_sysctl_and_limits()
    print(f"  {GREEN}✓{NC}  Оптимизация применена.")
    _pause()


def _step_docker() -> None:
    from vless_installer.modules.amnezia_vpn import install_docker_engine, prepare_awg_environment

    if install_docker_engine():
        prepare_awg_environment()
    _pause()


def _step_naive() -> None:
    from vless_installer.modules.naiveproxy import _run_install
    _run_install()


def _step_mieru() -> None:
    from vless_installer.modules.mieru import _run_install
    _run_install()


def _step_awg() -> None:
    from vless_installer.modules.amnezia_vpn import (
        _container_exists,
        _docker_available,
        install_docker_engine,
        prepare_awg_environment,
        show_awg_client_instructions,
    )

    os.system("clear")
    _box_top("🛡️  AMNEZIAWG — ПОДГОТОВКА СЕРВЕРА")
    _box_row()

    if not _docker_available():
        _box_warn("Docker не установлен — устанавливаю...")
        _box_row()
        _box_bottom()
        print()
        if install_docker_engine():
            prepare_awg_environment()
    elif not _container_exists():
        prepare_awg_environment()

    show_awg_client_instructions()
    _pause()


def _step_background() -> None:
    core = _get_core()
    os.system("clear")
    _box_top("⚙️  ФОНОВЫЕ СЛУЖБЫ HYDRA")
    _box_row()
    _box_info("Sync-агент проверяет TTL и лимиты трафика каждые 5 мин.")
    _box_row()
    _box_bottom()
    print()

    if _ask_yn("Установить sync-агент (systemd timer)?", default_yes=True):
        core.install_sync_agent()

    if _ask_yn("Установить сервер подписок (sub-server)?", default_yes=False):
        try:
            port_raw = input(f"{CYAN}Порт подписок [8080]:{NC} ").strip() or "8080"
            port = int(port_raw)
        except (ValueError, KeyboardInterrupt):
            port = 8080
        from vless_installer.modules.sub_server import install_sub_service
        install_sub_service("0.0.0.0", port)
        print(f"  {GREEN}✓{NC}  Sub-server на порту {port}.")

    _pause()


def _step_dnscrypt() -> None:
    core = _get_core()
    os.system("clear")
    _box_top("🔒  DNSCRYPT (ОПЦИОНАЛЬНО)")
    _box_row()
    _box_warn("DNSCrypt может конфликтовать с WARP-маршрутизацией.")
    _box_warn("Рекомендуется включать только при понимании последствий.")
    _box_row()
    _box_bottom()
    print()
    if _ask_yn("Установить DNSCrypt-proxy?", default_yes=False):
        core.install_dnscrypt(force=False)
    _pause()


def do_hydra_setup_wizard() -> None:
    """Пошаговый мастер установки HYDRA-стека."""
    os.system("clear")
    print()
    _box_top("🚀  МАСТЕР УСТАНОВКИ HYDRA")
    _box_row(f"  {DIM}Последовательная настройка: оптимизация → протоколы → фон.{NC}")
    _box_sep()
    _box_item("1", "⚡ Оптимизация системы (sysctl / limits)")
    _box_item("2", "🐳 Docker + подготовка AWG")
    _box_item("3", "🔒 NaiveProxy (Caddy)")
    _box_item("4", "🔐 Mieru (mita)")
    _box_item("5", "🛡️  AmneziaWG — инструкция / подготовка")
    _box_item("6", "⚙️  Фоновые службы (sync-agent, sub-server)")
    _box_item("7", "🔒 DNSCrypt (опционально, с предупреждением)")
    _box_sep()
    _box_item("A", "▶ Запустить всё по порядку (рекомендуется)")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return

    steps = {
        "1": [_step_optimize],
        "2": [_step_docker],
        "3": [_step_naive],
        "4": [_step_mieru],
        "5": [_step_awg],
        "6": [_step_background],
        "7": [_step_dnscrypt],
    }
    if ch == "a":
        for fn in (
            _step_optimize, _step_docker, _step_naive, _step_mieru,
            _step_awg, _step_background, _step_dnscrypt,
        ):
            fn()
        return

    if ch in steps:
        for fn in steps[ch]:
            fn()
    elif ch in ("q", ""):
        return
    else:
        print(f"{YELLOW}Неверный выбор.{NC}")
        time.sleep(1)


def _backup_state() -> Path | None:
    if not _STATE_FILE.exists():
        return None
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = _BACKUP_DIR / f"state_pre_uninstall_{ts}.json"
    shutil.copy2(_STATE_FILE, dst)
    return dst


def do_hydra_uninstall() -> None:
    """Полное удаление HYDRA-стека с опциональным бэкапом state.json."""
    os.system("clear")
    print()
    _box_top("🗑️  УДАЛЕНИЕ HYDRA")
    _box_row()
    _box_warn("Будет удалено:")
    _box_row(f"  {DIM}• NaiveProxy (Caddy){NC}")
    _box_row(f"  {DIM}• Mieru (mita){NC}")
    _box_row(f"  {DIM}• AmneziaWG Docker-контейнер (если есть){NC}")
    _box_row(f"  {DIM}• Sub-server, Telegram-боты, sync-агент{NC}")
    _box_row(f"  {DIM}• DNSCrypt-proxy, WARP-маршруты{NC}")
    _box_row(f"  {DIM}• Legacy Xray/Nginx (если остались){NC}")
    _box_row()
    _box_warn("Введите HYDRA для подтверждения.")
    _box_row()
    _box_bottom()

    try:
        confirm_word = input(f"{YELLOW}Подтверждение:{NC} ").strip()
    except KeyboardInterrupt:
        print(f"\n{DIM}Отменено.{NC}")
        return
    if confirm_word != "HYDRA":
        print(f"{YELLOW}Отменено — слово подтверждения не совпало.{NC}")
        return

    try:
        ans = input(f"{RED}Удалить всё? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        print(f"\n{DIM}Отменено.{NC}")
        return
    if ans != "y":
        print(f"{DIM}Отменено.{NC}")
        return

    os.system("clear")
    print()
    _box_top("🗑️  УДАЛЕНИЕ HYDRA")
    _box_row()

    backup = _backup_state()
    if backup:
        _box_info(f"Бэкап state.json: {backup}")
    else:
        _box_info("state.json не найден — бэкап пропущен.")

    core = _get_core()

    # Telegram-боты
    try:
        from vless_installer.modules.tg_bot import (
            _stop_admin_bot_service,
            _stop_bot_service,
        )
        _box_info("Остановка Telegram-ботов...")
        _stop_bot_service()
        _stop_admin_bot_service()
    except Exception as e:
        _box_warn(f"Telegram-боты: {e}")

    # Sub-server
    try:
        from vless_installer.modules.sub_server import uninstall_sub_service
        _box_info("Удаление sub-server...")
        uninstall_sub_service()
    except Exception as e:
        _box_warn(f"sub-server: {e}")

    # Sync-agent
    try:
        core.uninstall_sync_agent()
    except Exception as e:
        _box_warn(f"sync-agent: {e}")

    # Naive + Mieru
    try:
        from vless_installer.modules.naiveproxy import _full_uninstall as naive_rm
        _box_info("Удаление NaiveProxy...")
        naive_rm(silent=True)
    except Exception as e:
        _box_warn(f"NaiveProxy: {e}")

    try:
        from vless_installer.modules.mieru import _full_uninstall as mieru_rm
        _box_info("Удаление Mieru...")
        mieru_rm(silent=True)
    except Exception as e:
        _box_warn(f"Mieru: {e}")

    # AWG container
    try:
        from vless_installer.modules.amnezia_vpn import (
            _container_exists,
            _container_remove,
        )
        if _container_exists():
            _box_info("Удаление AWG-контейнера...")
            _container_remove()
    except Exception as e:
        _box_warn(f"AWG: {e}")

    # WARP routes
    try:
        from vless_installer.modules.warp_universal import disable_warp_routing
        _box_info("Сброс WARP-маршрутизации...")
        disable_warp_routing()
    except Exception as e:
        _box_warn(f"WARP: {e}")

    # DNSCrypt
    _box_info("Удаление DNSCrypt-proxy...")
    for svc in ("dnscrypt-proxy",):
        _run(["systemctl", "stop", svc], check=False, capture_output=True)
        _run(["systemctl", "disable", svc], check=False, capture_output=True)
    for p in (
        Path("/usr/local/bin/dnscrypt-proxy"),
        Path("/etc/systemd/system/dnscrypt-proxy.service"),
    ):
        p.unlink(missing_ok=True)
    shutil.rmtree(Path("/etc/dnscrypt-proxy"), ignore_errors=True)
    for log_f in (
        "/var/log/dnscrypt-proxy.log",
        "/var/log/dnscrypt-blocked.log",
        "/var/log/dnscrypt-proxy-blocked.log",
    ):
        Path(log_f).unlink(missing_ok=True)

    # Legacy Xray
    _box_info("Очистка legacy Xray...")
    for svc in ("xray",):
        _run(["systemctl", "stop", svc], check=False, capture_output=True)
        _run(["systemctl", "disable", svc], check=False, capture_output=True)
    for p in (Path("/usr/local/bin/xray"), Path("/etc/systemd/system/xray.service")):
        p.unlink(missing_ok=True)
    shutil.rmtree(Path("/etc/systemd/system/xray.service.d"), ignore_errors=True)
    for d in (
        Path("/usr/local/etc/xray"),
        Path("/etc/xray"),
        Path("/var/log/xray"),
        Path("/var/lib/xray"),
    ):
        shutil.rmtree(d, ignore_errors=True)

    # Nginx (legacy)
    _box_info("Очистка legacy Nginx...")
    _run(["systemctl", "stop", "nginx"], check=False, capture_output=True)
    override = Path("/etc/systemd/system/nginx.service.d/after-xray.conf")
    override.unlink(missing_ok=True)
    try:
        override.parent.rmdir()
    except OSError:
        pass
    _run(["systemctl", "daemon-reload"], check=False, capture_output=True)
    pkg_mgr = getattr(core, "PKG_MGR", "apt")
    if pkg_mgr == "apt":
        _run(
            ["apt-get", "remove", "--purge", "-y", "nginx", "nginx-common"],
            check=False, capture_output=True,
        )
    else:
        _run(["dnf", "remove", "-y", "nginx"], check=False, capture_output=True)
    shutil.rmtree(Path("/etc/nginx"), ignore_errors=True)
    shutil.rmtree(Path("/var/log/nginx"), ignore_errors=True)

    # Очистка state (оставляем бэкап)
    if _STATE_FILE.exists():
        try:
            state = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
            state["hydra_uninstalled_at"] = datetime.now().isoformat()
            _STATE_FILE.write_text(
                json.dumps(state, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except Exception:
            pass

    _box_row()
    print(f"  {GREEN}✓{NC}  Удаление HYDRA завершено.")
    if backup:
        print(f"  {DIM}Бэкап конфигурации: {backup}{NC}")
    _box_bottom()
