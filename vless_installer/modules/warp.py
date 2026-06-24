"""
vless_installer/modules/warp.py
───────────────────────────────────────────────────────────────────────────────
Cloudflare WARP — установка и управление.

Полностью переписанный модуль:
  • Безопасная установка с проверкой ключей и репозиториев
  • Безопасный запуск с исключенным дефолтным роутом (0.0.0.0/0), чтобы не ломать сеть
  • Интеграция с warp_universal.py для выборочного роутинга
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_item_exit,
    RED, GREEN, YELLOW, CYAN, BLUE, DIM, NC,
)

LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [WARP-{level}] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("OK", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def error(msg: str)   -> None: print(f"{RED}[ERR]{NC}   {msg}"); _log("ERR", msg)

def _run(cmd: list, capture: bool = False, check: bool = False, quiet: bool = False) -> subprocess.CompletedProcess:
    kw = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def command_exists(cmd: str) -> bool:
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0

def _get_pkg_mgr() -> str:
    if command_exists("apt-get"): return "apt"
    if command_exists("dnf"): return "dnf"
    return "apt"

def _warp_cli(*args: str, quiet: bool = True) -> subprocess.CompletedProcess:
    cmd = ["warp-cli", "--accept-tos"] + list(args)
    return _run(cmd, capture=True, check=False)

def _warp_is_installed() -> bool:
    return command_exists("warp-cli")

def _warp_service_active() -> bool:
    r = _run(["systemctl", "is-active", "warp-svc"], capture=True, check=False)
    return r.stdout.strip() == "active"

def _warp_status() -> str:
    if not _warp_is_installed() or not _warp_service_active():
        return "Unknown"
    r = _warp_cli("status")
    out = r.stdout.strip()
    if "Connected" in out: return "Connected"
    if "Disconnected" in out: return "Disconnected"
    return out.splitlines()[0] if out else "Unknown"

def _install_dependencies() -> bool:
    info("Проверка зависимостей (gnupg, curl, lsb-release)...")
    missing = []
    for pkg in ("gnupg", "curl", "lsb-release"):
        if pkg == "gnupg" and command_exists("gpg"): continue
        if not command_exists(pkg):
            missing.append(pkg)
            
    if not missing:
        return True
    
    if _get_pkg_mgr() == "apt":
        _run(["apt-get", "update", "-q"], quiet=True)
        r = _run(["apt-get", "install", "-y", "-q"] + missing, quiet=True)
        return r.returncode == 0
    elif _get_pkg_mgr() == "dnf":
        r = _run(["dnf", "install", "-y"] + missing, quiet=True)
        return r.returncode == 0
    return False

def install_warp() -> bool:
    if _warp_is_installed():
        success("Cloudflare WARP уже установлен.")
        return True

    if not _install_dependencies():
        warn("Не удалось установить базовые зависимости (gnupg/curl/lsb-release).")

    info("Установка Cloudflare WARP...")
    
    if _get_pkg_mgr() == "apt":
        keyring = "/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
        _run(["rm", "-f", keyring], quiet=True)
        
        info("Скачивание GPG-ключа Cloudflare...")
        r_key = _run([
            "bash", "-c",
            f"curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output {keyring}"
        ], capture=True)
        if r_key.returncode != 0:
            error(f"Не удалось установить GPG-ключ: {r_key.stderr.strip()}")
            return False

        r_code = _run(["lsb_release", "-cs"], capture=True)
        codename = r_code.stdout.strip() or "jammy"
        
        info(f"Добавление репозитория для {codename}...")
        repo_file = "/etc/apt/sources.list.d/cloudflare-client.list"
        
        def write_repo(cdname: str):
            repo_line = f"deb [signed-by={keyring}] https://pkg.cloudflareclient.com/ {cdname} main"
            Path(repo_file).write_text(repo_line + "\n")
            
        write_repo(codename)
        _run(["apt-get", "update", "-q"], quiet=True)
        r_inst = _run(["apt-get", "install", "-y", "-q", "cloudflare-warp"], capture=True)
        
        # Fallback if codename not supported
        if r_inst.returncode != 0 and codename not in ("jammy", "bookworm"):
            fallback = "jammy" if "ubuntu" in Path("/etc/os-release").read_text().lower() else "bookworm"
            warn(f"Ошибка установки для {codename}, пробуем fallback на {fallback}...")
            write_repo(fallback)
            _run(["apt-get", "update", "-q"], quiet=True)
            r_inst = _run(["apt-get", "install", "-y", "-q", "cloudflare-warp"], capture=True)
            
        if r_inst.returncode != 0:
            error(f"Ошибка установки пакета: {r_inst.stderr.strip()}")
            return False

    elif _get_pkg_mgr() == "dnf":
        _run(["rpm", "--import", "https://pkg.cloudflareclient.com/pubkey.gpg"], quiet=True)
        r_ver = _run(["lsb_release", "-rs"], capture=True)
        ver = r_ver.stdout.strip().split(".")[0] or "8"
        import textwrap
        repo_content = textwrap.dedent(f"""\
            [cloudflare-warp]
            name=Cloudflare WARP
            baseurl=https://pkg.cloudflareclient.com/rpm/el{ver}/
            enabled=1
            gpgcheck=1
            gpgkey=https://pkg.cloudflareclient.com/pubkey.gpg
        """)
        Path("/etc/yum.repos.d/cloudflare-warp.repo").write_text(repo_content)
        _run(["dnf", "install", "-y", "cloudflare-warp"], quiet=True)

    if not _warp_is_installed():
        error("Cloudflare WARP не установился — warp-cli не найден.")
        return False

    _run(["systemctl", "enable", "warp-svc"], quiet=True)
    _run(["systemctl", "start",  "warp-svc"], quiet=True)

    for _ in range(20):
        if _warp_service_active():
            break
        time.sleep(1)

    if not _warp_service_active():
        _run(["systemctl", "restart", "warp-svc"], quiet=True)
        time.sleep(5)

    if _warp_service_active():
        success("Cloudflare WARP установлен и запущен.")
        return True
    else:
        error("Сервис warp-svc не активен после установки.")
        return False

def configure_and_connect() -> bool:
    if not _warp_is_installed():
        warn("Сначала установите WARP.")
        return False

    info("Регистрация аккаунта WARP...")
    _warp_cli("registration", "new")
    
    info("Настройка безопасного режима (Exclude 0.0.0.0/0 и ::/0)...")
    # КРИТИЧЕСКИ ВАЖНО: Исключаем дефолтные маршруты ПЕРЕД подключением!
    # Иначе warp-cli мгновенно заберёт на себя весь трафик и убьёт SSH сессию.
    _warp_cli("tunnel", "ip", "add-excluded", "0.0.0.0/0")
    _warp_cli("tunnel", "ip", "add-excluded", "::/0")
    
    # Для новых версий warp-cli (split-tunnel вместо tunnel ip add-excluded)
    _warp_cli("split-tunnel", "ip", "add", "0.0.0.0/0")
    _warp_cli("split-tunnel", "ip", "add", "::/0")
    
    info("Подключение WARP...")
    _warp_cli("connect")
    
    for _ in range(15):
        if _warp_status() == "Connected":
            success("WARP успешно подключён в безопасном режиме!")
            return True
        time.sleep(1)
        
    warn(f"Статус после подключения: {_warp_status()}")
    return False

def disconnect_and_uninstall() -> None:
    if not _warp_is_installed():
        warn("WARP не установлен.")
        return
        
    ans = input(f"{RED}Отключить и удалить WARP? [y/N]:{NC} ").strip().lower()
    if ans == "y":
        info("Отключение...")
        _warp_cli("disconnect")
        _warp_cli("registration", "delete")
        
        info("Остановка сервисов...")
        _run(["systemctl", "stop", "warp-svc"], quiet=True)
        _run(["systemctl", "disable", "warp-svc"], quiet=True)
        
        info("Очистка старых правил маршрутизации (warp-selective/warp-runet)...")
        for svc in ("warp-ssh-ns", "warp-selective", "warp-runet"):
            _run(["systemctl", "stop", svc], quiet=True)
            _run(["systemctl", "disable", svc], quiet=True)
            
        _run(["iptables", "-t", "mangle", "-F", "OUTPUT"], quiet=True)
        _run(["ip", "rule", "del", "fwmark", "222", "table", "222"], quiet=True)
        _run(["ip", "rule", "del", "fwmark", "223", "table", "223"], quiet=True)
        
        info("Удаление пакета...")
        if _get_pkg_mgr() == "apt":
            _run(["apt-get", "remove", "--purge", "-y", "cloudflare-warp"], quiet=True)
        else:
            _run(["dnf", "remove", "-y", "cloudflare-warp"], quiet=True)
            
        # Удаляем репозитории чтобы не было мусора
        _run(["rm", "-f", "/etc/apt/sources.list.d/cloudflare-client.list"], quiet=True)
        
        success("WARP полностью удалён.")

def do_manage_warp() -> None:
    while True:
        os.system("clear")
        _box_top("CLOUDFLARE WARP — УПРАВЛЕНИЕ")
        _box_row(f"  {DIM}Безопасный туннель Cloudflare WARP для обхода блокировок{NC}")
        _box_sep()

        inst_str = f"{GREEN}Установлен{NC}" if _warp_is_installed() else f"{RED}Не установлен{NC}"
        svc_str  = f"{GREEN}Активен{NC}" if _warp_service_active() else f"{YELLOW}Не активен{NC}"
        st = _warp_status() if _warp_is_installed() and _warp_service_active() else "—"
        conn_str = f"{GREEN}{st}{NC}" if st == "Connected" else f"{YELLOW}{st}{NC}"

        _box_row(f"  Статус пакета:   {inst_str}")
        _box_row(f"  Статус сервиса:  {svc_str}")
        _box_row(f"  Соединение:      {conn_str}")
        _box_row()
        _box_sep()
        
        _box_item("1", "🚀 Установить и подключить WARP (Безопасный режим)")
        _box_item("2", "🔌 Подключить / Отключить WARP")
        _box_item("3", "🌐 Универсальный обход (выбор доменов и подсетей)")
        _box_item("4", "📊 Показать информацию и логи")
        _box_item("5", "🗑️  Отключить и удалить WARP")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            print()
            break

        if ch in ("0", "q", "Q", ""):
            break

        elif ch == "1":
            print()
            if install_warp():
                configure_and_connect()
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            if not _warp_is_installed():
                warn("Сначала установите WARP (пункт 1).")
            else:
                st = _warp_status()
                if st == "Connected":
                    _warp_cli("disconnect")
                    time.sleep(2)
                    success("WARP отключён.")
                else:
                    info("Подключение WARP...")
                    _warp_cli("connect")
                    time.sleep(3)
                    success(f"Текущий статус: {_warp_status()}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            if not _warp_is_installed() or _warp_status() != "Connected":
                warn("Для настройки маршрутизации установите и подключите WARP.")
                time.sleep(2)
            else:
                from vless_installer.modules.warp_universal import do_warp_routing_menu
                do_warp_routing_menu()

        elif ch == "4":
            print()
            if not _warp_is_installed():
                warn("WARP не установлен.")
            else:
                r_ver = _run(["warp-cli", "--version"], capture=True)
                print(f"Версия: {r_ver.stdout.strip()}")
                print(f"Статус: {_warp_status()}")
                r_st = _warp_cli("settings")
                print("\nНастройки (warp-cli settings):")
                print(r_st.stdout[:1500] + ("..." if len(r_st.stdout) > 1500 else ""))
                
                r_ex = _warp_cli("split-tunnel", "ip", "list")
                if r_ex.returncode != 0:
                    r_ex = _warp_cli("tunnel", "ip", "list-excluded")
                print("\nИсключенные IP (split-tunnel list):")
                print(r_ex.stdout[:1500] + ("..." if len(r_ex.stdout) > 1500 else ""))
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            print()
            disconnect_and_uninstall()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            
        else:
            warn("Неверный выбор")
            time.sleep(1)
