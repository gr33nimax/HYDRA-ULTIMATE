"""
vless_installer/modules/warp.py
───────────────────────────────────────────────────────────────────────────────
Cloudflare WARP — установка и управление через WireGuard (wgcf).

Полностью переписанный модуль:
  • Безопасная генерация профиля через wgcf
  • Настройка WireGuard интерфейса с Table = off (без перехвата дефолтного шлюза)
  • Интеграция с warp_universal.py для выборочного роутинга
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import subprocess
import time
import shutil
import platform
from pathlib import Path

from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_item_exit,
    RED, GREEN, YELLOW, CYAN, BLUE, DIM, NC,
)

LOG_FILE = Path("/var/log/vless-install.log")
WG_CONF = Path("/etc/wireguard/wg-warp.conf")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [WARP-WG-{level}] {clean}\n")
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
    return shutil.which(cmd) is not None

def _get_pkg_mgr() -> str:
    if command_exists("apt-get"): return "apt"
    if command_exists("dnf"): return "dnf"
    return "apt"

def _wg_interface_exists() -> bool:
    if not command_exists("wg"):
        return False
    r = _run(["wg", "show", "wg-warp"], capture=True, quiet=True)
    return r.returncode == 0

def _wg_service_active() -> bool:
    r = _run(["systemctl", "is-active", "wg-quick@wg-warp"], capture=True, quiet=True)
    return r.stdout.strip() == "active"

def _warp_status() -> str:
    if not WG_CONF.exists():
        return "Not Configured"
    if _wg_service_active() or _wg_interface_exists():
        return "Connected"
    return "Disconnected"

def _install_dependencies() -> bool:
    info("Проверка системных зависимостей (wireguard-tools, curl)...")
    missing = []
    if not command_exists("wg") or not command_exists("wg-quick"):
        missing.append("wireguard-tools")
    if not command_exists("curl"):
        missing.append("curl")
        
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

def download_wgcf() -> str | None:
    arch = platform.machine().lower()
    if "x86_64" in arch or "amd64" in arch:
        suffix = "amd64"
    elif "aarch64" in arch or "arm64" in arch:
        suffix = "arm64"
    elif "armv7" in arch:
        suffix = "armv7"
    else:
        suffix = "386"
        
    url = f"https://github.com/ViRb3/wgcf/releases/download/v2.2.22/wgcf_2.2.22_linux_{suffix}"
    dest = Path("/tmp/wgcf")
    info(f"Скачивание wgcf v2.2.22 ({suffix})...")
    
    r = _run(["curl", "-fsSL", "-o", str(dest), url], quiet=True)
    if r.returncode != 0:
        r = _run(["wget", "-q", "-O", str(dest), url], quiet=True)
        
    if dest.exists() and dest.stat().st_size > 100000:
        dest.chmod(0o755)
        return str(dest)
        
    error("Не удалось скачать wgcf binary.")
    return None

def install_warp() -> bool:
    if WG_CONF.exists():
        success("WARP профиль WireGuard уже создан.")
        return True

    # 1. Чистим остатки старого официального warp
    if command_exists("warp-cli") or _run(["systemctl", "status", "warp-svc"], quiet=True).returncode == 0:
        info("Обнаружены остатки официального cloudflare-warp. Удаляем для предотвращения конфликтов...")
        _run(["systemctl", "stop", "warp-svc"], quiet=True)
        _run(["systemctl", "disable", "warp-svc"], quiet=True)
        if _get_pkg_mgr() == "apt":
            _run(["apt-get", "remove", "--purge", "-y", "cloudflare-warp"], quiet=True)
        else:
            _run(["dnf", "remove", "-y", "cloudflare-warp"], quiet=True)
        _run(["rm", "-rf", "/var/lib/cloudflare-warp"], quiet=True)
        success("Остатки официального WARP удалены.")

    if not _install_dependencies():
        error("Не удалось установить wireguard-tools.")
        return False

    # 2. Скачиваем wgcf и регистрируемся
    wgcf_bin = download_wgcf()
    if not wgcf_bin:
        return False

    work_dir = Path("/tmp/wgcf_config")
    work_dir.mkdir(parents=True, exist_ok=True)
    
    info("Регистрация аккаунта Cloudflare WARP...")
    r_reg = subprocess.run([wgcf_bin, "register", "--accept-tos"], cwd=str(work_dir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r_reg.returncode != 0:
        error("Ошибка регистрации аккаунта через wgcf.")
        shutil.rmtree(work_dir, ignore_errors=True)
        return False
        
    info("Генерация профиля WireGuard...")
    r_gen = subprocess.run([wgcf_bin, "generate"], cwd=str(work_dir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r_gen.returncode != 0:
        error("Ошибка генерации профиля wgcf-profile.conf.")
        shutil.rmtree(work_dir, ignore_errors=True)
        return False

    profile_src = work_dir / "wgcf-profile.conf"
    if not profile_src.exists():
        error("Файл wgcf-profile.conf не найден.")
        shutil.rmtree(work_dir, ignore_errors=True)
        return False

    # 3. Читаем и адаптируем конфигурацию для безопасной выборочной маршрутизации
    lines = profile_src.read_text(encoding="utf-8").splitlines()
    new_lines = []
    
    for line in lines:
        if line.strip().startswith("DNS"):
            continue  # Пропускаем DNS, чтобы не ломать системный резолвер
        new_lines.append(line)
        if line.strip() == "[Interface]":
            # Добавляем отключение автоматической маршрутизации
            new_lines.append("Table = off")

    WG_CONF.parent.mkdir(parents=True, exist_ok=True)
    WG_CONF.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    
    # Права доступа
    WG_CONF.chmod(0o600)
    
    # Чистим темп
    shutil.rmtree(work_dir, ignore_errors=True)
    Path(wgcf_bin).unlink(missing_ok=True)
    
    success("Профиль WireGuard успешно создан и сохранен в /etc/wireguard/wg-warp.conf")
    return True

def configure_and_connect() -> bool:
    if not WG_CONF.exists():
        warn("Сначала настройте профиль WARP (пункт 1).")
        return False

    info("Запуск WireGuard туннеля wg-warp...")
    _run(["systemctl", "enable", "wg-quick@wg-warp"], quiet=True)
    r = _run(["systemctl", "start", "wg-quick@wg-warp"], quiet=True)
    
    if r.returncode == 0 or _wg_interface_exists():
        success("WireGuard туннель wg-warp успешно запущен и добавлен в автозагрузку.")
        return True
        
    error("Не удалось запустить wg-quick@wg-warp. Проверьте: journalctl -u wg-quick@wg-warp")
    return False

def disconnect_and_uninstall() -> None:
    if not WG_CONF.exists():
        warn("WARP не настроен.")
        return
        
    ans = input(f"{RED}Отключить и удалить WireGuard-профиль WARP? [y/N]:{NC} ").strip().lower()
    if ans == "y":
        info("Остановка интерфейса...")
        _run(["systemctl", "stop", "wg-quick@wg-warp"], quiet=True)
        _run(["systemctl", "disable", "wg-quick@wg-warp"], quiet=True)
        
        info("Удаление конфигурационных файлов...")
        if WG_CONF.exists():
            WG_CONF.unlink()
            
        success("WARP профиль полностью удален.")

def do_manage_warp() -> None:
    while True:
        os.system("clear")
        _box_top("WARP (WIREGUARD WGCF) — УПРАВЛЕНИЕ")
        _box_row(f"  {DIM}Безопасный WireGuard туннель Cloudflare WARP{NC}")
        _box_sep()

        inst_str = f"{GREEN}Настроен{NC}" if WG_CONF.exists() else f"{RED}Не настроен{NC}"
        svc_str  = f"{GREEN}Активен{NC}" if _wg_service_active() else f"{YELLOW}Не активен{NC}"
        conn_str = f"{GREEN}Подключен{NC}" if _wg_interface_exists() else f"{RED}Отключен{NC}"

        _box_row(f"  Статус профиля:  {inst_str}")
        _box_row(f"  Статус службы:   {svc_str}")
        _box_row(f"  Сетевой инт.:    {conn_str} (wg-warp)")
        _box_row()
        _box_sep()
        
        _box_item("1", "🚀 Установить и подключить WARP (Безопасный WireGuard)")
        _box_item("2", "🔌 Подключить / Отключить интерфейс")
        _box_item("3", "🌐 Универсальный обход (выбор доменов и подсетей)")
        _box_item("4", "📊 Показать информацию и статус")
        _box_item("5", "🗑️  Удалить профиль WARP")
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
            if not WG_CONF.exists():
                warn("Сначала установите WARP (пункт 1).")
            else:
                if _wg_service_active():
                    info("Остановка интерфейса...")
                    _run(["systemctl", "stop", "wg-quick@wg-warp"], quiet=True)
                    success("Интерфейс wg-warp остановлен.")
                else:
                    info("Запуск интерфейса...")
                    _run(["systemctl", "start", "wg-quick@wg-warp"], quiet=True)
                    success("Интерфейс wg-warp запущен.")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            if not WG_CONF.exists() or not _wg_interface_exists():
                warn("Для настройки маршрутизации установите и подключите WARP.")
                time.sleep(2)
            else:
                from vless_installer.modules.warp_universal import do_warp_routing_menu
                do_warp_routing_menu()

        elif ch == "4":
            print()
            if not WG_CONF.exists():
                warn("WARP не настроен.")
            else:
                print(f"Конфиг-файл: {WG_CONF}")
                print(f"Служба systemd: {'активна' if _wg_service_active() else 'неактивна'}")
                if _wg_interface_exists():
                    print("\nСтатус интерфейса (wg show wg-warp):")
                    r_wg = _run(["wg", "show", "wg-warp"], capture=True)
                    print(r_wg.stdout)
                else:
                    print("\nИнтерфейс wg-warp отключен.")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            print()
            disconnect_and_uninstall()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            
        else:
            warn("Неверный выбор")
            time.sleep(1)
