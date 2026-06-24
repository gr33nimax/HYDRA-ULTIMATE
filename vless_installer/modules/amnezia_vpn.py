"""
vless_installer/modules/amnezia_vpn.py
───────────────────────────────────────────────────────────────────────────────
Управление AmneziaVPN (AWG через Docker-контейнер).

Контейнер amnezia-awg развёрнут клиентом Amnezia через SSH.
Образ собирается локально на сервере (Alpine, ~42 MB).
Запускается через docker run --privileged с пробросом UDP-порта.

Точка входа из _core.py:
    from vless_installer.modules.amnezia_vpn import do_amnezia_vpn_menu
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

# ── Константы ─────────────────────────────────────────────────────────────────
_CONTAINER_NAME = "amnezia-awg"
_STATE_FILE     = Path("/var/lib/xray-installer/state.json")
_LOG_FILE       = Path("/var/log/vless-install.log")

def _detect_container_name() -> str:
    try:
        r = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            names = [n.strip() for n in r.stdout.splitlines() if n.strip()]
            for name in ("amnezia-awg", "amnezia-awg2", "amnezia-wg", "amnezia-awg-server"):
                if name in names:
                    return name
            for name in names:
                if name.startswith("amnezia-") and ("awg" in name or "wg" in name):
                    return name
            for name in names:
                if name.startswith("amnezia-"):
                    return name
            for name in names:
                if "amnezia" in name:
                    return name
    except Exception:
        pass
    return "amnezia-awg"

def _get_container_name() -> str:
    global _CONTAINER_NAME
    _CONTAINER_NAME = _detect_container_name()
    return _CONTAINER_NAME

# ── box_renderer ───────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    _box_back, _box_info, _box_warn, _box_desc,
)

# ── Логирование ────────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [AMNEZIA] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str):  print(f"{CYAN}[INFO]{NC}  {msg}");   _log("INFO",    msg)
def _ok(msg: str):    print(f"{GREEN}[OK]{NC}    {msg}");  _log("SUCCESS", msg)
def _warn(msg: str):  print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",    msg)
def _err(msg: str):   print(f"{RED}[ERR]{NC}   {msg}");    _log("ERROR",   msg)

# ── Утилиты Docker ─────────────────────────────────────────────────────────────
def _docker_available() -> bool:
    """Проверяет, установлен ли Docker."""
    r = subprocess.run(["which", "docker"], capture_output=True)
    return r.returncode == 0

def _container_exists() -> bool:
    """Проверяет, существует ли контейнер Amnezia."""
    name = _get_container_name()
    r = subprocess.run([
        "docker", "ps", "-a", "--filter", f"name={name}",
        "--format", "{{.Names}}"
    ], capture_output=True, text=True)
    return name in r.stdout.splitlines()

def _container_running() -> bool:
    """Проверяет, запущен ли контейнер Amnezia."""
    name = _get_container_name()
    r = subprocess.run([
        "docker", "ps", "--filter", f"name={name}",
        "--filter", "status=running", "--format", "{{.Names}}"
    ], capture_output=True, text=True)
    return name in r.stdout.splitlines()

def _get_container_info() -> dict:
    """Инспектирует контейнер и возвращает полезную информацию."""
    info = {
        "status": "not_exists",
        "image": "—",
        "created": "—",
        "ports": {},
    }
    name = _get_container_name()
    if not _container_exists():
        return info
    try:
        r = subprocess.run([
            "docker", "inspect", name
        ], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            data = json.loads(r.stdout)
            if data and isinstance(data, list):
                c_data = data[0]
                info["status"] = c_data.get("State", {}).get("Status", "exited")
                info["image"] = c_data.get("Config", {}).get("Image", "—")
                info["created"] = c_data.get("Created", "—")[:19].replace("T", " ")
                
                # Маппинг портов
                port_bindings = c_data.get("HostConfig", {}).get("PortBindings", {}) or {}
                ports = {}
                for container_port, host_ports in port_bindings.items():
                    if host_ports and isinstance(host_ports, list):
                        ports[container_port] = host_ports[0].get("HostPort")
                info["ports"] = ports
    except Exception as e:
        _log("ERROR", f"Error inspecting container: {e}")
    return info

def _get_awg_interface_stats() -> dict:
    """Запрашивает статистику WireGuard (awg show) внутри контейнера."""
    stats = {"interface": {}, "peers": []}
    if not _container_running():
        return stats
    name = _get_container_name()
    try:
        r = subprocess.run([
            "docker", "exec", name,
            "awg", "show", "awg0"
        ], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            # Fallback to wg if awg tool isn't found/configured
            r = subprocess.run([
                "docker", "exec", name,
                "wg", "show", "awg0"
            ], capture_output=True, text=True, timeout=10)
        
        if r.returncode == 0:
            current_peer = None
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("interface:"):
                    stats["interface"]["name"] = line.split()[-1]
                elif line.startswith("public key:"):
                    if current_peer is None:
                        stats["interface"]["public_key"] = line.split()[-1]
                    else:
                        current_peer["public_key"] = line.split()[-1]
                elif line.startswith("peer:"):
                    if current_peer:
                        stats["peers"].append(current_peer)
                    current_peer = {"public_key": line.split()[-1]}
                elif line.startswith("endpoint:") and current_peer:
                    current_peer["endpoint"] = line.split()[-1]
                elif line.startswith("allowed ips:") and current_peer:
                    current_peer["allowed_ips"] = line.split(":")[-1].strip()
                elif line.startswith("latest handshake:") and current_peer:
                    current_peer["latest_handshake"] = line.split(":")[-1].strip()
                elif line.startswith("transfer:") and current_peer:
                    current_peer["transfer"] = line.split(":")[-1].strip()
            if current_peer:
                stats["peers"].append(current_peer)
    except Exception as e:
        _log("ERROR", f"Error getting AWG stats: {e}")
    return stats

def _container_start() -> bool:
    name = _get_container_name()
    _info(f"Запускаю контейнер {name}...")
    r = subprocess.run(["docker", "start", name], capture_output=True)
    return r.returncode == 0

def _container_stop() -> bool:
    name = _get_container_name()
    _info(f"Останавливаю контейнер {name}...")
    r = subprocess.run(["docker", "stop", name], capture_output=True)
    return r.returncode == 0

def _container_restart() -> bool:
    name = _get_container_name()
    _info(f"Перезапускаю контейнер {name}...")
    r = subprocess.run(["docker", "restart", name], capture_output=True)
    return r.returncode == 0

def _container_remove() -> bool:
    name = _get_container_name()
    _info(f"Удаляю контейнер {name}...")
    subprocess.run(["docker", "stop", name], capture_output=True)
    r = subprocess.run(["docker", "rm", name], capture_output=True)
    return r.returncode == 0

def _container_logs(lines: int = 50) -> str:
    name = _get_container_name()
    r = subprocess.run([
        "docker", "logs", "--tail", str(lines), name
    ], capture_output=True, text=True, errors="replace")
    return r.stdout + r.stderr

def _get_client_configs() -> list[dict]:
    """Получает файлы конфигурации клиентов из контейнера."""
    if not _container_exists():
        return []
    
    name = _get_container_name()
    configs = []
    paths_to_check = [
        "/opt/amnezia/clients/",
        "/etc/amnezia/amneziawg/",
        "/root/clients/",
        "/root/"
    ]
    
    for path in paths_to_check:
        r = subprocess.run([
            "docker", "exec", name,
            "find", path, "-name", "*.conf"
        ], capture_output=True, text=True)
        if r.returncode == 0:
            files = [f.strip() for f in r.stdout.splitlines() if f.strip()]
            for f in files:
                r_cat = subprocess.run([
                    "docker", "exec", name,
                    "cat", f
                ], capture_output=True, text=True)
                if r_cat.returncode == 0:
                    configs.append({
                        "name": Path(f).stem,
                        "config_text": r_cat.stdout.strip()
                    })
            if configs:
                break
    return configs

def _generate_client_qr(config_text: str, output_path: str) -> bool:
    try:
        r = subprocess.run(
            ["qrencode", "-o", output_path, "-s", "8"],
            input=config_text, text=True, capture_output=True
        )
        return r.returncode == 0
    except Exception:
        return False

# ── Меню ───────────────────────────────────────────────────────────────────────
def do_amnezia_vpn_menu() -> None:
    """Главное интерактивное меню модуля AmneziaVPN."""
    while True:
        os.system("clear")
        
        name = _get_container_name()
        has_docker = _docker_available()
        exists = _container_exists()
        running = _container_running()
        
        info = _get_container_info()
        stats = _get_awg_interface_stats() if running else {"peers": []}
        
        # Определение порта
        port_str = "—"
        if info["ports"]:
            # Ищем UDP порт
            udp_ports = [host_port for c_port, host_port in info["ports"].items() if "udp" in c_port]
            if udp_ports:
                port_str = f"{udp_ports[0]}/udp"
            else:
                port_str = f"{list(info['ports'].values())[0]}"
        
        print()
        _box_top("🛡️  AMNEZIAVPN (AWG через Docker)")
        
        if not has_docker:
            _box_row(f"  Docker:       {RED}🔴 НЕ УСТАНОВЛЕН{NC}")
            _box_sep()
            _box_warn("Docker не обнаружен на сервере!")
            _box_warn("Установите Docker и настройте AmneziaVPN")
            _box_warn("через официальный клиент Amnezia по SSH.")
        elif not exists:
            _box_row(f"  Docker:       {GREEN}🟢 установлен{NC}")
            _box_row(f"  Контейнер:    {RED}🔴 {name} не найден{NC}")
            _box_sep()
            _box_warn(f"Контейнер {name} не запущен и не настроен.")
            _box_warn("Запустите установку AmneziaWG через официальный")
            _box_warn("клиент AmneziaVPN (подключение по SSH к этому серверу).")
        else:
            _box_row(f"  Docker:       {GREEN}🟢 установлен{NC}")
            c_status_color = GREEN if running else RED
            _box_row(f"  Контейнер:    {c_status_color}🟢 {name} ({info['status']}){NC}" if running else f"  Контейнер:    {c_status_color}🔴 {name} ({info['status']}){NC}")
            _box_row(f"  Образ:        {info['image']}")
            _box_row(f"  Порт:         {CYAN}{port_str}{NC}")
            _box_row(f"  Активных пиров:{CYAN}{len(stats['peers'])}{NC}")
            
        _box_sep()
        
        if exists:
            _box_item("1", "Статус контейнера (подробно)")
            if running:
                _box_item("2", "Статус пиров (handshake, трафик)")
                _box_item("3", "Перезапустить контейнер")
                _box_item("4", f"{RED}Остановить контейнер{NC}")
            else:
                _box_item("5", f"{GREEN}Запустить контейнер{NC}")
            _box_item("6", "Логи контейнера (последние 50 строк)")
            _box_item("7", "Показать клиентские конфиги")
            _box_item("8", "Генерировать QR-код для клиента")
            _box_item("9", f"{RED}Удалить контейнер {name}{NC}")
            
        _box_back()
        _box_bottom()
        
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return
            
        if ch in ("q", "Q", "0", ""):
            return
            
        if not exists:
            _warn("Контейнер не существует. Действия недоступны.")
            time.sleep(1.5)
            continue
            
        if ch == "1":
            os.system("clear")
            print()
            _box_top("📋 Подробный статус контейнера")
            _box_bottom()
            print()
            subprocess.run(["docker", "inspect", _CONTAINER_NAME])
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")
            
        elif ch == "2" and running:
            os.system("clear")
            print()
            _box_top("👥 Статус подключенных пиров (awg show)")
            _box_bottom()
            print()
            if stats["peers"]:
                for p in stats["peers"]:
                    print(f"{BOLD}Peer:{NC} {CYAN}{p.get('public_key')}{NC}")
                    if p.get("endpoint"):
                        print(f"  Эндпоинт:  {p['endpoint']}")
                    if p.get("allowed_ips"):
                        print(f"  AllowedIP: {p['allowed_ips']}")
                    if p.get("latest_handshake"):
                        print(f"  Handshake: {p['latest_handshake']}")
                    if p.get("transfer"):
                        print(f"  Трафик:    {p['transfer']}")
                    print()
            else:
                print("  Нет подключенных пиров или статистика пуста.")
                print()
            input(f"{BLUE}Нажмите Enter...{NC}")
            
        elif ch == "3" and running:
            if _container_restart():
                _ok("Контейнер перезапущен")
            else:
                _err("Ошибка перезапуска")
            time.sleep(1.5)
            
        elif ch == "4" and running:
            if _container_stop():
                _ok("Контейнер остановлен")
            else:
                _err("Ошибка остановки")
            time.sleep(1.5)
            
        elif ch == "5" and not running:
            if _container_start():
                _ok("Контейнер запущен")
            else:
                _err("Ошибка запуска")
            time.sleep(1.5)
            
        elif ch == "6":
            os.system("clear")
            print()
            _box_top("📋 Последние логи контейнера")
            _box_bottom()
            print()
            print(_container_logs(50))
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")
            
        elif ch == "7":
            os.system("clear")
            print()
            _box_top("🔑 Клиентские конфигурации AWG")
            _box_bottom()
            print()
            configs = _get_client_configs()
            if configs:
                for cfg in configs:
                    print(f"{GREEN}--- Клиент: {cfg['name']} ---{NC}")
                    print(cfg["config_text"])
                    print()
            else:
                _warn("Конфигурации клиентов не найдены в контейнере.")
                _warn("Проверьте папки: /opt/amnezia/clients/ или /etc/amnezia/amneziawg/")
                print()
            input(f"{BLUE}Нажмите Enter...{NC}")
            
        elif ch == "8":
            os.system("clear")
            print()
            _box_top("📲 Генерация QR-кода")
            _box_bottom()
            print()
            configs = _get_client_configs()
            if not configs:
                _warn("Конфигурации клиентов не найдены.")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
                
            print("Доступные клиенты:")
            for i, cfg in enumerate(configs, 1):
                print(f"  {i}. {CYAN}{cfg['name']}{NC}")
            print()
            
            try:
                sel = input(f"Выберите номер клиента (Enter = отмена): ").strip()
            except KeyboardInterrupt:
                continue
                
            if sel.isdigit() and 1 <= int(sel) <= len(configs):
                cfg = configs[int(sel)-1]
                qr_path = f"/tmp/awg_qr_{cfg['name']}.png"
                if _generate_client_qr(cfg["config_text"], qr_path):
                    _ok(f"QR-код успешно сохранен как картинка в: {qr_path}")
                    # Попробуем отобразить ASCII QR в терминале
                    try:
                        subprocess.run(["qrencode", "-t", "ansiutf8"], input=cfg["config_text"], text=True)
                    except Exception:
                        pass
                else:
                    _err("Не удалось сгенерировать QR-код (убедитесь, что qrencode установлен).")
            input(f"{BLUE}Нажмите Enter...{NC}")
            
        elif ch == "9":
            try:
                ans = input(f"  {RED}Вы действительно хотите УДАЛИТЬ контейнер amnezia-awg? [y/N]:{NC} ").strip().lower()
            except KeyboardInterrupt:
                continue
            if ans == "y":
                if _container_remove():
                    _ok("Контейнер успешно удален!")
                else:
                    _err("Ошибка удаления контейнера.")
            time.sleep(1.5)
        else:
            _warn("Неверный выбор")
            time.sleep(1)
