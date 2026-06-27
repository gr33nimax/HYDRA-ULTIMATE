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
import shutil
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
            return dict(RED='\x1b[0;31m', GREEN='\x1b[0;32m', YELLOW='\x1b[0;33m',
                        CYAN='\x1b[0;34m', BLUE='\x1b[0;35m', BOLD='\x1b[1m',
                        DIM='\x1b[2m', WHITE='\x1b[0;30m', NC='\x1b[0m')
        return dict(RED='\x1b[0;31m', GREEN='\x1b[0;32m', YELLOW='\x1b[1;33m',
                    CYAN='\x1b[0;36m', BLUE='\x1b[0;34m', BOLD='\x1b[1m',
                    DIM='\x1b[2m', WHITE='\x1b[1;37m', NC='\x1b[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

# ── Константы ─────────────────────────────────────────────────────────────────
_CONTAINER_NAME = "amnezia-awg2"
_STATE_FILE     = Path("/var/lib/xray-installer/state.json")
_LOG_FILE       = Path("/var/log/vless-install.log")

def _detect_container_name() -> str:
    try:
        r = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            names = [n.strip() for n in r.stdout.splitlines() if n.strip()]
            for name in ("amnezia-awg2", "amnezia-awg", "amnezia-wg", "amnezia-awg-server"):
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
    return "amnezia-awg2"

def _get_container_name() -> str:
    global _CONTAINER_NAME
    _CONTAINER_NAME = _detect_container_name()
    return _CONTAINER_NAME

# ── box_renderer ───────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    _box_back, _box_info, _box_warn, _box_desc, _box_item_exit,
)

# ── Логирование ────────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Fix FutureWarning: escape [ inside character class
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


def _pkg_mgr() -> str:
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    return "unknown"


def install_docker_engine() -> bool:
    """Устанавливает Docker (docker.io / docker) и запускает службу."""
    if _docker_available():
        _ok("Docker уже установлен.")
        subprocess.run(["systemctl", "enable", "--now", "docker"],
                         capture_output=True, check=False)
        return True

    mgr = _pkg_mgr()
    if mgr == "apt":
        _info("Установка docker.io через apt...")
        subprocess.run(["apt-get", "update", "-qq"], check=False, capture_output=True)
        r = subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", "docker.io"],
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            capture_output=True,
        )
    elif mgr == "dnf":
        _info("Установка docker через dnf...")
        r = subprocess.run(["dnf", "install", "-y", "docker"], capture_output=True)
    else:
        _err("Неизвестный пакетный менеджер — установите Docker вручную.")
        return False

    if r.returncode != 0:
        _err("Не удалось установить Docker.")
        return False

    subprocess.run(["systemctl", "enable", "--now", "docker"],
                   capture_output=True, check=False)
    if _docker_available():
        _ok("Docker установлен и запущен.")
        return True
    _err("Docker установлен, но бинарник не найден в PATH.")
    return False


def prepare_awg_environment() -> None:
    """Sysctl и MTU-подсказки для AWG на сервере."""
    _info("Включаю net.ipv4.ip_forward...")
    subprocess.run(
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        capture_output=True, check=False,
    )
    sysctl_conf = Path("/etc/sysctl.d/99-hydra-awg.conf")
    if not sysctl_conf.exists():
        sysctl_conf.write_text("net.ipv4.ip_forward=1\n", encoding="utf-8")

    try:
        from vless_installer.modules.network_mtu import recommend_mtu_for_awg
        mtu = recommend_mtu_for_awg()
        _info(f"Рекомендуемый MTU для AWG-клиентов: {mtu}")
    except Exception:
        pass
    _ok("Сервер подготовлен для AmneziaWG.")


def show_awg_client_instructions() -> None:
    """Показывает шаги установки контейнера через клиент Amnezia."""
    os.system("clear")
    print()
    _box_top("📖  УСТАНОВКА AMNEZIAWG")
    _box_row("Контейнер разворачивается официальным клиентом AmneziaVPN:")
    _box_sep()
    _box_row("  1. Установите AmneziaVPN на ПК/телефон")
    _box_row("  2. Добавьте сервер → «Установить по SSH»")
    _box_row("  3. Укажите IP, пользователя root и пароль/ключ")
    _box_row("  4. Выберите протокол AmneziaWG (AWG)")
    _box_row("  5. Дождитесь завершения — контейнер появится здесь")
    _box_sep()
    _box_warn("После установки управляйте AWG через меню HYDRA → AmneziaVPN.")
    _box_bottom()


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
                    trf_val = line.split(":", 1)[-1].strip()
                    current_peer["transfer"] = trf_val
                    rx_bytes = 0
                    tx_bytes = 0
                    try:
                        import re
                        def _parse_bytes(val_str: str) -> int:
                            val_str = val_str.strip()
                            match = re.match(r'^([\d\.]+)\s*([a-zA-Z]+)?$', val_str)
                            if not match:
                                return 0
                            val = float(match.group(1))
                            unit = match.group(2)
                            if not unit:
                                return int(val)
                            unit = unit.lower()
                            if 'k' in unit:
                                return int(val * 1024)
                            elif 'm' in unit:
                                return int(val * 1024 * 1024)
                            elif 'g' in unit:
                                return int(val * 1024 * 1024 * 1024)
                            elif 't' in unit:
                                return int(val * 1024 * 1024 * 1024 * 1024)
                            return int(val)
                        
                        parts_trf = trf_val.split(",")
                        if len(parts_trf) >= 2:
                            rx_str = parts_trf[0].replace("received", "").strip()
                            tx_str = parts_trf[1].replace("sent", "").strip()
                            rx_bytes = _parse_bytes(rx_str)
                            tx_bytes = _parse_bytes(tx_str)
                        elif len(parts_trf) == 1:
                            rx_str = parts_trf[0].replace("received", "").strip()
                            rx_bytes = _parse_bytes(rx_str)
                    except Exception:
                        pass
                    current_peer["rx_bytes"] = rx_bytes
                    current_peer["tx_bytes"] = tx_bytes
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
    
    err_msg = r.stderr or ""
    if "configured logging driver does not support reading" in err_msg:
        # 1. Пробуем получить логи через journalctl по имени контейнера
        rj = subprocess.run([
            "journalctl", f"CONTAINER_NAME={name}", "-n", str(lines), "--no-pager"
        ], capture_output=True, text=True, errors="replace")
        if rj.returncode == 0 and rj.stdout.strip():
            return rj.stdout
            
        # 2. Пробуем по Full ID или Short ID
        r_id = subprocess.run([
            "docker", "inspect", "--format", "{{.Id}}", name
        ], capture_output=True, text=True, errors="replace")
        if r_id.returncode == 0 and r_id.stdout.strip():
            full_id = r_id.stdout.strip()
            rj_id = subprocess.run([
                "journalctl", f"CONTAINER_ID_FULL={full_id}", "-n", str(lines), "--no-pager"
            ], capture_output=True, text=True, errors="replace")
            if rj_id.returncode == 0 and rj_id.stdout.strip():
                return rj_id.stdout
            
            short_id = full_id[:12]
            rj_short = subprocess.run([
                "journalctl", f"CONTAINER_ID={short_id}", "-n", str(lines), "--no-pager"
            ], capture_output=True, text=True, errors="replace")
            if rj_short.returncode == 0 and rj_short.stdout.strip():
                return rj_short.stdout

        # 3. Резервный поиск по docker.service
        rj_svc = subprocess.run([
            "journalctl", "-u", "docker", "-n", "500", "--no-pager"
        ], capture_output=True, text=True, errors="replace")
        if rj_svc.returncode == 0 and rj_svc.stdout.strip():
            lines_filtered = [l for l in rj_svc.stdout.splitlines() if name in l]
            if lines_filtered:
                return "\n".join(lines_filtered[-lines:])
                
    return r.stdout + r.stderr

def _get_client_configs() -> list[dict]:
    """Получает файлы конфигурации клиентов из контейнера."""
    if not _container_exists():
        return []
    
    name = _get_container_name()
    configs = []
    
    # 1. Читаем clientsTable для извлечения информации обо всех зарегистрированных пирах
    clients_list = []
    r_table = subprocess.run(["docker", "exec", name, "cat", "/opt/amnezia/awg/clientsTable"], capture_output=True, text=True)
    if r_table.returncode == 0:
        try:
            clients_list = json.loads(r_table.stdout)
        except Exception:
            pass
            
    # 2. Ищем созданные нами файлы конфигураций в /opt/amnezia/awg/
    r_files = subprocess.run([
        "docker", "exec", name,
        "find", "/opt/amnezia/awg/", "-name", "*.conf"
    ], capture_output=True, text=True)
    
    saved_configs = {}
    if r_files.returncode == 0:
        files = [f.strip() for f in r_files.stdout.splitlines() if f.strip()]
        for f in files:
            filename = Path(f).name
            if filename in ("awg0.conf", "wg0.conf"):
                continue
            r_cat = subprocess.run([
                "docker", "exec", name,
                "cat", f
            ], capture_output=True, text=True)
            if r_cat.returncode == 0:
                saved_configs[Path(f).stem.replace("client_", "")] = r_cat.stdout.strip()
                
    for cl in clients_list:
        username = cl.get("userData", {}).get("clientName", "")
        if not username:
            continue
        # Если у нас есть сохраненный файл конфигурации (с приватным ключом)
        if username in saved_configs:
            configs.append({
                "name": username,
                "config_text": saved_configs[username]
            })
        else:
            # Создан в Amnezia, приватный ключ недоступен
            cli_ip = cl.get("userData", {}).get("allowedIps", "").replace("/32", "")
            configs.append({
                "name": f"{username} (создан в Amnezia)",
                "config_text": f"# Этот клиент был добавлен через официальное приложение Amnezia.\n# Приватный ключ хранится на устройстве клиента и недоступен на сервере.\n\n[Interface]\nAddress = {cli_ip}/24\nPrivateKey = <хранится на устройстве клиента>\n"
            })
            
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

# ── Добавление и удаление пользователей (AmneziaWG в Docker) ──────────────────

def parse_awg_conf(conf_text: str) -> tuple[dict, list[dict]]:
    lines = conf_text.splitlines()
    interface = {}
    peers = []
    
    current_section = None
    current_peer = {}
    current_comment = None
    
    for line in lines:
        line_strip = line.strip()
        if not line_strip:
            continue
        if line_strip.startswith("#"):
            if "CLIENT:" in line_strip:
                current_comment = line_strip.split("CLIENT:")[-1].strip()
            continue
            
        if line_strip.startswith("[Interface]"):
            current_section = "interface"
            continue
        elif line_strip.startswith("[Peer]"):
            if current_peer:
                peers.append(current_peer)
            current_section = "peer"
            current_peer = {}
            if current_comment:
                current_peer["name"] = current_comment
                current_comment = None
            continue
            
        if "=" in line_strip:
            key, val = line_strip.split("=", 1)
            key = key.strip()
            val = val.strip()
            if current_section == "interface":
                interface[key] = val
            elif current_section == "peer":
                current_peer[key] = val
                
    if current_peer:
        peers.append(current_peer)
        
    return interface, peers

def rebuild_awg_conf(interface: dict, peers: list[dict]) -> str:
    lines = []
    lines.append("[Interface]")
    for k, v in interface.items():
        lines.append(f"{k} = {v}")
    lines.append("")
    
    for peer in peers:
        if "name" in peer:
            lines.append(f"### CLIENT: {peer['name']}")
        lines.append("[Peer]")
        for k, v in peer.items():
            if k == "name":
                continue
            lines.append(f"{k} = {v}")
        lines.append("")
        
    return "\n".join(lines)

def get_next_available_ip(interface_address: str, peers: list[dict]) -> str:
    ip_part = interface_address.split("/")[0].split(",")[0].strip()
    octets = ip_part.split(".")
    base = ".".join(octets[:3])
    server_last_octet = int(octets[3])
    
    used_octets = {server_last_octet}
    for peer in peers:
        allowed_ips = peer.get("AllowedIPs", "")
        m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,3}))', allowed_ips)
        if m:
            used_octets.add(int(m.group(2)))
            
    for i in range(2, 255):
        if i not in used_octets:
            return f"{base}.{i}"
            
    raise ValueError("Нет свободных IP-адресов в подсети сервера.")

def _add_client(username: str) -> bool:
    """Добавляет нового пользователя (пира) в контейнер AmneziaWG."""
    if not _container_running():
        _err("Контейнер должен быть запущен для настройки пира!")
        return False
        
    name = _get_container_name()
    username = re.sub(r'[^a-zA-Z0-9_-]', '', username)
    if not username:
        _err("Недопустимое имя пользователя!")
        return False
        
    # Проверим, нет ли уже такого пользователя
    existing = _get_client_configs()
    for cfg in existing:
        if cfg["name"].split(" (")[0].lower() == username.lower():
            _err(f"Пользователь с именем '{username}' уже существует!")
            return False

    # 1. Читаем clientsTable и awg0.conf
    r_table = subprocess.run(["docker", "exec", name, "cat", "/opt/amnezia/awg/clientsTable"], capture_output=True, text=True)
    clients_list = []
    if r_table.returncode == 0:
        try:
            clients_list = json.loads(r_table.stdout)
        except Exception:
            pass

    r = subprocess.run(["docker", "exec", name, "cat", "/opt/amnezia/awg/awg0.conf"], capture_output=True, text=True)
    if r.returncode != 0:
        _err("Не удалось получить файл конфигурации сервера (awg0.conf)!")
        return False
            
    conf_text = r.stdout
    interface, peers = parse_awg_conf(conf_text)
    
    # 2. Генерируем ключи для клиента
    r_gen = subprocess.run(["docker", "exec", name, "awg", "genkey"], capture_output=True, text=True)
    if r_gen.returncode != 0:
        r_gen = subprocess.run(["docker", "exec", name, "wg", "genkey"], capture_output=True, text=True)
        if r_gen.returncode != 0:
            _err("Не удалось сгенерировать приватный ключ!")
            return False
    cli_private_key = r_gen.stdout.strip()
    
    tool_bin = "awg" if "awg" in r_gen.args[2] else "wg"
    r_pub = subprocess.run(["docker", "exec", "-i", name, tool_bin, "pubkey"], input=cli_private_key, capture_output=True, text=True)
    if r_pub.returncode != 0:
        _err("Не удалось сгенерировать публичный ключ!")
        return False
    cli_public_key = r_pub.stdout.strip()
    
    # 3. Выделяем IP-адрес для клиента
    srv_address = interface.get("Address", "10.8.1.0/24")
    try:
        cli_ip = get_next_available_ip(srv_address, peers)
    except Exception as e:
        _err(f"Ошибка выделения IP: {e}")
        return False
        
    # Читаем preshared key из wireguard_psk.key
    r_psk = subprocess.run(["docker", "exec", name, "cat", "/opt/amnezia/awg/wireguard_psk.key"], capture_output=True, text=True)
    psk = r_psk.stdout.strip() if r_psk.returncode == 0 else ""
    
    # 4. Добавляем пир в peers
    new_peer = {
        "PublicKey": cli_public_key,
        "AllowedIPs": f"{cli_ip}/32"
    }
    if psk:
        new_peer["PresharedKey"] = psk
    peers.append(new_peer)
    
    # 5. Пересобираем и записываем конфиг сервера
    new_conf_text = rebuild_awg_conf(interface, peers)
    r_write = subprocess.run(["docker", "exec", "-i", name, "tee", "/opt/amnezia/awg/awg0.conf"], input=new_conf_text, capture_output=True, text=True)
    if r_write.returncode != 0:
        _err("Не удалось сохранить конфигурацию на сервере!")
        return False
        
    # 6. Добавляем пользователя в clientsTable
    creation_date = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    new_client_entry = {
        "clientId": cli_public_key,
        "userData": {
            "allowedIps": f"{cli_ip}/32",
            "clientName": username,
            "creationDate": creation_date,
            "dataReceived": "0 B",
            "dataSent": "0 B",
            "latestHandshake": "never"
        }
    }
    clients_list.append(new_client_entry)
    new_clients_json = json.dumps(clients_list, indent=4)
    subprocess.run(["docker", "exec", "-i", name, "tee", "/opt/amnezia/awg/clientsTable"], input=new_clients_json, text=True)
    
    # 7. Применяем пир динамически в интерфейс awg0 без перезагрузки
    subprocess.run(["docker", "exec", name, "bash", "-c", f"{tool_bin} syncconf awg0 <({tool_bin}-quick strip /opt/amnezia/awg/awg0.conf)"])
    
    # 8. Генерируем клиентский файл конфигурации
    srv_private_key = interface.get("PrivateKey")
    if not srv_private_key:
        _err("Не найден приватный ключ сервера в конфигурации!")
        return False
        
    r_spub = subprocess.run(["docker", "exec", "-i", name, tool_bin, "pubkey"], input=srv_private_key, capture_output=True, text=True)
    if r_spub.returncode != 0:
        _err("Не удалось получить публичный ключ сервера!")
        return False
    srv_public_key = r_spub.stdout.strip()
    
    # Вычисляем публичный IP сервера
    server_ip = "YOUR_SERVER_IP"
    try:
        if _STATE_FILE.exists():
            st = json.loads(_STATE_FILE.read_text())
            server_ip = st.get("domain", "") or st.get("server_ip", "")
    except Exception:
        pass
    if not server_ip or server_ip == "YOUR_SERVER_IP":
        r_ip = subprocess.run(["curl", "-s", "-4", "--connect-timeout", "5", "https://api4.ipify.org"], capture_output=True, text=True)
        if r_ip.returncode == 0:
            server_ip = r_ip.stdout.strip()
            
    srv_port = interface.get("ListenPort", "40768")
    
    cli_lines = [
        "[Interface]",
        f"PrivateKey = {cli_private_key}",
        f"Address = {cli_ip}/24",
        "DNS = 1.1.1.1"
    ]
    # Добавляем параметры обфускации AmneziaWG
    for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
        if k in interface:
            cli_lines.append(f"{k} = {interface[k]}")
            
    cli_lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {srv_public_key}",
        f"Endpoint = {server_ip}:{srv_port}",
        "AllowedIPs = 0.0.0.0/0",
        "PersistentKeepalive = 25"
    ])
    if psk:
        cli_lines.append(f"PresharedKey = {psk}")
        
    client_config_text = "\n".join(cli_lines)
    
    # Сохраняем клиентский файл конфига
    client_config_path = f"/opt/amnezia/awg/client_{username}.conf"
    r_cli_save = subprocess.run(["docker", "exec", "-i", name, "tee", client_config_path], input=client_config_text, capture_output=True, text=True)
    
    if r_cli_save.returncode == 0:
        _ok(f"Пользователь '{username}' успешно добавлен!")
        _ok(f"Конфиг сохранен в контейнере: {client_config_path}")
        return True
    else:
        _err("Не удалось сохранить конфигурационный файл клиента в контейнер!")
        return False

def _delete_client(username: str) -> bool:
    """Удаляет пользователя (клиента) из конфигурации AmneziaWG."""
    if not _container_exists():
        _err("Контейнер не существует!")
        return False
        
    name = _get_container_name()
    username = re.sub(r'[^a-zA-Z0-9_-]', '', username)
    if not username:
        _err("Недопустимое имя пользователя!")
        return False

    # 1. Читаем clientsTable
    r_table = subprocess.run(["docker", "exec", name, "cat", "/opt/amnezia/awg/clientsTable"], capture_output=True, text=True)
    clients_list = []
    if r_table.returncode == 0:
        try:
            clients_list = json.loads(r_table.stdout)
        except Exception:
            pass
            
    target_client = None
    new_clients_list = []
    for cl in clients_list:
        if cl.get("userData", {}).get("clientName", "").lower() == username.lower():
            target_client = cl
        else:
            new_clients_list.append(cl)
            
    if not target_client:
        _err(f"Пользователь '{username}' не найден в clientsTable!")
        return False
        
    cli_public_key = target_client.get("clientId")

    # 2. Считываем текущий awg0.conf
    r = subprocess.run(["docker", "exec", name, "cat", "/opt/amnezia/awg/awg0.conf"], capture_output=True, text=True)
    if r.returncode != 0:
        _err("Не удалось прочитать awg0.conf из контейнера!")
        return False
            
    conf_text = r.stdout
    interface, peers = parse_awg_conf(conf_text)
    
    new_peers = []
    for peer in peers:
        if peer.get("PublicKey") == cli_public_key:
            continue
        new_peers.append(peer)
        
    # 3. Пересобираем и сохраняем новый awg0.conf
    new_conf_text = rebuild_awg_conf(interface, new_peers)
    r_write = subprocess.run(["docker", "exec", "-i", name, "tee", "/opt/amnezia/awg/awg0.conf"], input=new_conf_text, capture_output=True, text=True)
    if r_write.returncode != 0:
        _err("Не удалось сохранить обновленную конфигурацию сервера!")
        return False
        
    # 4. Пересохраняем clientsTable
    new_clients_json = json.dumps(new_clients_list, indent=4)
    subprocess.run(["docker", "exec", "-i", name, "tee", "/opt/amnezia/awg/clientsTable"], input=new_clients_json, text=True)
    
    # 5. Применяем изменения "на лету"
    tool_bin = "awg" if "awg" in r.args[3] else "wg"
    subprocess.run(["docker", "exec", name, "bash", "-c", f"{tool_bin} syncconf awg0 <({tool_bin}-quick strip /opt/amnezia/awg/awg0.conf)"])
        
    # 6. Удаляем конфигурационный файл клиента в контейнере
    subprocess.run(["docker", "exec", name, "rm", "-f", f"/opt/amnezia/awg/client_{username}.conf"])
    
    _ok(f"Пользователь '{username}' успешно удален!")
    return True

# ── Публичное API для интеграции с подписочной системой ───────────────────────

def awg_user_exists(username: str) -> bool:
    """Проверяет, существует ли пользователь AWG в clientsTable."""
    if not _container_exists():
        return False
    name = _get_container_name()
    r = subprocess.run(
        ["docker", "exec", name, "cat", "/opt/amnezia/awg/clientsTable"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0:
        return False
    try:
        clients = json.loads(r.stdout)
        username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username).lower()
        for cl in clients:
            cname = cl.get("userData", {}).get("clientName", "").lower()
            if cname == username_clean:
                return True
    except Exception:
        pass
    return False


def ensure_awg_user(username: str) -> tuple[bool, str]:
    """
    Создаёт AWG-пользователя если его ещё нет.
    Возвращает (created: bool, message: str).

    Используется из подписочного меню (_core.py):
        from vless_installer.modules.amnezia_vpn import ensure_awg_user
        ok, msg = ensure_awg_user(email_prefix)
    """
    username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username)
    if not username_clean:
        return False, "Некорректное имя пользователя"

    if not _docker_available():
        return False, "Docker недоступен"
    if not _container_exists():
        return False, "Контейнер AmneziaWG не найден"
    if not _container_running():
        return False, "Контейнер не запущен"

    if awg_user_exists(username_clean):
        # Пользователь уже есть — проверим, есть ли у него client_.conf
        conf = _get_client_conf_text(username_clean)
        if conf:
            return False, f"Пользователь '{username_clean}' уже существует (конфиг есть)"
        else:
            return False, f"Пользователь '{username_clean}' уже существует (конфиг в Amnezia-приложении)"

    ok = _add_client(username_clean)
    if ok:
        return True, f"Пользователь '{username_clean}' создан в AmneziaWG"
    return False, f"Не удалось создать пользователя '{username_clean}'"


def ensure_delete_awg_user(username: str) -> tuple[bool, str]:
    """Удаляет AWG-пользователя из контейнера AmneziaWG."""
    username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username)
    if not username_clean:
        return False, "Некорректное имя пользователя"
    if not _container_exists():
        return False, "Контейнер AmneziaWG не найден"
    if not _container_running():
        return False, "Контейнер не запущен"
    if not awg_user_exists(username_clean):
        return False, f"Пользователь '{username_clean}' не найден в AmneziaWG"
    ok = _delete_client(username_clean)
    if ok:
        return True, f"Пользователь '{username_clean}' успешно удален"
    return False, f"Не удалось удалить пользователя '{username_clean}'"


def _get_client_conf_text(username: str) -> str | None:
    """Читает текст клиентского конфига из контейнера, или None если нет."""
    if not _container_exists():
        return None
    name = _get_container_name()
    conf_path = f"/opt/amnezia/awg/client_{username}.conf"
    r = subprocess.run(
        ["docker", "exec", name, "cat", conf_path],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    return None


def get_awg_traffic_for_user(username: str) -> dict:
    """
    Возвращает статистику трафика AWG для конкретного пользователя.

    Алгоритм:
      1. Читаем clientsTable → находим publicKey по clientName
      2. Запрашиваем 'awg show awg0' → находим peer по publicKey → берём transfer

    Возвращает:
      {
        "found": bool,
        "rx_bytes": int,   # получено (сервер → клиент)
        "tx_bytes": int,   # отправлено (клиент → сервер)
        "total_bytes": int,
        "rx_human": str,   # "1.23 MiB"
        "tx_human": str,
        "total_human": str,
        "handshake": str,  # "3d, 2h ago" или "never"
        "client_ip": str,  # "10.8.1.3/32"
        "data_received": str,  # из clientsTable (строка от Amnezia)
        "data_sent": str,
      }
    """
    empty = {
        "found": False, "rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0,
        "rx_human": "0 B", "tx_human": "0 B", "total_human": "0 B",
        "handshake": "never", "client_ip": "", "data_received": "0 B", "data_sent": "0 B",
    }
    if not _container_exists():
        return empty

    name = _get_container_name()
    username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', username).lower()

    # Шаг 1: найти publicKey по clientName в clientsTable
    target_pubkey = None
    client_ip = ""
    data_received_str = "0 B"
    data_sent_str = "0 B"
    try:
        r = subprocess.run(
            ["docker", "exec", name, "cat", "/opt/amnezia/awg/clientsTable"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            for cl in json.loads(r.stdout):
                ud = cl.get("userData", {})
                cname = ud.get("clientName", "").lower()
                if cname == username_clean or cname.split(" (")[0] == username_clean:
                    target_pubkey = cl.get("clientId", "")
                    client_ip = ud.get("allowedIps", "")
                    data_received_str = ud.get("dataReceived", "0 B")
                    data_sent_str = ud.get("dataSent", "0 B")
                    break
    except Exception:
        pass

    if not target_pubkey:
        return {**empty, "found": False}

    # Шаг 2: получить live-статистику из awg show
    rx_bytes = 0
    tx_bytes = 0
    handshake = "never"
    try:
        r2 = subprocess.run(
            ["docker", "exec", name, "awg", "show", "awg0"],
            capture_output=True, text=True, timeout=10
        )
        if r2.returncode != 0:
            r2 = subprocess.run(
                ["docker", "exec", name, "wg", "show", "awg0"],
                capture_output=True, text=True, timeout=10
            )
        if r2.returncode == 0:
            in_peer = False
            for line in r2.stdout.splitlines():
                line = line.strip()
                if line.startswith("peer:"):
                    in_peer = target_pubkey in line
                elif in_peer:
                    if line.startswith("transfer:"):
                        # "transfer: 12.34 MiB received, 56.78 MiB sent"
                        parts = line.split("transfer:")[-1].strip().split(",")
                        rx_bytes = _parse_transfer_bytes(parts[0].strip() if parts else "0")
                        tx_bytes = _parse_transfer_bytes(parts[1].strip() if len(parts) > 1 else "0")
                    elif line.startswith("latest handshake:"):
                        handshake = line.split("latest handshake:")[-1].strip()
                    elif line.startswith("peer:"):
                        in_peer = False
    except Exception:
        pass

    total = rx_bytes + tx_bytes
    return {
        "found": True,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "total_bytes": total,
        "rx_human": _bytes_human(rx_bytes),
        "tx_human": _bytes_human(tx_bytes),
        "total_human": _bytes_human(total),
        "handshake": handshake,
        "client_ip": client_ip,
        "data_received": data_received_str,
        "data_sent": data_sent_str,
    }


def _parse_transfer_bytes(s: str) -> int:
    """Парсит '12.34 MiB' → int байт."""
    try:
        parts = s.split()
        if len(parts) < 2:
            return 0
        val = float(parts[0])
        unit = parts[1].upper().rstrip('B').rstrip('I')
        mult = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
        return int(val * mult.get(unit, 1))
    except Exception:
        return 0


def _bytes_human(n: int) -> str:
    """Форматирует байты в человекочитаемый вид."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PiB"


def _show_single_client_config(cfg: dict) -> None:
    sn_link = None
    try:
        from vless_installer.modules.sub_generator import generate_awg_sn_link
        if "хранится на устройстве клиента" not in cfg["config_text"]:
            sn_link = generate_awg_sn_link(cfg["config_text"], profile_name=cfg["name"].split(" (")[0])
    except Exception as e:
        _log("ERROR", f"Error generating sn_link: {e}")

    while True:
        os.system("clear")
        print()
        _box_top(f"🔑 Конфигурация клиента: {cfg['name']}")
        _box_sep()
        
        lines = cfg["config_text"].splitlines()
        for line in lines:
            _box_row(f"  {line}")
            
        if sn_link:
            _box_sep()
            _box_row("🔗 Ссылка sn://awg для Nekobox / SFA:")
            _box_row(f"  {CYAN}{sn_link}{NC}")
            
        _box_sep()
        _box_item("1", "📱 Показать QR-код для ссылки sn://awg")
        _box_item("2", "📱 Показать QR-код для конфига (.conf)")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()
        
        try:
            choice = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
            
        if choice in ("0", "q", "Q", ""):
            break
        elif choice == "1":
            if not sn_link:
                _err("Ссылка недоступна (приватный ключ хранится на устройстве клиента)")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            os.system("clear")
            print()
            _box_top("QR-код для sn://awg")
            _box_sep()
            try:
                subprocess.run(["qrencode", "-t", "ansiutf8"], input=sn_link, text=True)
            except Exception:
                _err("Не удалось отобразить QR-код. Убедитесь, что утилита qrencode установлена.")
            _box_bottom()
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif choice == "2":
            if "хранится на устройстве клиента" in cfg["config_text"]:
                _err("Приватный ключ этого клиента отсутствует на сервере.")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            os.system("clear")
            print()
            _box_top("QR-код для конфига (.conf)")
            _box_sep()
            try:
                subprocess.run(["qrencode", "-t", "ansiutf8"], input=cfg["config_text"], text=True)
            except Exception:
                _err("Не удалось отобразить QR-код. Убедитесь, что утилита qrencode установлена.")
            _box_bottom()
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")


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
        
        port_str = "—"
        if info["ports"]:
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
            _box_item("I", f"{GREEN}🐳 Установить Docker{NC}")
        elif not exists:
            _box_row(f"  Docker:       {GREEN}🟢 установлен{NC}")
            _box_row(f"  Контейнер:    {RED}🔴 {name} не найден{NC}")
            _box_sep()
            _box_warn(f"Контейнер {name} не запущен и не настроен.")
            _box_item("P", f"{GREEN}📋 Подготовить сервер + инструкция Amnezia{NC}")
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
            if running:
                _box_item("10", f"{GREEN}Добавить пользователя (клиента){NC}")
                _box_item("11", f"{RED}Удалить пользователя (клиента){NC}")
            _box_item("9", f"{RED}Удалить контейнер {name}{NC}")
            
        _box_back()
        _box_bottom()
        
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return
            
        if ch in ("q", "Q", "0", ""):
            return

        if ch == "i" and not has_docker:
            if install_docker_engine():
                prepare_awg_environment()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            continue

        if ch == "p" and has_docker and not exists:
            prepare_awg_environment()
            show_awg_client_instructions()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            continue
            
        if not exists:
            _warn("Контейнер не существует. Установите AWG через клиент Amnezia (пункт P).")
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
            
            configs = _get_client_configs()
            key_to_name = {}
            r_srv = subprocess.run(["docker", "exec", name, "cat", "/opt/amnezia/awg/clientsTable"], capture_output=True, text=True)
            if r_srv.returncode == 0:
                try:
                    clients_parsed = json.loads(r_srv.stdout)
                    for cl in clients_parsed:
                        if cl.get("clientId") and cl.get("userData", {}).get("clientName"):
                            key_to_name[cl["clientId"]] = cl["userData"]["clientName"]
                except Exception:
                    pass
            
            if stats["peers"]:
                col_widths = [18, 16, 18, 28]
                top_border = "  ┌" + "┬".join("─" * (w + 2) for w in col_widths) + "┐"
                sep_border = "  ├" + "┼".join("─" * (w + 2) for w in col_widths) + "┤"
                bot_border = "  └" + "┴".join("─" * (w + 2) for w in col_widths) + "┘"
                
                h_name = "Клиент".ljust(col_widths[0])
                h_ip = "Внутренний IP".ljust(col_widths[1])
                h_hs = "Активность".ljust(col_widths[2])
                h_trf = "Трафик".ljust(col_widths[3])
                
                print(top_border)
                print(f"  │ {BOLD}{h_name}{NC} │ {BOLD}{h_ip}{NC} │ {BOLD}{h_hs}{NC} │ {BOLD}{h_trf}{NC} │")
                print(sep_border)
                
                for p in stats["peers"]:
                    pubkey = p.get('public_key', '')
                    friendly_name = key_to_name.get(pubkey, "Неизвестный")
                    if len(friendly_name) > col_widths[0]:
                        friendly_name = friendly_name[:col_widths[0]-3] + "..."
                    name_part = friendly_name.ljust(col_widths[0])
                    
                    ip = p.get("allowed_ips", "—")
                    if len(ip) > col_widths[1]:
                        ip = ip[:col_widths[1]-3] + "..."
                    ip_part = ip.ljust(col_widths[1])
                    
                    hs = p.get("latest_handshake", "never")
                    hs_clean = hs.replace("seconds", "s").replace("second", "s") \
                                 .replace("minutes", "m").replace("minute", "m") \
                                 .replace("hours", "h").replace("hour", "h") \
                                 .replace("days", "d").replace("day", "d") \
                                 .replace(" ago", "")
                    if len(hs_clean) > col_widths[2]:
                        hs_clean = hs_clean[:col_widths[2]-3] + "..."
                    hs_part = hs_clean.ljust(col_widths[2])
                    
                    trf = p.get("transfer", "—")
                    trf_clean = trf.replace(" received", " rx").replace(" sent", " tx").replace(",", " /")
                    if len(trf_clean) > col_widths[3]:
                        trf_clean = trf_clean.replace(" KiB", " K").replace(" MiB", " M").replace(" GiB", " G")
                    if len(trf_clean) > col_widths[3]:
                        trf_clean = trf_clean[:col_widths[3]-3] + "..."
                    trf_part = trf_clean.ljust(col_widths[3])
                    
                    print(f"  │ {GREEN}{name_part}{NC} │ {CYAN}{ip_part}{NC} │ {YELLOW}{hs_part}{NC} │ {WHITE}{trf_part}{NC} │")
                print(bot_border)
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
            while True:
                os.system("clear")
                print()
                _box_top("🔑 Клиентские конфигурации AWG")
                _box_sep()
                
                configs = _get_client_configs()
                if not configs:
                    _box_warn("Конфигурации клиентов не найдены в контейнере.")
                    _box_bottom()
                    input(f"\n{BLUE}Нажмите Enter...{NC}")
                    break
                    
                _box_row("Доступные клиенты:")
                for i, cfg in enumerate(configs, 1):
                    _box_row(f"  [{i}] {cfg['name']}")
                _box_sep()
                _box_item_exit("0", "← Назад")
                _box_bottom()
                
                try:
                    sel = input(f"{CYAN}Выберите номер клиента:{NC} ").strip()
                except KeyboardInterrupt:
                    break
                    
                if sel in ("0", "q", "Q", ""):
                    break
                    
                if sel.isdigit() and 1 <= int(sel) <= len(configs):
                    cfg = configs[int(sel)-1]
                    _show_single_client_config(cfg)
            
        elif ch == "9":
            try:
                ans = input(f"  {RED}Вы действительно хотите УДАЛИТЬ контейнер amnezia-awg2? [y/N]:{NC} ").strip().lower()
            except KeyboardInterrupt:
                continue
            if ans == "y":
                if _container_remove():
                    _ok("Контейнер успешно удален!")
                else:
                    _err("Ошибка удаления контейнера.")
            time.sleep(1.5)
            
        elif ch == "10" and running:
            os.system("clear")
            print()
            _box_top("👤 Добавить нового пользователя")
            _box_bottom()
            print()
            try:
                username = input("Введите имя нового пользователя (латиница, цифры, дефис): ").strip()
            except KeyboardInterrupt:
                continue
            if username:
                _add_client(username)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            
        elif ch == "11" and running:
            os.system("clear")
            print()
            _box_top("👤  Удалить пользователя")
            _box_bottom()
            print()
            configs = _get_client_configs()
            if not configs:
                _warn("Пользователи не найдены.")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
                
            print("Список пользователей:")
            for i, cfg in enumerate(configs, 1):
                print(f"  {i}. {CYAN}{cfg['name']}{NC}")
            print()
            
            try:
                sel = input("Выберите номер пользователя для УДАЛЕНИЯ (Enter = отмена): ").strip()
            except KeyboardInterrupt:
                continue
                
            if sel.isdigit() and 1 <= int(sel) <= len(configs):
                cfg = configs[int(sel)-1]
                # Извлекаем чистое имя пользователя без приписок о Amnezia
                clean_username = cfg['name'].split(" (")[0]
                try:
                    ans = input(f"Вы действительно хотите удалить пользователя {clean_username}? [y/N]: ").strip().lower()
                except KeyboardInterrupt:
                    continue
                if ans == 'y':
                    _delete_client(clean_username)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            
        else:
            _warn("Неверный выбор")
            time.sleep(1)
