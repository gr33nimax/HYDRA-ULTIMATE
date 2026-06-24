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
        clean = re.sub(r'\\x1b\\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [AMNEZIA] [{level}] {clean}\\n")
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
                if Path(f).name == "awg0.conf" or Path(f).name == "wg0.conf":
                    continue
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
        
    return "\\n".join(lines)

def get_next_available_ip(interface_address: str, peers: list[dict]) -> str:
    ip_part = interface_address.split("/")[0].split(",")[0].strip()
    octets = ip_part.split(".")
    base = ".".join(octets[:3])
    server_last_octet = int(octets[3])
    
    used_octets = {server_last_octet}
    for peer in peers:
        allowed_ips = peer.get("AllowedIPs", "")
        m = re.search(r'(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.(\\d{1,3}))', allowed_ips)
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
        
    existing = _get_client_configs()
    for cfg in existing:
        if cfg["name"].lower() == username.lower():
            _err(f"Пользователь с именем '{username}' уже существует!")
            return False

    r = subprocess.run(["docker", "exec", name, "cat", "/etc/amnezia/amneziawg/awg0.conf"], capture_output=True, text=True)
    if r.returncode != 0:
        r = subprocess.run(["docker", "exec", name, "cat", "/etc/wireguard/wg0.conf"], capture_output=True, text=True)
        if r.returncode != 0:
            _err("Не удалось найти файл конфигурации сервера (awg0.conf/wg0.conf)!")
            return False
            
    conf_path_in_container = "/etc/amnezia/amneziawg/awg0.conf" if "amneziawg" in r.args[3] else "/etc/wireguard/wg0.conf"
    conf_text = r.stdout
    interface, peers = parse_awg_conf(conf_text)
    
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
    
    srv_address = interface.get("Address", "10.8.0.1/24")
    try:
        cli_ip = get_next_available_ip(srv_address, peers)
    except Exception as e:
        _err(f"Ошибка выделения IP: {e}")
        return False
        
    new_peer = {
        "name": username,
        "PublicKey": cli_public_key,
        "AllowedIPs": f"{cli_ip}/32"
    }
    peers.append(new_peer)
    
    new_conf_text = rebuild_awg_conf(interface, peers)
    r_write = subprocess.run(["docker", "exec", "-i", name, "tee", conf_path_in_container], input=new_conf_text, capture_output=True, text=True)
    if r_write.returncode != 0:
        _err("Не удалось сохранить конфигурацию на сервере!")
        return False
        
    iface_name = "awg0" if "awg0" in conf_path_in_container else "wg0"
    subprocess.run(["docker", "exec", name, tool_bin, "set", iface_name, "peer", cli_public_key, "allowed-ips", f"{cli_ip}/32"])
    
    srv_private_key = interface.get("PrivateKey")
    if not srv_private_key:
        _err("Не найден приватный ключ сервера в конфигурации!")
        return False
        
    r_spub = subprocess.run(["docker", "exec", "-i", name, tool_bin, "pubkey"], input=srv_private_key, capture_output=True, text=True)
    if r_spub.returncode != 0:
        _err("Не удалось получить публичный ключ сервера!")
        return False
    srv_public_key = r_spub.stdout.strip()
    
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
            
    srv_port = interface.get("ListenPort", "51820")
    
    cli_lines = [
        "[Interface]",
        f"PrivateKey = {cli_private_key}",
        f"Address = {cli_ip}/24",
        "DNS = 1.1.1.1"
    ]
    for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
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
    
    client_config_text = "\\n".join(cli_lines)
    
    subprocess.run(["docker", "exec", name, "mkdir", "-p", "/opt/amnezia/clients/"])
    client_config_path = f"/opt/amnezia/clients/{username}.conf"
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

    r = subprocess.run(["docker", "exec", name, "cat", "/etc/amnezia/amneziawg/awg0.conf"], capture_output=True, text=True)
    if r.returncode != 0:
        r = subprocess.run(["docker", "exec", name, "cat", "/etc/wireguard/wg0.conf"], capture_output=True, text=True)
        if r.returncode != 0:
            _err("Не удалось найти файл конфигурации сервера!")
            return False
            
    conf_path_in_container = "/etc/amnezia/amneziawg/awg0.conf" if "amneziawg" in r.args[3] else "/etc/wireguard/wg0.conf"
    conf_text = r.stdout
    interface, peers = parse_awg_conf(conf_text)
    
    target_peer = None
    new_peers = []
    for peer in peers:
        if peer.get("name", "").lower() == username.lower():
            target_peer = peer
        else:
            new_peers.append(peer)
            
    if not target_peer:
        _err(f"Пользователь '{username}' не найден в конфигурации сервера!")
        return False
        
    cli_public_key = target_peer.get("PublicKey")
    
    new_conf_text = rebuild_awg_conf(interface, new_peers)
    r_write = subprocess.run(["docker", "exec", "-i", name, "tee", conf_path_in_container], input=new_conf_text, capture_output=True, text=True)
    if r_write.returncode != 0:
        _err("Не удалось сохранить обновленную конфигурацию сервера!")
        return False
        
    if _container_running() and cli_public_key:
        tool_bin = "awg" if "awg" in conf_path_in_container else "wg"
        iface_name = "awg0" if "awg0" in conf_path_in_container else "wg0"
        subprocess.run(["docker", "exec", name, tool_bin, "set", iface_name, "peer", cli_public_key, "remove"])
        
    subprocess.run(["docker", "exec", name, "rm", "-f", f"/opt/amnezia/clients/{username}.conf"])
    
    _ok(f"Пользователь '{username}' успешно удален!")
    return True

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
            
            configs = _get_client_configs()
            key_to_name = {}
            r_srv = subprocess.run(["docker", "exec", name, "cat", "/etc/amnezia/amneziawg/awg0.conf"], capture_output=True, text=True)
            if r_srv.returncode == 0:
                _, peers_parsed = parse_awg_conf(r_srv.stdout)
                for p in peers_parsed:
                    if p.get("PublicKey") and p.get("name"):
                        key_to_name[p["PublicKey"]] = p["name"]
            
            if stats["peers"]:
                for p in stats["peers"]:
                    pubkey = p.get('public_key', '')
                    friendly_name = key_to_name.get(pubkey, "Неизвестный клиент")
                    print(f"{BOLD}Пользователь:{NC} {GREEN}{friendly_name}{NC}")
                    print(f"  Public Key: {CYAN}{pubkey}{NC}")
                    if p.get("endpoint"):
                        print(f"  Эндпоинт:   {p['endpoint']}")
                    if p.get("allowed_ips"):
                        print(f"  AllowedIP:  {p['allowed_ips']}")
                    if p.get("latest_handshake"):
                        print(f"  Handshake:  {p['latest_handshake']}")
                    if p.get("transfer"):
                        print(f"  Трафик:     {p['transfer']}")
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
            input(f"\\n{BLUE}Нажмите Enter...{NC}")
            
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
                try:
                    ans = input(f"Вы действительно хотите удалить пользователя {cfg['name']}? [y/N]: ").strip().lower()
                except KeyboardInterrupt:
                    continue
                if ans == 'y':
                    _delete_client(cfg['name'])
            input(f"\\n{BLUE}Нажмите Enter...{NC}")
            
        else:
            _warn("Неверный выбор")
            time.sleep(1)
