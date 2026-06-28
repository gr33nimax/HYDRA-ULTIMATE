"""
hydra/core/singbox.py — Управление Sing-Box.

Установка, запуск, генерация конфига, проверка статуса.
Sing-Box — центральный оркестратор: все протоколы → inbound'ы,
WARP/DNS/GeoIP → outbound/route/rules.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from hydra.core.state import AppState, ProtocolState, load_state, save_state

SINGBOX_BIN = Path("/usr/local/bin/sing-box")
SINGBOX_CONFIG = Path("/etc/sing-box/config.json")
SINGBOX_SERVICE = Path("/etc/systemd/system/sing-box.service")
LOG_FILE = Path("/var/log/hydra/install.log")


def _log(level: str, msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        ts = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{level}] {msg}\n")
    except Exception:
        pass


def _run(cmd: list, capture: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    kw = {"timeout": timeout}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    return subprocess.run(cmd, **kw)


# ═════════════════════════════════════════════════════════════════════════════
#  Установка
# ═════════════════════════════════════════════════════════════════════════════

def is_installed() -> bool:
    """Проверяет, установлен ли Sing-Box."""
    return SINGBOX_BIN.exists()


def get_version() -> Optional[str]:
    """Возвращает версию установленного Sing-Box."""
    if not is_installed():
        return None
    r = _run([str(SINGBOX_BIN), "version"])
    if r.returncode == 0:
        return r.stdout.strip().split()[-1]
    return None


def install() -> bool:
    """Устанавливает Sing-Box из официального репозитория."""
    if is_installed():
        return True

    _log("INFO", "Installing Sing-Box...")

    script = """
    set -e
    curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
    chmod 644 /etc/apt/keyrings/sagernet.asc
    echo "deb [signed-by=/etc/apt/keyrings/sagernet.asc] https://deb.sagernet.org/ * *" \
        > /etc/apt/sources.list.d/sagernet.list
    apt-get update -qq
    apt-get install -y -qq sing-box
    """

    r = subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, timeout=120,
    )

    if r.returncode != 0:
        _log("ERROR", f"Sing-Box install failed: {r.stderr[:500]}")
        return False

    _log("INFO", f"Sing-Box installed: {get_version()}")
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  Генерация конфига
# ═════════════════════════════════════════════════════════════════════════════

def _base_config(state: AppState) -> dict:
    """Базовый скелет конфига Sing-Box."""
    return {
        "log": {
            "level": "info",
            "timestamp": True,
            "output": "/var/log/sing-box/sing-box.log",
        },
        "dns": _dns_config(state),
        "inbounds": [],
        "outbounds": [],
        "route": {
            "rules": [],
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "path": "/var/lib/sing-box/cache.db",
            },
        },
    }


def _dns_config(state: AppState) -> dict:
    """DNS-конфиг: DNSCrypt или публичные DoH."""
    if state.network.dnscrypt_enabled:
        return {
            "servers": [
                {
                    "tag": "dnscrypt-local",
                    "address": f"127.0.0.1:{state.network.dnscrypt_port}",
                    "detour": "direct",
                }
            ],
            "rules": [],
        }
    return {
        "servers": [
            {
                "tag": "dns-remote",
                "address": "https://dns.quad9.net/dns-query",
                "address_resolver": "dns-direct",
                "strategy": "ipv4_only",
                "detour": "direct",
            },
            {
                "tag": "dns-direct",
                "address": "1.1.1.1",
                "detour": "direct",
            },
        ],
        "rules": [],
    }


def _warp_outbound(state: AppState) -> dict | None:
    """WARP-исходящее, если включено."""
    if not state.network.warp_enabled:
        return None
    return {
        "type": "wireguard",
        "tag": "warp",
        "server": "engage.cloudflareclient.com",
        "server_port": 2408,
        "local_address": ["172.16.0.2/32"],
        "private_key": "{{WARP_PRIVATE_KEY}}",
        "peer_public_key": "{{WARP_PEER_KEY}}",
        "mtu": 1280,
    }


def generate_config(state: AppState, plugin_fragments: dict[str, dict]) -> dict:
    """
    Собирает полный конфиг Sing-Box из базового скелета и фрагментов плагинов.

    Каждый плагин отдаёт словарь с опциональными ключами:
      - inbounds: list[dict]
      - outbounds: list[dict]
      - route: dict (rules)
    """
    config = _base_config(state)

    # Собираем inbound'ы от активных плагинов
    for name, proto in state.protocols.items():
        if proto.enabled and name in plugin_fragments:
            frag = plugin_fragments[name]
            config["inbounds"].extend(frag.get("inbounds", []))
            config["outbounds"].extend(frag.get("outbounds", []))
            config["route"]["rules"].extend(frag.get("route_rules", []))

    # WARP outbound
    warp = _warp_outbound(state)
    if warp:
        config["outbounds"].append(warp)

    # Default direct outbound (always present)
    config["outbounds"].append({"type": "direct", "tag": "direct"})

    return config


def write_config(config: dict) -> bool:
    """Записывает конфиг и проверяет валидность."""
    SINGBOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)

    tmp = SINGBOX_CONFIG.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")

    # Валидация
    r = _run([str(SINGBOX_BIN), "check", "-c", str(tmp)])
    if r.returncode != 0:
        _log("ERROR", f"Sing-Box config invalid: {r.stderr[:500]}")
        tmp.unlink(missing_ok=True)
        return False

    tmp.replace(SINGBOX_CONFIG)
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  Управление службой
# ═════════════════════════════════════════════════════════════════════════════

def _install_service() -> bool:
    """Создаёт systemd-юнит для sing-box."""
    unit = f"""[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/sing-box
ExecStart={SINGBOX_BIN} run -c {SINGBOX_CONFIG}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=30
LimitNPROC=500
LimitNOFILE=1000000
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
"""
    SINGBOX_SERVICE.parent.mkdir(parents=True, exist_ok=True)
    SINGBOX_SERVICE.write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    return True


def start() -> bool:
    """Запускает sing-box."""
    _install_service()
    r = _run(["systemctl", "start", "sing-box"], capture=False)
    if r.returncode != 0:
        return False
    time.sleep(1)
    return is_running()


def stop() -> bool:
    """Останавливает sing-box."""
    _run(["systemctl", "stop", "sing-box"], capture=False)
    return not is_running()


def reload() -> bool:
    """Перезагружает конфиг sing-box (graceful)."""
    if not is_running():
        return start()
    r = _run(["systemctl", "reload", "sing-box"], capture=False)
    return r.returncode == 0


def restart() -> bool:
    """Полный перезапуск sing-box."""
    _run(["systemctl", "restart", "sing-box"], capture=False)
    time.sleep(1)
    return is_running()


def is_running() -> bool:
    """Проверяет, работает ли sing-box."""
    r = _run(["systemctl", "is-active", "--quiet", "sing-box"])
    return r.returncode == 0


def enable_autostart() -> None:
    """Включает автозапуск при загрузке."""
    _run(["systemctl", "enable", "sing-box"], capture=False)


def status_text() -> str:
    """Возвращает текстовый статус Sing-Box."""
    version = get_version()
    running = is_running()
    return (
        f"Sing-Box: {version or 'не установлен'} | "
        f"{'✓ запущен' if running else '✗ остановлен'}"
    )
