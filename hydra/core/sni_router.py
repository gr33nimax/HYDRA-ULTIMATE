"""hydra/core/sni_router.py — Управление HAProxy: установка, генерация конфига, systemd, валидация."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from hydra.core.state import AppState

HAPROXY_BIN = "/usr/sbin/haproxy"
HAPROXY_CFG = Path("/etc/haproxy/haproxy.cfg")
HAPROXY_CFG_DIR = Path("/etc/haproxy")
SERVICE_NAME = "haproxy"
FRONTEND_PORT = 443

# Пул внутренних портов для бэкендов за SNI-мультиплексором
_INTERNAL_PORTS = {
    "naive": 10443,
    "anytls": 10444,
}

def is_installed() -> bool:
    """Проверяет, установлен ли HAProxy."""
    return Path(HAPROXY_BIN).exists() or shutil.which("haproxy") is not None

def install() -> bool:
    """Устанавливает HAProxy через apt."""
    if is_installed():
        return True
    
    # apt-get install -y haproxy
    r = subprocess.run(["apt-get", "update"], capture_output=True)
    r = subprocess.run(["apt-get", "install", "-y", "haproxy"], capture_output=True)
    return r.returncode == 0

def needs_mux(state: AppState) -> bool:
    """True, если включено 2+ TLS-443 плагина и нужен мультиплексор."""
    count = 0
    for name in _INTERNAL_PORTS:
        proto = state.protocols.get(name)
        if proto and proto.enabled:
            # Check if domain config is present
            if name == "naive" and state.network.domain:
                count += 1
            elif name == "anytls" and proto.config.get("domain"):
                count += 1
    return count >= 2

def is_active() -> bool:
    """Проверяет, активен ли SNI-мультиплексор (>1 бэкенд на :443)."""
    if not is_installed():
        return False
    r = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True)
    return r.stdout.strip() == "active"

def get_internal_port(plugin_name: str) -> int:
    """Возвращает внутренний порт для плагина."""
    return _INTERNAL_PORTS.get(plugin_name, 0)

def get_effective_port(plugin_name: str, state: AppState) -> int:
    """Возвращает порт, на котором плагин должен слушать.
    
    - Если SNI-мультиплексор активен → внутренний порт (10443/10444)
    - Если единственный TLS-443 плагин → 443 напрямую
    """
    if needs_mux(state):
        return get_internal_port(plugin_name)
    return FRONTEND_PORT

def _generate_config(backends: list[dict]) -> str:
    """Генерирует HAProxy конфиг для TCP SNI routing.
    
    backends = [
        {"name": "naive", "domain": "proxy1.example.com", "port": 10443},
        {"name": "anytls", "domain": "proxy2.example.com", "port": 10444},
    ]
    """
    lines = [
        "global",
        "    log /dev/log local0",
        "    maxconn 4096",
        "",
        "defaults",
        "    mode tcp",
        "    timeout connect 5s",
        "    timeout client 1h",
        "    timeout server 1h",
        "",
        "frontend tls_mux",
        "    bind *:443",
        "    tcp-request inspect-delay 5s",
        "    tcp-request content accept if { req_ssl_hello_type 1 }",
        ""
    ]
    
    for b in backends:
        name = b["name"]
        domain = b["domain"]
        lines.append(f"    use_backend bk_{name} if {{ req_ssl_sni -i {domain} }}")
        
    if backends:
        first_name = backends[0]["name"]
        lines.append(f"    default_backend bk_{first_name}")
        
    lines.append("")
    for b in backends:
        name = b["name"]
        port = b["port"]
        lines.append(f"backend bk_{name}")
        lines.append(f"    server {name} 127.0.0.1:{port}")
        lines.append("")
        
    return "\n".join(lines)

def rebuild(state: AppState) -> bool:
    """Пересобирает HAProxy конфиг и reload/stop по текущему state.
    
    Логика:
    1. Собрать список активных TLS-443 бэкендов
    2. Если 0-1 бэкенд → остановить HAProxy, плагин слушает :443 напрямую
    3. Если 2+ бэкендов → сгенерировать конфиг, запустить HAProxy
    """
    backends = []
    for name, port in _INTERNAL_PORTS.items():
        proto = state.protocols.get(name)
        if proto and proto.enabled:
            domain = ""
            if name == "naive":
                domain = state.network.domain
            elif name == "anytls":
                domain = proto.config.get("domain", "")
            if domain:
                backends.append({
                    "name": name,
                    "domain": domain,
                    "port": port
                })
                
    if len(backends) < 2:
        stop()
        return True

    # Убедимся, что HAProxy установлен
    if not is_installed():
        if not install():
            return False

    # Сгенерировать и записать конфиг
    cfg_content = _generate_config(backends)
    HAPROXY_CFG_DIR.mkdir(parents=True, exist_ok=True)
    HAPROXY_CFG.write_text(cfg_content, encoding="utf-8")

    # Перед тем как запустить/перезапустить HAProxy на 443 порту,
    # нам нужно убедиться, что caddy (naive) переехал на свой внутренний порт 10443.
    # Так как мы изменили состояние (теперь 2+ бэкенда), вызовы get_effective_port("naive", state)
    # внутри configure() вернут 10443. Переконфигурируем caddy-naive:
    from hydra.plugins import registry
    naive_plugin = registry.get("naive")
    if naive_plugin:
        naive_proto = state.protocols.get("naive")
        if naive_proto and naive_proto.enabled:
            # Настраиваем на новый порт и перезапускаем caddy-naive
            naive_plugin.configure(state)
            naive_plugin.apply(state)

    # Блокируем внешний доступ к внутренним портам (только loopback / HAProxy)
    for b in backends:
        port = b["port"]
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)

    # Запускаем/перезапускаем службу HAProxy
    subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)
    r = subprocess.run(["systemctl", "restart", SERVICE_NAME], capture_output=True)
    return r.returncode == 0

def stop() -> None:
    """Останавливает HAProxy (при переходе к 0-1 бэкенду)."""
    if is_installed():
        subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        subprocess.run(["systemctl", "disable", SERVICE_NAME], capture_output=True)
    for port in _INTERNAL_PORTS.values():
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
