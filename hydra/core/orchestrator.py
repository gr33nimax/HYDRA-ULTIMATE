"""hydra/core/orchestrator.py — единая точка применения конфигурации."""
from __future__ import annotations

import subprocess
from hydra.core.state import AppState, User, save_state, get_protocol, find_user
from hydra.core import singbox, nft
from hydra.plugins import registry


def apply_config(state: AppState) -> bool:
    # Принудительно включаем TPROXY — необходим для AWG и других транспортов
    if not state.network.tproxy_enabled:
        state.network.tproxy_enabled = True
        save_state(state)

    fragments = registry.collect_fragments(state)
    cfg = singbox.generate_config(state, fragments)
    if not singbox.write_config(cfg):
        return False
    try:
        nft.apply_tproxy(fragments, state.network.tproxy_port)
    except Exception:
        pass

    from hydra.core.sni_router import needs_mux, stop as stop_mux, rebuild as rebuild_mux, uninstall_haproxy
    import socket
    import time
    import subprocess

    # Onetime HAProxy migration
    _maybe_migrate_haproxy(state)

    mux_active = needs_mux(state)

    # Если мультиплексор не нужен, гасим caddy-l4 ДО перезапуска sing-box, чтобы освободить порт 443
    if not mux_active:
        stop_mux()
        for _ in range(10):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', 443)) != 0:
                    break
            time.sleep(0.3)

    res = singbox.reload()

    # Если мультиплексор нужен, ждем пока sing-box освободит порт 443, и только тогда запускаем caddy-l4
    if mux_active:
        for _ in range(10):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', 443)) != 0:
                    break
            time.sleep(0.3)
        rebuild_mux(state)

    try:
        naive_proto = state.protocols.get("naive")
        if naive_proto and naive_proto.enabled:
            p_naive = registry.get("naive")
            if p_naive:
                p_naive.configure(state)
                p_naive.apply(state)
            r = subprocess.run(["systemctl", "cat", "caddy-naive"], capture_output=True)
            if r.returncode == 0:
                subprocess.run(["systemctl", "reset-failed", "caddy-naive"], capture_output=True)
                subprocess.run(["systemctl", "restart", "caddy-naive"], capture_output=True)
    except Exception:
        pass

    # Управляем traffic daemon
    try:
        _manage_traffic_daemon(state)
    except Exception:
        pass

    return res


def _maybe_migrate_haproxy(state: AppState) -> None:
    """Performs a one-time migration from HAProxy to Caddy L4 if HAProxy was enabled."""
    from hydra.core.sni_router import uninstall_haproxy
    import shutil
    marker = state.install.get("caddy_l4_migrated", False)
    if marker:
        return

    if shutil.which("systemctl"):
        try:
            # Check if HAProxy service is enabled
            r = subprocess.run(["systemctl", "is-enabled", "haproxy"], capture_output=True, text=True)
            if r.stdout.strip() == "enabled":
                print("  Migration: stopping and disabling HAProxy...")
                uninstall_haproxy()
        except Exception:
            pass

    state.install["caddy_l4_migrated"] = True
    save_state(state)


def _manage_traffic_daemon(state: AppState) -> None:
    import subprocess
    from pathlib import Path
    
    service_file = Path("/etc/systemd/system/hydra-traffic-daemon.service")
    enabled = getattr(state.network, "clash_api_enabled", False)
    
    if enabled:
        project_root = Path(__file__).resolve().parent.parent.parent
        unit = f"""[Unit]
Description=HYDRA User Traffic Accounting Daemon
After=sing-box.service
Wants=sing-box.service

[Service]
Type=simple
User=root
WorkingDirectory={project_root}
Environment=PYTHONPATH={project_root}
ExecStart=/usr/bin/python3 -m hydra.services.traffic_daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        try:
            if not service_file.exists() or service_file.read_text() != unit:
                service_file.write_text(unit)
                subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
                subprocess.run(["systemctl", "enable", "hydra-traffic-daemon"], capture_output=True)
            
            # Restart to make sure the new environment/working directory takes effect
            subprocess.run(["systemctl", "restart", "hydra-traffic-daemon"], capture_output=True)
        except Exception:
            pass
    else:
        try:
            subprocess.run(["systemctl", "stop", "hydra-traffic-daemon"], capture_output=True)
            subprocess.run(["systemctl", "disable", "hydra-traffic-daemon"], capture_output=True)
            if service_file.exists():
                service_file.unlink()
                subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        except Exception:
            pass



def install_plugin(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    ok = p.install()
    proto = get_protocol(state, name)
    proto.installed = ok
    save_state(state)
    apply_config(state)
    return ok


def uninstall_plugin(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    proto = get_protocol(state, name)
    if proto and proto.enabled:
        try:
            p.on_disable(state)
        except Exception:
            pass
    ok = p.uninstall()
    proto = get_protocol(state, name)
    proto.installed = False
    proto.enabled = False
    proto.config = {}
    proto.port = 0
    save_state(state)
    apply_config(state)
    return ok


def enable(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    p.on_enable(state)
    proto = get_protocol(state, name)
    proto.enabled = True
    if name == "fail2ban":
        state.security.fail2ban_enabled = True
    elif name == "honeypot":
        state.security.honeypot_enabled = True
    elif name == "ipban":
        state.security.ipban_enabled = True
    save_state(state)

    # Генерируем конфиги для всех существующих пользователей
    for user in state.users:
        if not user.blocked:
            try:
                p.on_user_add(user, state)
            except Exception:
                pass

    return apply_config(state)


def disable(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    p.on_disable(state)
    proto = get_protocol(state, name)
    proto.enabled = False
    if name == "fail2ban":
        state.security.fail2ban_enabled = False
    elif name == "honeypot":
        state.security.honeypot_enabled = False
    elif name == "ipban":
        state.security.ipban_enabled = False
    save_state(state)
    return apply_config(state)


def add_user(state: AppState, user: User) -> None:
    from hydra.core.state import add_user as _add
    _add(state, user)
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_add(user, state)
            except Exception:
                pass
    save_state(state)
    apply_config(state)

    # Перезапуск сервера подписок, если он активен
    from hydra.core.systemd import is_active as is_svc_active, restart as restart_svc
    if is_svc_active("hydra-sub"):
        restart_svc("hydra-sub")


def remove_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u:
        return
    state.users = [x for x in state.users if x.email != email]
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_remove(u, state)
            except Exception:
                pass
    save_state(state)
    apply_config(state)

    # Перезапуск сервера подписок, если он активен
    from hydra.core.systemd import is_active as is_svc_active, restart as restart_svc
    if is_svc_active("hydra-sub"):
        restart_svc("hydra-sub")


def block_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u:
        return
    u.blocked = True
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_block(u, state)
            except Exception:
                pass
    save_state(state)
    apply_config(state)


def unblock_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u:
        return
    u.blocked = False
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_add(u, state)
            except Exception:
                pass
    save_state(state)
    apply_config(state)


def sync_user_configs(state: AppState, plugin_name: str | None = None) -> None:
    """Пересоздаёт конфиги для всех пользователей на указанном или всех протоколах."""
    targets = [registry.get(plugin_name)] if plugin_name else registry.transports()
    for p in targets:
        if p is None:
            continue
        ps = state.protocols.get(p.meta.name)
        if not ps or not ps.enabled:
            continue
        try:
            p.configure(state)
            p.apply(state)
        except Exception:
            pass
    save_state(state)
