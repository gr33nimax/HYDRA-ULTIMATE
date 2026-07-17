"""hydra/core/orchestrator.py — единая точка применения конфигурации."""
from __future__ import annotations

import copy
import subprocess
from hydra.core.state import AppState, User, save_state, get_protocol, find_user
from hydra.core import singbox, nft
from hydra.plugins import registry


def apply_config(state: AppState) -> bool:
    # Принудительно включаем TPROXY — необходим для AWG и других транспортов
    if not state.network.tproxy_enabled:
        state.network.tproxy_enabled = True
        save_state(state)

    try:
        fragments = registry.collect_fragments(state)
    except Exception as exc:
        singbox._log("ERROR", str(exc))
        return False
    cfg = singbox.generate_config(state, fragments)
    previous_config = None
    if singbox.SINGBOX_CONFIG.exists():
        try:
            previous_config = singbox.SINGBOX_CONFIG.read_bytes()
        except OSError:
            previous_config = None
    if not singbox.write_config(cfg):
        return False
    try:
        nft.apply_tproxy(fragments, state.network.tproxy_port)
    except Exception as exc:
        singbox._log("ERROR", f"Failed to apply plugin/network configuration: {exc}")
        _restore_singbox_config(previous_config)
        return False

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

    try:
        registry.apply_enabled(state)
    except Exception as exc:
        singbox._log("ERROR", f"Failed to apply plugin configuration: {exc}")
        _restore_singbox_config(previous_config)
        return False

    res = singbox.reload()

    # Если мультиплексор нужен, ждем пока sing-box освободит порт 443, и только тогда запускаем caddy-l4
    mux_ok = True
    if mux_active:
        for _ in range(10):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', 443)) != 0:
                    break
            time.sleep(0.3)
        mux_ok = rebuild_mux(state)

    # Управляем traffic daemon
    try:
        _manage_traffic_daemon(state)
    except Exception:
        pass

    if not res or not mux_ok:
        _restore_singbox_config(previous_config)
        try:
            singbox.reload()
        except Exception as exc:
            singbox._log("ERROR", f"Failed to reload restored sing-box config: {exc}")
        return False
    return True


def _restore_singbox_config(previous: bytes | None) -> None:
    """Restore the last known configuration after a failed apply phase."""
    try:
        if previous is None:
            singbox.SINGBOX_CONFIG.unlink(missing_ok=True)
        else:
            tmp = singbox.SINGBOX_CONFIG.with_suffix(".json.rollback")
            tmp.write_bytes(previous)
            tmp.replace(singbox.SINGBOX_CONFIG)
    except OSError as exc:
        singbox._log("ERROR", f"Failed to restore sing-box config: {exc}")


def _restore_state(target: AppState, snapshot: AppState) -> None:
    """Restore AppState in place so existing UI references remain valid."""
    for field_name in snapshot.__dataclass_fields__:
        setattr(target, field_name, copy.deepcopy(getattr(snapshot, field_name)))


def _rollback_plugin_change(state: AppState, snapshot: AppState, plugin, undo_hook: str) -> None:
    try:
        getattr(plugin, undo_hook)(state)
    except Exception as exc:
        singbox._log("ERROR", f"Plugin rollback hook {plugin.meta.name}.{undo_hook} failed: {exc}")
    _restore_state(state, snapshot)
    save_state(state)
    try:
        apply_config(state)
    except Exception as exc:
        singbox._log("ERROR", f"Configuration rollback failed: {exc}")


def _commit_state_change(state: AppState, snapshot: AppState) -> None:
    """Persist and apply a state mutation, restoring the snapshot on failure."""
    save_state(state)
    if apply_config(state):
        return
    _restore_state(state, snapshot)
    save_state(state)
    apply_config(state)
    raise RuntimeError("Configuration apply failed; state change was rolled back")


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
    if ok and proto.enabled:
        return apply_config(state)
    return ok


def uninstall_plugin(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    snapshot = copy.deepcopy(state)
    proto = get_protocol(state, name)
    if proto and proto.enabled:
        try:
            p.on_disable(state)
        except Exception:
            pass
    ok = p.uninstall()
    if not ok:
        _restore_state(state, snapshot)
        save_state(state)
        return False
    proto = get_protocol(state, name)
    proto.installed = False
    proto.enabled = False
    proto.config = {}
    proto.port = 0
    save_state(state)
    return apply_config(state)


def enable(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    snapshot = copy.deepcopy(state)
    try:
        p.on_enable(state)
        proto = get_protocol(state, name)
        proto.enabled = True
    except Exception:
        _rollback_plugin_change(state, snapshot, p, "on_disable")
        raise
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
                _rollback_plugin_change(state, snapshot, p, "on_disable")
                raise

    try:
        applied = apply_config(state)
    except Exception:
        _rollback_plugin_change(state, snapshot, p, "on_disable")
        raise

    if not applied:
        _rollback_plugin_change(state, snapshot, p, "on_disable")
    return applied


def disable(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    snapshot = copy.deepcopy(state)
    try:
        p.on_disable(state)
    except Exception:
        _restore_state(state, snapshot)
        save_state(state)
        raise
    proto = get_protocol(state, name)
    proto.enabled = False
    if name == "fail2ban":
        state.security.fail2ban_enabled = False
    elif name == "honeypot":
        state.security.honeypot_enabled = False
    elif name == "ipban":
        state.security.ipban_enabled = False
    save_state(state)
    try:
        applied = apply_config(state)
    except Exception:
        _rollback_plugin_change(state, snapshot, p, "on_enable")
        raise
    if not applied:
        _rollback_plugin_change(state, snapshot, p, "on_enable")
    return applied


def add_user(state: AppState, user: User) -> None:
    from hydra.core.state import add_user as _add
    snapshot = copy.deepcopy(state)
    _add(state, user)
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_add(user, state)
            except Exception:
                _restore_state(state, snapshot)
                save_state(state)
                raise
    _commit_state_change(state, snapshot)

    # Перезапуск сервера подписок, если он активен
    from hydra.core.systemd import is_active as is_svc_active, restart as restart_svc
    if is_svc_active("hydra-sub"):
        restart_svc("hydra-sub")


def remove_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u:
        return
    snapshot = copy.deepcopy(state)
    state.users = [x for x in state.users if x.email != email]
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_remove(u, state)
            except Exception:
                _restore_state(state, snapshot)
                save_state(state)
                raise
    _commit_state_change(state, snapshot)

    # Перезапуск сервера подписок, если он активен
    from hydra.core.systemd import is_active as is_svc_active, restart as restart_svc
    if is_svc_active("hydra-sub"):
        restart_svc("hydra-sub")


def block_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u:
        return
    snapshot = copy.deepcopy(state)
    u.blocked = True
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_block(u, state)
            except Exception:
                _restore_state(state, snapshot)
                save_state(state)
                raise
    _commit_state_change(state, snapshot)


def unblock_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u:
        return
    snapshot = copy.deepcopy(state)
    u.blocked = False
    for p in registry.transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try:
                p.on_user_add(u, state)
            except Exception:
                _restore_state(state, snapshot)
                save_state(state)
                raise
    _commit_state_change(state, snapshot)


def sync_user_configs(state: AppState, plugin_name: str | None = None) -> None:
    """Пересоздаёт конфиги для всех пользователей на указанном или всех протоколах."""
    targets = [registry.get(plugin_name)] if plugin_name else registry.transports()
    for p in targets:
        if p is None:
            continue
        ps = state.protocols.get(p.meta.name)
        if not ps or not ps.enabled:
            continue
        p.configure(state)
        if not p.apply(state):
            raise RuntimeError(f"Plugin {p.meta.name} apply returned false")
    save_state(state)
