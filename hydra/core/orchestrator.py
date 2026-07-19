"""hydra/core/orchestrator.py — единая точка применения конфигурации."""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from hydra.core.state import AppState, User, save_state, get_protocol, find_user
from hydra.core import singbox, nft
from hydra.core.host import HOST
from hydra.core.apply_transaction import ApplyTransaction
from hydra.plugins import registry


TRAFFIC_DAEMON_SERVICE = Path("/etc/systemd/system/hydra-traffic-daemon.service")
APPLY_JOURNAL = Path("/var/log/hydra/apply.jsonl")
APPLY_LOCK_FILE = Path(os.environ.get("HYDRA_APPLY_LOCK_FILE", "/run/lock/hydra-apply.lock"))
_last_apply_error = ""
_apply_lock = threading.Lock()


def last_apply_error() -> str:
    return _last_apply_error


def _set_apply_error(message: str) -> None:
    global _last_apply_error
    _last_apply_error = message


@contextmanager
def _process_apply_guard():
    """Acquire an inter-process apply lock in addition to the thread lock."""
    if os.name == "nt" or getattr(os, "geteuid", lambda: 1)() != 0:
        yield True
        return
    try:
        import fcntl
        APPLY_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        with APPLY_LOCK_FILE.open("a+") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                handle.seek(0)
                handle.truncate()
                handle.write(str(os.getpid()))
                handle.flush()
                yield True
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except (BlockingIOError, OSError):
        yield False


def _journal(event: str, **fields) -> None:
    """Append a compact apply event without making logging a failure source."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    try:
        APPLY_JOURNAL.parent.mkdir(parents=True, exist_ok=True)
        with APPLY_JOURNAL.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        if hasattr(APPLY_JOURNAL, "chmod"):
            APPLY_JOURNAL.chmod(0o600)
    except OSError:
        pass


def apply_config(state: AppState) -> bool:
    """Apply one configuration transaction at a time."""
    if not _apply_lock.acquire(blocking=False):
        _set_apply_error("Применение конфигурации уже выполняется")
        _journal("rejected", reason="already_running")
        return False
    try:
        with _process_apply_guard() as acquired:
            if not acquired:
                _set_apply_error("Применение конфигурации уже выполняется в другом процессе")
                _journal("rejected", reason="already_running_process")
                return False
            state_snapshot = copy.deepcopy(state)
            try:
                applied = _apply_config_unlocked(state)
            except Exception as exc:
                _set_apply_error(f"Неожиданная ошибка применения: {exc}")
                singbox._log("ERROR", last_apply_error())
                _journal("failed", stage="unexpected", error=last_apply_error())
                applied = False
            if not applied:
                _restore_state(state, state_snapshot)
                try:
                    save_state(state)
                except Exception as exc:
                    singbox._log("ERROR", f"Не удалось восстановить состояние после сбоя: {exc}")
            return applied
    finally:
        _apply_lock.release()


def _apply_config_unlocked(state: AppState) -> bool:
    _set_apply_error("")
    _journal("started")
    transaction = ApplyTransaction()

    def fail(stage: str, message: str, *, reload_restored: bool = False) -> bool:
        _set_apply_error(message)
        singbox._log("ERROR", message)
        transaction.rollback(lambda error: singbox._log("ERROR", error))
        _journal("rolled_back", stage=stage, error=message)
        if reload_restored:
            try:
                singbox.reload()
            except Exception as exc:
                singbox._log("ERROR", f"Не удалось перезагрузить восстановленный Sing-Box: {exc}")
        return False

    # Принудительно включаем TPROXY — необходим для AWG и других транспортов
    if not state.network.tproxy_enabled:
        state.network.tproxy_enabled = True
        save_state(state)

    try:
        fragments = registry.collect_fragments(state)
        _journal("fragments_collected", plugins=list(fragments))
    except Exception as exc:
        _set_apply_error(str(exc))
        singbox._log("ERROR", str(exc))
        _journal("failed", stage="collect_fragments", error=str(exc))
        return False
    cfg = singbox.generate_config(state, fragments)
    transaction.advance("snapshot")
    previous_config = None
    if singbox.SINGBOX_CONFIG.exists():
        try:
            previous_config = singbox.SINGBOX_CONFIG.read_bytes()
        except OSError:
            previous_config = None
    if not singbox.write_config(cfg):
        _set_apply_error(singbox.last_error() or "Не удалось записать конфигурацию Sing-Box")
        _journal("failed", stage="singbox_config", error=last_apply_error())
        return False
    transaction.add_rollback(
        "sing-box config",
        lambda: _restore_singbox_config(previous_config),
        priority=10,
    )
    nft_snapshot = nft.snapshot_tproxy()
    transaction.add_rollback(
        "nftables",
        lambda: _restore_nft_snapshot(nft_snapshot),
        priority=20,
    )
    transaction.advance("apply")
    try:
        nft.apply_tproxy(fragments, state.network.tproxy_port)
        _journal("nft_applied")
    except Exception as exc:
        message = f"Не удалось применить сетевую конфигурацию: {exc}"
        return fail("nft", message)

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
        applied_plugins = registry.apply_enabled(state)
        _journal("plugins_applied", plugins=[p.meta.name for p in registry.enabled(state)])
    except Exception as exc:
        message = f"Не удалось применить конфигурацию плагина: {exc}"
        return fail("plugins", message)

    plugin_count = len(applied_plugins)
    for index, (plugin, snapshot) in enumerate(applied_plugins):
        transaction.add_rollback(
            f"plugin {plugin.meta.name}",
            lambda plugin=plugin, snapshot=snapshot: plugin.rollback(state, snapshot),
            priority=30 + plugin_count - index,
        )

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
    except Exception as exc:
        message = f"Не удалось применить сервис учёта трафика: {exc}"
        return fail("traffic_daemon", message, reload_restored=True)

    transaction.advance("healthcheck")
    plugin_health = registry.health_all(state)
    if plugin_health:
        details = "; ".join(f"{name}: {reason}" for name, reason in plugin_health.items())
        return fail(
            "plugin_health",
            f"Проверка сервисов не пройдена: {details}",
            reload_restored=True,
        )

    if not res or not mux_ok:
        if not res:
            _set_apply_error(singbox.last_error() or "Sing-Box не запустился после применения")
        else:
            _set_apply_error("SNI-маршрутизатор не запустился после применения")
        return fail("healthcheck", last_apply_error(), reload_restored=True)
    transaction.commit()
    _journal("committed")
    return True


def _restore_nft_snapshot(snapshot: nft.TproxySnapshot) -> None:
    try:
        nft.restore_tproxy(snapshot)
    except Exception as exc:
        singbox._log("ERROR", f"Не удалось восстановить правила nftables HYDRA: {exc}")


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
            r = HOST.run(["systemctl", "is-enabled", "haproxy"], text=True)
            if r.stdout.strip() == "enabled":
                print("  Migration: stopping and disabling HAProxy...")
                uninstall_haproxy()
        except Exception:
            pass

    state.install["caddy_l4_migrated"] = True
    save_state(state)


def _manage_traffic_daemon(state: AppState) -> None:
    service_file = TRAFFIC_DAEMON_SERVICE
    enabled = getattr(state.network, "clash_api_enabled", False)

    if not enabled and not service_file.exists():
        return
    if os.name != "nt" and shutil.which("systemctl") is None:
        raise RuntimeError("systemctl is unavailable")

    def systemctl(*args: str, allow_inactive: bool = False) -> subprocess.CompletedProcess:
        try:
            result = HOST.run(["systemctl", *args], text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"systemctl {' '.join(args)} failed: {exc}") from exc
        if result.returncode != 0 and not allow_inactive:
            raise RuntimeError(
                f"systemctl {' '.join(args)} failed: "
                f"{(result.stderr or result.stdout or 'unknown error').strip()}"
            )
        return result

    if enabled:
        import hashlib

        project_root = Path(__file__).resolve().parent.parent.parent
        daemon_source = project_root / "hydra" / "services" / "traffic_daemon.py"
        try:
            daemon_revision = hashlib.sha256(daemon_source.read_bytes()).hexdigest()[:12]
        except OSError:
            daemon_revision = "unknown"
        unit = f"""[Unit]
Description=HYDRA User Traffic Accounting Daemon
After=sing-box.service
Wants=sing-box.service

[Service]
Type=simple
User=root
WorkingDirectory={project_root}
Environment=PYTHONPATH={project_root}
Environment=HYDRA_TRAFFIC_DAEMON_REV={daemon_revision}
ExecStart=/usr/bin/python3 -m hydra.services.traffic_daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        unit_changed = not service_file.exists() or service_file.read_text(encoding="utf-8") != unit
        if unit_changed:
            service_file.parent.mkdir(parents=True, exist_ok=True)
            pending = service_file.with_suffix(".service.pending")
            pending.write_text(unit, encoding="utf-8")
            pending.chmod(0o644)
            pending.replace(service_file)
            systemctl("daemon-reload")
        systemctl("enable", "hydra-traffic-daemon")
        active = systemctl(
            "is-active", "--quiet", "hydra-traffic-daemon", allow_inactive=True,
        ).returncode == 0
        if unit_changed:
            systemctl("restart", "hydra-traffic-daemon")
        elif not active:
            systemctl("start", "hydra-traffic-daemon")
    else:
        systemctl("stop", "hydra-traffic-daemon", allow_inactive=True)
        systemctl("disable", "hydra-traffic-daemon", allow_inactive=True)
        service_file.unlink(missing_ok=True)
        systemctl("daemon-reload")


def reconcile_traffic_daemon(state: AppState) -> None:
    """Reconcile the daemon after a code update without rebuilding networking."""
    _manage_traffic_daemon(state)



def install_plugin(state: AppState, name: str) -> bool:
    p = registry.get(name)
    if not p:
        return False
    snapshot = copy.deepcopy(state)
    try:
        ok = p.install()
    except Exception:
        _restore_state(state, snapshot)
        save_state(state)
        raise
    proto = get_protocol(state, name)
    proto.installed = ok
    save_state(state)
    if ok and proto.enabled:
        try:
            applied = apply_config(state)
        except Exception:
            _restore_state(state, snapshot)
            save_state(state)
            raise
        if not applied:
            _restore_state(state, snapshot)
            save_state(state)
            apply_config(state)
        return applied
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


def reinstall_plugin(state: AppState, name: str) -> bool:
    """Reinstall a plugin without turning "reinstall" into a settings reset.

    Full uninstall intentionally clears the protocol configuration.  A TUI
    reinstall, however, is a repair operation and must retain user choices.
    """
    proto = get_protocol(state, name)
    saved_config = copy.deepcopy(proto.config)
    saved_port = proto.port
    was_enabled = proto.enabled

    if not uninstall_plugin(state, name):
        return False

    proto = get_protocol(state, name)
    proto.config = saved_config
    proto.port = saved_port
    save_state(state)

    if not install_plugin(state, name):
        return False
    if was_enabled:
        return enable(state, name)
    return True


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
    # on_user_add hooks populate protocol credentials for users that predate
    # the plugin. Persist them before applying services and subscriptions.
    save_state(state)

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
