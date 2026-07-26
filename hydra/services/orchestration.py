"""Legacy function facade for orchestration compatibility.

New production code receives an instance-scoped ``OrchestrationService`` from
the application composition root.  These functions retain historical imports
and monkeypatch seams while third-party callers migrate.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from hydra.core.state import save_state
from hydra.core.state_models import AppState, User, get_protocol
from hydra.core import singbox, nft
from hydra.core.host import HOST
from hydra.plugins import registry
from hydra.plugins.invoker import PluginInvoker
from hydra.services.configuration import (
    ConfigurationApplier,
    migrate_haproxy,
    restore_state_in_place,
)
from hydra.services.certificates import CertificateProvisioner
from hydra.services.plugin_lifecycle import PluginLifecycleOperations
from hydra.services.protocol_setup import ProtocolSetupService
from hydra.services.traffic_daemon_unit import TrafficDaemonUnitManager
from hydra.services.user_lifecycle import UserLifecycleOperations


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
                singbox.log("ERROR", last_apply_error())
                _journal("failed", stage="unexpected", error=last_apply_error())
                applied = False
            if not applied:
                _restore_state(state, state_snapshot)
                try:
                    save_state(state)
                except Exception as exc:
                    singbox.log("ERROR", f"Не удалось восстановить состояние после сбоя: {exc}")
            return applied
    finally:
        _apply_lock.release()


def _apply_config_unlocked(state: AppState) -> bool:
    return _configuration_applier().apply(state)


def _configuration_applier() -> ConfigurationApplier:
    """Build the pipeline from the facade's current, patchable dependencies."""
    return ConfigurationApplier(
        registry=registry,
        singbox=singbox,
        nft=nft,
        save_state=save_state,
        set_apply_error=_set_apply_error,
        last_apply_error=last_apply_error,
        journal=_journal,
        manage_traffic_daemon=_manage_traffic_daemon,
        migrate_haproxy=_maybe_migrate_haproxy,
    )


def _restore_state(target: AppState, snapshot: AppState) -> None:
    restore_state_in_place(target, snapshot)


def _log_rollback_error(message: str) -> None:
    singbox.log("ERROR", message)


def _user_lifecycle() -> UserLifecycleOperations:
    """Build operations from the facade's current, patchable dependencies."""
    return UserLifecycleOperations(
        transports=registry.transports,
        apply_config=apply_config,
        save_state=save_state,
        last_apply_error=last_apply_error,
        log_rollback_error=_log_rollback_error,
        invoker=PluginInvoker(),
    )


def _plugin_lifecycle() -> PluginLifecycleOperations:
    """Build operations from the facade's current, patchable dependencies."""
    return PluginLifecycleOperations(
        get_plugin=registry.get,
        get_protocol=get_protocol,
        lifecycle_result=PluginInvoker().lifecycle,
        apply_config=apply_config,
        save_state=save_state,
        last_apply_error=last_apply_error,
        set_apply_error=_set_apply_error,
        log_rollback_error=_log_rollback_error,
        invoker=PluginInvoker(),
        prepare_enable=_prepare_enable,
    )


def _prepare_enable(state: AppState, name: str) -> None:
    """Patchable compatibility seam for production enable preparation."""
    ProtocolSetupService(
        CertificateProvisioner(HOST),
        registry.get,
    ).prepare_enable(state, name)


def _maybe_migrate_haproxy(state: AppState) -> None:
    migrate_haproxy(state, host=HOST, save_state=save_state)


def _manage_traffic_daemon(state: AppState) -> None:
    TrafficDaemonUnitManager(
        service_file=TRAFFIC_DAEMON_SERVICE,
        host=HOST,
    ).reconcile(state)


def reconcile_traffic_daemon(state: AppState) -> None:
    """Reconcile the daemon after a code update without rebuilding networking."""
    _manage_traffic_daemon(state)



def install_plugin(state: AppState, name: str) -> bool:
    return _plugin_lifecycle().install(state, name)


def uninstall_plugin(state: AppState, name: str) -> bool:
    return _plugin_lifecycle().uninstall(state, name)


def reinstall_plugin(state: AppState, name: str) -> bool:
    return _plugin_lifecycle().reinstall(state, name)


def enable(state: AppState, name: str) -> bool:
    return _plugin_lifecycle().enable(state, name)


def disable(state: AppState, name: str) -> bool:
    return _plugin_lifecycle().disable(state, name)


def add_user(state: AppState, user: User) -> None:
    _user_lifecycle().add(state, user)


def remove_user(state: AppState, email: str) -> None:
    _user_lifecycle().remove(state, email)


def block_user(state: AppState, email: str) -> None:
    _user_lifecycle().block(state, email)


def unblock_user(state: AppState, email: str) -> None:
    _user_lifecycle().unblock(state, email)


def rename_user(state: AppState, email: str, new_email: str) -> None:
    _user_lifecycle().rename(state, email, new_email)


def set_user_device_limit(
    state: AppState,
    email: str,
    limit: int,
    *,
    reset: bool = False,
) -> None:
    _user_lifecycle().set_device_limit(state, email, limit, reset=reset)


def sync_user_configs(state: AppState, plugin_name: str | None = None) -> None:
    """Пересоздаёт конфиги для всех пользователей на указанном или всех протоколах."""
    invoker = PluginInvoker()
    targets = [registry.get(plugin_name)] if plugin_name else registry.transports()
    for p in targets:
        if p is None:
            continue
        ps = state.protocols.get(p.meta.name)
        if not ps or not ps.enabled:
            continue
        invoker.configure(p, state)
        if not invoker.apply(p, state):
            raise RuntimeError(f"Plugin {p.meta.name} apply returned false")
    save_state(state)
