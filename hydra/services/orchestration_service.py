"""Instance-scoped application orchestration.

Unlike the legacy module facade, every dependency (including the plugin
collection) belongs to one composition root.  This makes multiple independent
application instances and third-party plugin sets safe in the same process.
"""
from __future__ import annotations

import copy
import json
import os
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from hydra.core.state_models import AppState, User
from hydra.plugins.invoker import PluginInvoker
from hydra.services.configuration import (
    ConfigurationApplier,
    migrate_haproxy,
    restore_state_in_place,
)
from hydra.services.plugin_lifecycle import PluginLifecycleOperations
from hydra.services.protocol_setup import (
    CertificateProvider,
    ProtocolSetupService,
)
from hydra.services.traffic_daemon_unit import TrafficDaemonUnitManager
from hydra.services.user_lifecycle import UserLifecycleOperations


GetProtocol = Callable[[AppState, str], Any]
SaveState = Callable[[AppState], None]


@dataclass
class OrchestrationService:
    """Transactional lifecycle and configuration operations for one app."""

    plugins: Any
    singbox: Any
    nft: Any
    host: Any
    save_state: SaveState
    get_protocol: GetProtocol
    certificates: CertificateProvider
    traffic_daemon_service: Path
    apply_journal: Path
    apply_lock_file: Path
    _last_apply_error: str = field(default="", init=False)
    _apply_lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )

    def last_apply_error(self) -> str:
        return self._last_apply_error

    def _set_apply_error(self, message: str) -> None:
        self._last_apply_error = message

    @contextmanager
    def _process_apply_guard(self) -> Iterator[bool]:
        if (
            os.name == "nt"
            or getattr(os, "geteuid", lambda: 1)() != 0
        ):
            yield True
            return
        try:
            import fcntl

            self.apply_lock_file.parent.mkdir(parents=True, exist_ok=True)
            with self.apply_lock_file.open("a+") as handle:
                fcntl.flock(
                    handle.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
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

    def _journal(self, event: str, **fields: object) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        try:
            self.apply_journal.parent.mkdir(parents=True, exist_ok=True)
            with self.apply_journal.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(record, ensure_ascii=False) + "\n",
                )
            self.apply_journal.chmod(0o600)
        except OSError:
            pass

    def apply_config(self, state: AppState) -> bool:
        if not self._apply_lock.acquire(blocking=False):
            self._set_apply_error(
                "Применение конфигурации уже выполняется",
            )
            self._journal("rejected", reason="already_running")
            return False
        try:
            with self._process_apply_guard() as acquired:
                if not acquired:
                    self._set_apply_error(
                        "Применение конфигурации уже выполняется "
                        "в другом процессе",
                    )
                    self._journal(
                        "rejected",
                        reason="already_running_process",
                    )
                    return False
                snapshot = copy.deepcopy(state)
                try:
                    applied = self._configuration_applier().apply(state)
                except Exception as exc:
                    self._set_apply_error(
                        f"Неожиданная ошибка применения: {exc}",
                    )
                    self.singbox.log(
                        "ERROR",
                        self.last_apply_error(),
                    )
                    self._journal(
                        "failed",
                        stage="unexpected",
                        error=self.last_apply_error(),
                    )
                    applied = False
                if not applied:
                    restore_state_in_place(state, snapshot)
                    try:
                        self.save_state(state)
                    except Exception as exc:
                        self.singbox.log(
                            "ERROR",
                            "Не удалось восстановить состояние "
                            f"после сбоя: {exc}",
                        )
                return applied
        finally:
            self._apply_lock.release()

    def _configuration_applier(self) -> ConfigurationApplier:
        return ConfigurationApplier(
            registry=self.plugins,
            singbox=self.singbox,
            nft=self.nft,
            save_state=self.save_state,
            set_apply_error=self._set_apply_error,
            last_apply_error=self.last_apply_error,
            journal=self._journal,
            manage_traffic_daemon=self._manage_traffic_daemon,
            migrate_haproxy=self._migrate_haproxy,
            prepare_state=ProtocolSetupService(
                self.certificates,
                self.plugins.get,
            ).prepare_enabled,
        )

    def _migrate_haproxy(self, state: AppState) -> None:
        migrate_haproxy(
            state,
            host=self.host,
            save_state=self.save_state,
        )

    def _manage_traffic_daemon(self, state: AppState) -> None:
        TrafficDaemonUnitManager(
            service_file=self.traffic_daemon_service,
            host=self.host,
        ).reconcile(state)

    def reconcile_traffic_daemon(self, state: AppState) -> None:
        self._manage_traffic_daemon(state)

    def _log_rollback_error(self, message: str) -> None:
        self.singbox.log("ERROR", message)

    def _prepare_enable(self, state: AppState, name: str) -> None:
        self._protocol_setup().prepare_enable(state, name)

    def _protocol_setup(self) -> ProtocolSetupService:
        return ProtocolSetupService(
            self.certificates,
            self.plugins.get,
        )

    def _plugin_lifecycle(self) -> PluginLifecycleOperations:
        invoker = PluginInvoker()
        return PluginLifecycleOperations(
            get_plugin=self.plugins.get,
            get_protocol=self.get_protocol,
            lifecycle_result=invoker.lifecycle,
            apply_config=self.apply_config,
            save_state=self.save_state,
            last_apply_error=self.last_apply_error,
            set_apply_error=self._set_apply_error,
            log_rollback_error=self._log_rollback_error,
            invoker=invoker,
            prepare_enable=self._prepare_enable,
        )

    def _user_lifecycle(self) -> UserLifecycleOperations:
        return UserLifecycleOperations(
            transports=self.plugins.transports,
            apply_config=self.apply_config,
            save_state=self.save_state,
            last_apply_error=self.last_apply_error,
            log_rollback_error=self._log_rollback_error,
            invoker=PluginInvoker(),
        )

    def install_plugin(self, state: AppState, name: str) -> bool:
        return self._plugin_lifecycle().install(state, name)

    def uninstall_plugin(self, state: AppState, name: str) -> bool:
        return self._plugin_lifecycle().uninstall(state, name)

    def reinstall_plugin(self, state: AppState, name: str) -> bool:
        return self._plugin_lifecycle().reinstall(state, name)

    def activate_plugin(
        self,
        state: AppState,
        name: str,
        *,
        domain: str | None = None,
    ) -> bool:
        """Install and enable a protocol while committing input atomically."""
        snapshot = copy.deepcopy(state)
        lifecycle = self._plugin_lifecycle()
        was_installed = self.get_protocol(snapshot, name).installed
        try:
            if domain is not None:
                self._protocol_setup().stage_domain(state, name, domain)
            if not self.get_protocol(state, name).installed:
                if not lifecycle.install(state, name):
                    self._restore_failed_activation(
                        state,
                        snapshot,
                        name,
                        keep_installed=False,
                    )
                    return False
            if lifecycle.enable(state, name):
                return True
        except Exception:
            keep_installed = (
                not was_installed
                and self.get_protocol(state, name).installed
            )
            self._restore_failed_activation(
                state,
                snapshot,
                name,
                keep_installed=keep_installed,
            )
            raise

        keep_installed = (
            not was_installed
            and self.get_protocol(state, name).installed
        )
        self._restore_failed_activation(
            state,
            snapshot,
            name,
            keep_installed=keep_installed,
        )
        return False

    def _restore_failed_activation(
        self,
        state: AppState,
        snapshot: AppState,
        name: str,
        *,
        keep_installed: bool,
    ) -> None:
        """Restore activation input while retaining a completed install."""
        restore_state_in_place(state, snapshot)
        if keep_installed:
            protocol = self.get_protocol(state, name)
            protocol.installed = True
            protocol.enabled = False
        try:
            self.save_state(state)
        except Exception as exc:
            self._log_rollback_error(
                "Не удалось сохранить откат активации "
                f"{name}: {exc}",
            )

    def enable(self, state: AppState, name: str) -> bool:
        return self._plugin_lifecycle().enable(state, name)

    def disable(self, state: AppState, name: str) -> bool:
        return self._plugin_lifecycle().disable(state, name)

    def add_user(self, state: AppState, user: User) -> None:
        self._user_lifecycle().add(state, user)

    def remove_user(self, state: AppState, email: str) -> None:
        self._user_lifecycle().remove(state, email)

    def block_user(self, state: AppState, email: str) -> None:
        self._user_lifecycle().block(state, email)

    def unblock_user(self, state: AppState, email: str) -> None:
        self._user_lifecycle().unblock(state, email)

    def rename_user(self, state: AppState, email: str, new_email: str) -> None:
        self._user_lifecycle().rename(state, email, new_email)

    def set_user_device_limit(
        self,
        state: AppState,
        email: str,
        limit: int,
        *,
        reset: bool = False,
    ) -> None:
        self._user_lifecycle().set_device_limit(
            state,
            email,
            limit,
            reset=reset,
        )

    def rotate_user_hydrabox_key(
        self,
        state: AppState,
        email: str,
    ) -> None:
        self._user_lifecycle().rotate_hydrabox_key(state, email)

    def sync_user_configs(
        self,
        state: AppState,
        plugin_name: str | None = None,
    ) -> None:
        invoker = PluginInvoker()
        targets = (
            [self.plugins.get(plugin_name)]
            if plugin_name
            else self.plugins.transports()
        )
        for plugin in targets:
            if plugin is None:
                continue
            protocol = state.protocols.get(plugin.meta.name)
            if not protocol or not protocol.enabled:
                continue
            invoker.configure(plugin, state)
            if not invoker.apply(plugin, state):
                raise RuntimeError(
                    f"Plugin {plugin.meta.name} apply returned false",
                )
        self.save_state(state)


__all__ = ["OrchestrationService"]
