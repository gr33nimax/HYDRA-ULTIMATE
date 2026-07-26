"""Transactional plugin lifecycle use-cases."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable

from hydra.core.apply_transaction import ApplyTransaction
from hydra.core.state_models import AppState, PluginState
from hydra.core.transaction_helpers import state_transaction
from hydra.plugins.invoker import PluginInvoker
from hydra.services.configuration import restore_state_in_place


@dataclass(frozen=True)
class PluginLifecycleOperations:
    """Coordinate plugin hooks, persisted state and configuration apply."""

    get_plugin: Callable[[str], Any | None]
    get_protocol: Callable[[AppState, str], PluginState]
    lifecycle_result: Callable[..., Any]
    apply_config: Callable[[AppState], bool]
    save_state: Callable[[AppState], None]
    last_apply_error: Callable[[], str]
    set_apply_error: Callable[[str], None]
    log_rollback_error: Callable[[str], None]
    invoker: PluginInvoker
    prepare_enable: Callable[[AppState, str], None] = lambda state, name: None

    def install(self, state: AppState, name: str) -> bool:
        plugin = self.get_plugin(name)
        if not plugin:
            return False
        snapshot = copy.deepcopy(state)
        transaction = self._new_transaction(state, snapshot)
        try:
            installed = self.lifecycle_result(plugin, "install")
        except Exception:
            transaction.rollback(self.log_rollback_error)
            raise
        if not installed:
            transaction.rollback(self.log_rollback_error)
            return False

        if not self.get_protocol(snapshot, name).installed:
            transaction.add_rollback(
                f"plugin {name}.uninstall",
                lambda: self._require_success(
                    self.lifecycle_result(plugin, "uninstall"),
                    f"Plugin {name} cleanup failed",
                ),
                priority=10,
            )
        protocol = self.get_protocol(state, name)
        try:
            protocol.installed = True
            self.save_state(state)
            if protocol.enabled and not self.apply_config(state):
                self._rollback_after_apply_failure(transaction)
                return False
        except Exception:
            transaction.rollback(self.log_rollback_error)
            raise
        transaction.commit()
        return True

    def uninstall(self, state: AppState, name: str) -> bool:
        plugin = self.get_plugin(name)
        if not plugin:
            return False
        snapshot = copy.deepcopy(state)
        protocol = self.get_protocol(state, name)
        was_installed = protocol.installed
        was_enabled = protocol.enabled
        transaction = self._new_transaction(state, snapshot)
        if was_enabled:
            try:
                self.lifecycle_result(plugin, "disable", state)
            except Exception:
                transaction.rollback(self.log_rollback_error)
                raise
            transaction.add_rollback(
                f"plugin {name}.on_enable",
                lambda: self.lifecycle_result(plugin, "enable", state),
                priority=10,
            )
        if was_installed:
            transaction.add_rollback(
                f"plugin {name}.install",
                lambda: self._require_success(
                    self.lifecycle_result(plugin, "install"),
                    f"Plugin {name} reinstall failed",
                ),
                priority=5,
            )
        try:
            uninstalled = self.lifecycle_result(plugin, "uninstall")
        except Exception:
            transaction.rollback(self.log_rollback_error)
            raise
        if not uninstalled:
            transaction.rollback(self.log_rollback_error)
            return False
        try:
            protocol = self.get_protocol(state, name)
            protocol.installed = False
            protocol.enabled = False
            protocol.config = {}
            protocol.port = 0
            self.save_state(state)
            applied = self.apply_config(state)
        except Exception:
            transaction.rollback(self.log_rollback_error)
            raise
        if not applied:
            self._rollback_after_apply_failure(transaction)
            return False
        transaction.commit()
        return True

    def reinstall(self, state: AppState, name: str) -> bool:
        """Repair a plugin while retaining the user's configuration."""
        plugin = self.get_plugin(name)
        if not plugin:
            return False
        snapshot = copy.deepcopy(state)
        protocol = self.get_protocol(state, name)
        saved_config = copy.deepcopy(protocol.config)
        saved_port = protocol.port
        was_enabled = protocol.enabled

        if not self.uninstall(state, name):
            return False

        transaction = self._new_transaction(state, snapshot)
        transaction.add_rollback(
            f"plugin {name}.install",
            lambda: self._restore_plugin_install(state, name, plugin),
            priority=5,
        )
        if was_enabled:
            transaction.add_rollback(
                f"plugin {name}.on_enable",
                lambda: self.lifecycle_result(plugin, "enable", state),
                priority=10,
            )

        try:
            protocol = self.get_protocol(state, name)
            protocol.config = saved_config
            protocol.port = saved_port
            self.save_state(state)

            if not self.install(state, name):
                transaction.rollback(self.log_rollback_error)
                return False
            if was_enabled and not self.enable(state, name):
                transaction.rollback(self.log_rollback_error)
                return False
        except Exception:
            transaction.rollback(self.log_rollback_error)
            raise
        transaction.commit()
        return True

    def enable(self, state: AppState, name: str) -> bool:
        plugin = self.get_plugin(name)
        if not plugin:
            return False
        snapshot = copy.deepcopy(state)
        transaction = self._new_transaction(state, snapshot)
        transaction.add_rollback(
            f"plugin {name}.on_disable",
            lambda: self.lifecycle_result(plugin, "disable", state),
            priority=10,
        )
        try:
            self.prepare_enable(state, name)
            self.lifecycle_result(plugin, "enable", state)
            protocol = self.get_protocol(state, name)
            protocol.enabled = True
            self.save_state(state)

            for user in state.users:
                if not user.blocked:
                    self.invoker.user_add(plugin, user, state)
            self.save_state(state)
            applied = self.apply_config(state)
        except Exception:
            transaction.rollback(self.log_rollback_error)
            raise

        if not applied:
            self._rollback_after_apply_failure(transaction)
        else:
            transaction.commit()
        return applied

    def disable(self, state: AppState, name: str) -> bool:
        plugin = self.get_plugin(name)
        if not plugin:
            return False
        snapshot = copy.deepcopy(state)
        transaction = self._new_transaction(state, snapshot)
        try:
            self.lifecycle_result(plugin, "disable", state)
        except Exception:
            transaction.rollback(self.log_rollback_error)
            raise
        transaction.add_rollback(
            f"plugin {name}.on_enable",
            lambda: self.lifecycle_result(plugin, "enable", state),
            priority=10,
        )
        try:
            protocol = self.get_protocol(state, name)
            protocol.enabled = False
            self.save_state(state)
            applied = self.apply_config(state)
        except Exception:
            transaction.rollback(self.log_rollback_error)
            raise
        if not applied:
            self._rollback_after_apply_failure(transaction)
        else:
            transaction.commit()
        return applied

    def _new_transaction(
        self,
        state: AppState,
        snapshot: AppState,
    ) -> ApplyTransaction:
        return state_transaction(
            lambda: self._restore_and_save(state, snapshot),
            lambda: self._reapply_restored_state(state),
        )

    def _restore_and_save(self, state: AppState, snapshot: AppState) -> None:
        restore_state_in_place(state, snapshot)
        self.save_state(state)

    def _reapply_restored_state(self, state: AppState) -> None:
        if not self.apply_config(state):
            detail = self.last_apply_error() or "restored configuration apply failed"
            raise RuntimeError(detail)

    def _rollback_after_apply_failure(self, transaction: ApplyTransaction) -> None:
        failure = self.last_apply_error()
        transaction.rollback(self.log_rollback_error)
        self.set_apply_error(failure)

    def _restore_plugin_install(self, state: AppState, name: str, plugin: Any) -> None:
        if self.get_protocol(state, name).installed:
            return
        self._require_success(
            self.lifecycle_result(plugin, "install"),
            f"Plugin {name} repair install failed",
        )

    @staticmethod
    def _require_success(result: bool, message: str) -> None:
        if not result:
            raise RuntimeError(message)
