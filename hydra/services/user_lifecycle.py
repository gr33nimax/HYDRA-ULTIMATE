"""Transactional user lifecycle use-cases.

This module owns the fan-out from one user mutation to all enabled transport
plugins.  It intentionally receives infrastructure callbacks so the legacy
``hydra.core.orchestrator`` module can remain a patchable compatibility facade.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Callable, Iterable

from hydra.core.apply_transaction import ApplyTransaction
from hydra.core.hydrabox_keys import generate_hydrabox_jwe_key
from hydra.core.state_validation import supports_personal_protocol_access
from hydra.core.state_models import (
    AppState,
    User,
    add_user as append_user,
    find_user,
)
from hydra.core.transaction_helpers import state_transaction
from hydra.plugins.base import BasePlugin
from hydra.plugins.invoker import PluginInvoker
from hydra.services.configuration import restore_state_in_place


@dataclass(frozen=True)
class UserLifecycleOperations:
    """Apply user mutations atomically across state and transport plugins."""

    transports: Callable[[], Iterable[BasePlugin]]
    apply_config: Callable[[AppState], bool]
    save_state: Callable[[AppState], None]
    last_apply_error: Callable[[], str]
    log_rollback_error: Callable[[str], None]
    invoker: PluginInvoker

    def add(self, state: AppState, user: User) -> None:
        snapshot = copy.deepcopy(state)
        append_user(state, user)
        transaction = self._new_transaction(state, snapshot)
        for index, plugin in self._enabled_transports(state):
            transaction.add_rollback(
                f"user {user.email} plugin {plugin.meta.name}",
                lambda plugin=plugin: self.invoker.user_remove(
                    plugin,
                    user,
                    state,
                ),
                priority=10 - index,
            )
            try:
                self.invoker.user_add(plugin, user, state)
            except Exception:
                transaction.rollback(self.log_rollback_error)
                raise
        self._commit(state, transaction)
        self._restart_subscriptions()

    def reconcile_users(self, state: AppState, users: list[User]) -> None:
        """Replace the node-local user projection in one transactional apply."""
        by_uuid = {user.uuid: user for user in users}
        by_email = {user.email: user for user in users}
        if len(by_uuid) != len(users) or len(by_email) != len(users):
            raise ValueError("reconciled users must have unique UUIDs and identifiers")
        snapshot = copy.deepcopy(state)
        previous = {user.uuid: user for user in snapshot.users}
        state.users = users
        transaction = self._new_transaction(state, snapshot)

        for index, plugin in self._enabled_transports(state):
            name = plugin.meta.name
            was_enabled = bool(snapshot.protocols.get(name) and snapshot.protocols[name].enabled)
            if not was_enabled:
                for user in users:
                    self._register_user_add_rollback(transaction, plugin, user, state, index)
                    try:
                        self.invoker.user_add(plugin, user, state)
                    except Exception:
                        transaction.rollback(self.log_rollback_error)
                        raise
                continue

            for old_user in snapshot.users:
                user = by_uuid.get(old_user.uuid)
                if user is None:
                    transaction.add_rollback(
                        f"user {old_user.email} plugin {name}",
                        lambda plugin=plugin, old_user=old_user: self.invoker.user_add(
                            plugin,
                            old_user,
                            state,
                        ),
                        priority=10 - index,
                    )
                    try:
                        self.invoker.user_remove(plugin, old_user, state)
                    except Exception:
                        transaction.rollback(self.log_rollback_error)
                        raise
                    continue
                if old_user.email != user.email:
                    transaction.add_rollback(
                        f"rename {old_user.email} plugin {name}",
                        lambda plugin=plugin, old_user=old_user, user=user: self._restore_plugin_identity(
                            plugin,
                            state,
                            old_user,
                            user,
                        ),
                        priority=10 - index,
                    )
                    try:
                        self.invoker.user_remove(plugin, old_user, state)
                        self.invoker.user_add(plugin, user, state)
                    except Exception:
                        transaction.rollback(self.log_rollback_error)
                        raise
                    continue
                if self._user_projection_changed(old_user, user):
                    if old_user.blocked and not user.blocked:
                        rollback = lambda plugin=plugin, old_user=old_user: self.invoker.user_block(
                            plugin,
                            old_user,
                            state,
                        )
                    else:
                        rollback = lambda plugin=plugin, old_user=old_user: self.invoker.user_add(
                            plugin,
                            old_user,
                            state,
                        )
                    transaction.add_rollback(
                        f"update {user.email} plugin {name}",
                        rollback,
                        priority=10 - index,
                    )
                    try:
                        if user.blocked and not old_user.blocked:
                            self.invoker.user_block(plugin, user, state)
                        else:
                            self.invoker.user_add(plugin, user, state)
                    except Exception:
                        transaction.rollback(self.log_rollback_error)
                        raise

            for user in users:
                if user.uuid not in previous:
                    self._register_user_add_rollback(transaction, plugin, user, state, index)
                    try:
                        self.invoker.user_add(plugin, user, state)
                    except Exception:
                        transaction.rollback(self.log_rollback_error)
                        raise

        self._commit(state, transaction)

    def _register_user_add_rollback(
        self,
        transaction: ApplyTransaction,
        plugin: BasePlugin,
        user: User,
        state: AppState,
        index: int,
    ) -> None:
        transaction.add_rollback(
            f"user {user.email} plugin {plugin.meta.name}",
            lambda plugin=plugin, user=user: self.invoker.user_remove(plugin, user, state),
            priority=10 - index,
        )

    @staticmethod
    def _user_projection_changed(previous: User, current: User) -> bool:
        return any(
            getattr(previous, field) != getattr(current, field)
            for field in (
                "blocked",
                "expiry_date",
                "traffic_limit_gb",
                "disabled_protocols",
            )
        )

    def remove(self, state: AppState, email: str) -> None:
        user = find_user(state, email)
        if not user:
            return
        snapshot = copy.deepcopy(state)
        state.users = [candidate for candidate in state.users if candidate.email != email]
        transaction = self._new_transaction(state, snapshot)
        for index, plugin in self._enabled_transports(state):
            transaction.add_rollback(
                f"user {user.email} plugin {plugin.meta.name}",
                lambda plugin=plugin: self.invoker.user_add(
                    plugin,
                    user,
                    state,
                ),
                priority=10 - index,
            )
            try:
                self.invoker.user_remove(plugin, user, state)
            except Exception:
                transaction.rollback(self.log_rollback_error)
                raise
        self._commit(state, transaction)
        self._restart_subscriptions()

    def block(self, state: AppState, email: str) -> None:
        user = find_user(state, email)
        if not user:
            return
        snapshot = copy.deepcopy(state)
        user.blocked = True
        transaction = self._new_transaction(state, snapshot)
        for index, plugin in self._enabled_transports(state):
            transaction.add_rollback(
                f"block {user.email} plugin {plugin.meta.name}",
                lambda plugin=plugin: self.invoker.user_add(
                    plugin,
                    user,
                    state,
                ),
                priority=10 - index,
            )
            try:
                self.invoker.user_block(plugin, user, state)
            except Exception:
                transaction.rollback(self.log_rollback_error)
                raise
        self._commit(state, transaction)

    def unblock(self, state: AppState, email: str) -> None:
        user = find_user(state, email)
        if not user:
            return
        snapshot = copy.deepcopy(state)
        user.blocked = False
        transaction = self._new_transaction(state, snapshot)
        for index, plugin in self._enabled_transports(state):
            transaction.add_rollback(
                f"unblock {user.email} plugin {plugin.meta.name}",
                lambda plugin=plugin: self.invoker.user_block(
                    plugin,
                    user,
                    state,
                ),
                priority=10 - index,
            )
            try:
                self.invoker.user_add(plugin, user, state)
            except Exception:
                transaction.rollback(self.log_rollback_error)
                raise
        self._commit(state, transaction)

    def rename(self, state: AppState, email: str, new_email: str) -> None:
        """Rename a user without rotating its UUID or plugin credentials."""
        user = find_user(state, email)
        if not user:
            raise ValueError(f"User {email} not found")

        normalized_email = new_email.strip().lower()
        if not normalized_email or any(character.isspace() for character in normalized_email):
            raise ValueError(
                "User identifier must be non-empty and contain no whitespace",
            )
        duplicate = find_user(state, normalized_email)
        if duplicate is not None and duplicate is not user:
            raise ValueError(f"User {normalized_email} already exists")
        if normalized_email == user.email:
            return

        snapshot = copy.deepcopy(state)
        previous = copy.deepcopy(user)
        user.email = normalized_email
        renamed = copy.deepcopy(user)
        transaction = self._new_transaction(state, snapshot)
        for index, plugin in self._enabled_transports(state):
            transaction.add_rollback(
                f"rename {email} plugin {plugin.meta.name}",
                lambda plugin=plugin: self._restore_plugin_identity(
                    plugin,
                    state,
                    previous,
                    renamed,
                ),
                priority=10 - index,
            )
            try:
                self.invoker.user_remove(plugin, previous, state)
                self.invoker.user_add(plugin, user, state)
            except Exception:
                transaction.rollback(self.log_rollback_error)
                raise
        self._commit(state, transaction)
        self._restart_subscriptions()

    def set_protocol_enabled(
        self,
        state: AppState,
        email: str,
        name: str,
        enabled: bool,
    ) -> None:
        """Rebuild server authentication atomically for one user's transport."""
        user = find_user(state, email)
        if user is None:
            raise ValueError(f"User {email} not found")
        if not supports_personal_protocol_access(name) or name not in {
            plugin.meta.name for _, plugin in self._enabled_transports(state)
        }:
            raise ValueError(f"Protocol {name} is unavailable for per-user access")
        if type(enabled) is not bool:
            raise ValueError("enabled must be a boolean")
        was_enabled = name not in user.disabled_protocols
        if was_enabled == enabled:
            return
        snapshot = copy.deepcopy(state)
        if enabled:
            user.disabled_protocols.remove(name)
            if not user.blocked:
                plugin = next(plugin for _, plugin in self._enabled_transports(state) if plugin.meta.name == name)
                try:
                    self.invoker.user_add(plugin, user, state)
                except Exception:
                    self._restore_and_save(state, snapshot)
                    raise
        else:
            user.disabled_protocols.append(name)
        self._commit(state, self._new_transaction(state, snapshot))

    def set_device_limit(
        self,
        state: AppState,
        email: str,
        limit: int,
        *,
        reset: bool = False,
    ) -> None:
        """Set a subscription device limit; zero means unlimited."""
        user = find_user(state, email)
        if not user:
            raise ValueError(f"User {email} not found")
        if not isinstance(limit, int) or limit < 0:
            raise ValueError("Device limit must be a non-negative integer")

        user.device_limit = limit
        if reset:
            user.devices.clear()
            state.install.setdefault("_device_binding_resets", []).append(
                user.uuid,
            )
        self.save_state(state)

    def rotate_hydrabox_key(self, state: AppState, email: str) -> None:
        """Atomically replace the private key, invalidating every old link."""
        user = find_user(state, email)
        if not user:
            raise ValueError(f"User {email} not found")
        previous = user.hydrabox_jwe_key
        user.hydrabox_jwe_key = generate_hydrabox_jwe_key()
        try:
            self.save_state(state)
        except Exception:
            user.hydrabox_jwe_key = previous
            raise
        self._restart_subscriptions()

    def _enabled_transports(
        self,
        state: AppState,
    ) -> Iterable[tuple[int, BasePlugin]]:
        for index, plugin in enumerate(self.transports()):
            protocol = state.protocols.get(plugin.meta.name)
            if protocol and protocol.enabled:
                yield index, plugin

    def _new_transaction(
        self,
        state: AppState,
        snapshot: AppState,
    ) -> ApplyTransaction:
        return state_transaction(
            lambda: self._restore_and_save(state, snapshot),
            lambda: self._reapply_restored_state(state),
        )

    def _commit(self, state: AppState, transaction: ApplyTransaction) -> None:
        try:
            self.save_state(state)
            applied = self.apply_config(state)
        except Exception:
            transaction.rollback(self.log_rollback_error)
            raise
        if not applied:
            transaction.rollback(self.log_rollback_error)
            raise RuntimeError("Configuration apply failed; user change was rolled back")
        transaction.commit()

    def _restore_and_save(self, state: AppState, snapshot: AppState) -> None:
        restore_state_in_place(state, snapshot)
        self.save_state(state)

    def _reapply_restored_state(self, state: AppState) -> None:
        if not self.apply_config(state):
            detail = self.last_apply_error() or "restored configuration apply failed"
            raise RuntimeError(detail)

    def _restore_plugin_identity(
        self,
        plugin: BasePlugin,
        state: AppState,
        previous: User,
        renamed: User,
    ) -> None:
        self.invoker.user_remove(plugin, renamed, state)
        self.invoker.user_add(plugin, previous, state)

    @staticmethod
    def _restart_subscriptions() -> None:
        from hydra.core.systemd import is_active, restart

        if is_active("hydra-sub"):
            restart("hydra-sub")
