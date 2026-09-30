"""Apply a complete base snapshot to one node's local Hydra state."""

from __future__ import annotations

import copy
import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Callable

from hydra.contracts.node_export import (
    NodeClientExport,
    NodeClientExportUser,
    NodeClientProfile,
)
from hydra.contracts.node_traffic import NodeTrafficReport, NodeTrafficUsage
from hydra.contracts.node_snapshot import (
    NodeDesiredSnapshot,
    NodeProtocolSpec,
    is_node_local_secret_key,
)
from hydra.contracts.node_validation import checked_node_branch, checked_node_revision
from hydra.core.state_models import AppState, User, get_protocol
from hydra.plugins.base import PluginCategory
from hydra.services.application import ApplicationService
from hydra.services.node_traffic_accounting import (
    set_traffic_reset_epoch,
    traffic_reset_epoch,
)
from hydra.services.traffic import reset_user_traffic

_GENERATION_KEY = "hydra_node_control"
_LOGGER = logging.getLogger(__name__)


@dataclass
class NodeReconciler:
    node_id: str
    application: ApplicationService
    state_reader: Callable[[], AppState]
    upgrade_scheduler: Callable[[str, str], dict[str, object]] | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def current_generation(self) -> int:
        raw = self.state_reader().feature_extensions.get(_GENERATION_KEY, {})
        if not isinstance(raw, dict):
            raise ValueError("node control generation state is invalid")
        generation = raw.get("generation", 0)
        if type(generation) is not int or generation < 0:
            raise ValueError("node control generation is invalid")
        return generation

    def diagnostics(self) -> dict[str, object]:
        return {"last_error": self.application.apply_error()}

    def schedule_upgrade(self, *, branch: str, revision: str) -> dict[str, object]:
        branch = checked_node_branch(branch, context="branch")
        revision = checked_node_revision(revision, context="revision")
        if self.upgrade_scheduler is None:
            raise RuntimeError("node upgrade scheduling is unavailable")
        result = self.upgrade_scheduler(branch, revision)
        if not isinstance(result, dict) or result.get("status") != "scheduled":
            raise RuntimeError("node upgrade could not be scheduled")
        already_scheduled = result.get("already_scheduled", False)
        if type(already_scheduled) is not bool:
            raise RuntimeError("node upgrade scheduler returned an invalid result")
        response: dict[str, object] = {
            "node_id": self.node_id,
            "status": "scheduled",
            "branch": branch,
            "revision": revision,
        }
        if already_scheduled:
            response["already_scheduled"] = True
        return response

    def export(self) -> NodeClientExport:
        state = self.state_reader()
        return self._export_state(state, self._generation(state))

    def traffic_report(self) -> NodeTrafficReport:
        state = self.state_reader()
        return NodeTrafficReport(
            node_id=self.node_id,
            generation=self._generation(state),
            users={
                user.uuid: NodeTrafficUsage(
                    reset_epoch=traffic_reset_epoch(state, user),
                    used_bytes=max(0, user.traffic_used_bytes),
                )
                for user in state.users
            },
        )

    def _export_state(self, state: AppState, generation: int) -> NodeClientExport:
        profiles_by_user: dict[str, NodeClientExportUser] = {}
        enabled = self.application.protocols.enabled_subscription_names(
            state,
            category=PluginCategory.TRANSPORT,
        )
        for user in state.users:
            if user.blocked:
                continue
            profiles: list[NodeClientProfile] = []
            for name in sorted(enabled):
                if name in user.disabled_protocols:
                    continue
                declared = self.application.protocols.client_profiles(state, name)
                profile_names = _profile_names(declared) if declared else ("",)
                for profile_name in profile_names:
                    parameters = {"profile": profile_name} if profile_name else {}
                    links = self.application.protocols.client_links(
                        state,
                        name,
                        user,
                        **parameters,
                    )
                    raw_config = self.application.protocols.client_config(
                        state,
                        name,
                        user,
                        **parameters,
                    )
                    singbox = _singbox_documents(raw_config)
                    if links or singbox:
                        profiles.append(
                            NodeClientProfile(
                                protocol=name,
                                profile=profile_name,
                                links=tuple(links),
                                singbox=singbox,
                            )
                        )
            profiles_by_user[user.uuid] = NodeClientExportUser(
                uuid=user.uuid,
                profiles=tuple(profiles),
            )
        exported = NodeClientExport(
            node_id=self.node_id,
            generation=generation,
            users=profiles_by_user,
        )
        exported.validate()
        return exported

    def apply(self, snapshot: NodeDesiredSnapshot) -> dict[str, object]:
        snapshot.validate()
        if snapshot.node_id != self.node_id:
            raise ValueError("snapshot node_id does not match this node")
        with self._lock:
            state = self.state_reader()
            current = self._generation(state)
            if snapshot.generation < current:
                raise ValueError("stale generation")
            if snapshot.generation == current:
                return {"generation": current, "already_applied": True}

            previous = copy.deepcopy(state)
            calls = snapshot.protocols.get("calls")
            old_calls = state.protocols.get("calls")
            pool_changed = bool(calls and calls.enabled) != bool(old_calls and old_calls.enabled)
            pool_snapshot = self.application.calls.snapshot_managed_vk_pool() if pool_changed else None
            try:
                users = self._users_for_snapshot(state, snapshot)
                if not self._users_match(state.users, users):
                    self.application.users.reconcile(state, users)
                self._sync_protocols(state, snapshot.protocols)
                self._export_state(state, snapshot.generation)
                state.feature_extensions[_GENERATION_KEY] = {
                    "generation": snapshot.generation,
                }
                self.application.admin.save_state(state)
            except Exception:
                if pool_changed:
                    try:
                        self.application.calls.restore_managed_vk_pool(pool_snapshot)
                    except Exception:
                        _LOGGER.error("Node VK pool rollback failed; original error preserved")
                self._restore_after_failure(state, previous)
                raise
            return {"generation": snapshot.generation, "already_applied": False}

    @staticmethod
    def _generation(state: AppState) -> int:
        raw = state.feature_extensions.get(_GENERATION_KEY, {})
        if not isinstance(raw, dict):
            raise ValueError("node control generation state is invalid")
        value = raw.get("generation", 0)
        if type(value) is not int or value < 0:
            raise ValueError("node control generation is invalid")
        return value

    @staticmethod
    def _users_for_snapshot(
        state: AppState,
        snapshot: NodeDesiredSnapshot,
    ) -> list[User]:
        existing = {user.uuid: user for user in state.users}
        users: list[User] = []
        for projection in snapshot.users:
            current = existing.get(projection.uuid)
            current_epoch = traffic_reset_epoch(state, current) if current is not None else 0
            if projection.traffic_reset_epoch < current_epoch:
                raise ValueError("snapshot traffic reset epoch is stale")
            if projection.traffic_reset_epoch > current_epoch and current is not None:
                reset_user_traffic(state, current.email)
                set_traffic_reset_epoch(state, current, projection.traffic_reset_epoch)
            user = copy.deepcopy(existing.get(projection.uuid))
            if user is None:
                user = User(email=projection.email, uuid=projection.uuid)
            set_traffic_reset_epoch(state, user, projection.traffic_reset_epoch)
            user.email = projection.email
            user.uuid = projection.uuid
            user.blocked = projection.blocked
            user.expiry_date = projection.expiry_date
            user.disabled_protocols = list(projection.disabled_protocols)
            user.traffic_limit_gb = projection.traffic_limit_gb
            users.append(user)
        return users

    @staticmethod
    def _users_match(current: list[User], desired: list[User]) -> bool:
        if len(current) != len(desired):
            return False
        by_uuid = {user.uuid: user for user in current}
        for target in desired:
            user = by_uuid.get(target.uuid)
            if user is None or any(
                getattr(user, field) != getattr(target, field)
                for field in (
                    "email",
                    "blocked",
                    "expiry_date",
                    "disabled_protocols",
                    "traffic_limit_gb",
                )
            ):
                return False
        return True

    def _sync_protocols(
        self,
        state: AppState,
        desired: dict[str, NodeProtocolSpec],
    ) -> None:
        plugins = {plugin.meta.name: plugin for plugin in self.application.protocols.list(PluginCategory.TRANSPORT)}
        unknown = set(desired) - set(plugins)
        if unknown:
            raise ValueError(f"unknown node protocols: {', '.join(sorted(unknown))}")
        for name, spec in desired.items():
            capabilities = plugins[name].meta.capabilities
            if spec.enabled and not (capabilities.subscription_enabled or capabilities.hydra_v2_subscription_enabled):
                raise ValueError(f"protocol {name} cannot be published in a subscription")

        config_changed = False
        for name, plugin in plugins.items():
            spec = desired.get(name)
            enabled = bool(spec and spec.enabled)
            protocol = get_protocol(state, name)
            if spec is not None:
                merged = _merge_local_secrets(protocol.config, spec.config)
                if protocol.config != merged or protocol.port != spec.port:
                    protocol.config = merged
                    protocol.port = spec.port
                    config_changed = True
            if name == "calls" and enabled != protocol.enabled:
                operation = (
                    self.application.calls.enable_native_vk if enabled else self.application.calls.disable_native_vk
                )
                if not operation(state):
                    raise RuntimeError("node VK pool lifecycle failed")
                config_changed = False
                continue
            if enabled and not protocol.installed:
                protocol.enabled = False
                if not self.application.protocols.install(state, name):
                    raise RuntimeError(f"protocol {name} installation failed")
                protocol.installed = True
            protocol = get_protocol(state, name)
            if enabled and not protocol.enabled:
                if not self.application.protocols.enable(state, name):
                    raise RuntimeError(f"protocol {name} could not be enabled")
                config_changed = False
            elif not enabled and protocol.enabled:
                if not self.application.protocols.disable(state, name):
                    raise RuntimeError(f"protocol {name} could not be disabled")
                config_changed = False
        if config_changed and not self.application.apply(state):
            message = self.application.apply_error() or "node protocol configuration apply failed"
            raise RuntimeError(message)

    def _restore_after_failure(self, state: AppState, previous: AppState) -> None:
        from hydra.services.configuration import restore_state_in_place

        failed = copy.deepcopy(state)
        if not self._users_match(state.users, previous.users):
            try:
                self.application.users.reconcile(state, copy.deepcopy(previous.users))
            except Exception:
                _LOGGER.error("Node user rollback failed; original error preserved")

        try:
            plugins = self.application.protocols.list(PluginCategory.TRANSPORT)
        except Exception:
            plugins = []
            _LOGGER.error("Node protocol rollback inventory failed; original error preserved")
        for plugin in plugins:
            name = plugin.meta.name
            old = previous.protocols.get(name)
            new = failed.protocols.get(name)
            old_enabled = bool(old and old.enabled)
            new_enabled = bool(new and new.enabled)
            if old_enabled != new_enabled:
                operation = "enable" if old_enabled else "disable"
                try:
                    if not getattr(self.application.protocols, operation)(state, name):
                        _LOGGER.error("Node protocol lifecycle rollback failed; original error preserved")
                except Exception:
                    _LOGGER.error("Node protocol lifecycle rollback failed; original error preserved")
            if not (old and old.installed) and new and new.installed:
                try:
                    if not self.application.protocols.uninstall(state, name):
                        _LOGGER.error("Node protocol install rollback failed; original error preserved")
                except Exception:
                    _LOGGER.error("Node protocol install rollback failed; original error preserved")

        restore_state_in_place(state, previous)
        try:
            self.application.admin.save_state(state)
            if not self.application.apply(state):
                _LOGGER.error("Node snapshot rollback apply failed; original error preserved")
        except Exception:
            _LOGGER.error("Node snapshot rollback failed; original error preserved")


def _merge_local_secrets(local: dict, desired: dict) -> dict:
    """Keep node-generated credentials local when replacing protocol settings."""
    merged = copy.deepcopy(desired)
    for key, value in local.items():
        if is_node_local_secret_key(key):
            merged[key] = copy.deepcopy(value)
        elif isinstance(value, dict):
            child = merged.get(key)
            preserved = _merge_local_secrets(value, child if isinstance(child, dict) else {})
            if preserved:
                merged[key] = preserved
    return merged


def _profile_names(raw: list[dict]) -> tuple[str, ...]:
    names = tuple(
        item["name"] for item in raw if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]
    )
    if len(names) != len(raw):
        raise ValueError("protocol profile query returned an invalid profile")
    return names


def _singbox_documents(raw: str) -> tuple[dict, ...]:
    if not raw:
        return ()
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return ()
    if isinstance(decoded, dict):
        return (decoded,)
    if isinstance(decoded, list) and all(isinstance(item, dict) for item in decoded):
        return tuple(decoded)
    return ()


__all__ = ["NodeReconciler"]
