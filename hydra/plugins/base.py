"""hydra/plugins/base.py — Абстрактный интерфейс плагина v2."""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, cast
from hydra.contracts import BackupResource, ConfigFragment, JsonValue
from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess


class PluginCategory(enum.Enum):
    TRANSPORT = "transport"
    ENHANCEMENT = "enhancement"
    SECURITY = "security"


@dataclass(frozen=True)
class MaintenanceTask:
    """One plugin-owned task executed by the shared background scheduler."""

    action: str
    title: str
    description: str = ""
    due_query: str = ""
    enabled_flag: str = ""
    apply_on_success: bool = False


@dataclass(frozen=True)
class PluginCapabilities:
    """Declarative host and orchestration capabilities of a plugin."""

    central_apply: bool
    required_commands: tuple[str, ...] = ()
    required_services: tuple[str, ...] = ()
    conflicts_with: tuple[str, ...] = ()
    commands: tuple[str, ...] = ()
    persist_only_commands: tuple[str, ...] = ()
    queries: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    tls_domain_source: str = ""
    config_defaults: tuple[tuple[str, JsonValue], ...] = ()
    subscription_profile_query: str = ""
    subscription_enabled: bool = True
    hydra_v2_subscription_enabled: bool = True
    manual_artifacts_query: str = ""
    connection_source: str = "plugin"
    maintenance_tasks: tuple[MaintenanceTask, ...] = ()
    backup_resources: tuple[BackupResource, ...] = ()

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class LifecycleResult:
    """Normalized result for install/uninstall/enable/disable operations."""

    operation: str
    ok: bool
    changed: bool = True
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class HealthResult:
    """Structured health result while accepting legacy tuple implementations."""

    healthy: bool
    detail: str = ""
    severity: str = "ok"
    checks: dict[str, bool] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def lifecycle_result(
    plugin,
    operation: str,
    state: PluginStateAccess | None = None,
) -> LifecycleResult:
    """Invoke the typed lifecycle adapter while supporting legacy objects."""
    typed = getattr(type(plugin), f"{operation}_result", None)
    if callable(typed):
        return cast(
            LifecycleResult,
            typed(plugin) if state is None else typed(plugin, state),
        )
    callback_name = {
        "install": "install",
        "uninstall": "uninstall",
        "enable": "on_enable",
        "disable": "on_disable",
    }[operation]
    callback = getattr(plugin, callback_name)
    value = callback() if state is None else callback(state)
    return LifecycleResult(
        operation,
        value if isinstance(value, bool) else True,
    )


def failure_stage(plugin, kind: str) -> str:
    """Read one optional, best-effort redacted plugin failure stage.

    A plugin that fails records the failing stage itself (the unit that did not
    come up, the route that stayed inactive). Reading it is best effort: a
    missing hook, a non-string value or a raising reader must never change the
    lifecycle outcome, so every caller gets "" instead.
    """
    hook = getattr(plugin, f"{kind}_failure", None)
    if not callable(hook):
        return ""
    try:
        stage = hook()
    except Exception:
        return ""
    return stage.strip() if isinstance(stage, str) else ""


@dataclass
class PluginMeta:
    name: str
    description: str
    display_name: str = ""
    category: PluginCategory = PluginCategory.TRANSPORT
    version: str = "1.0.0"
    needs_domain: bool = False
    central_apply: bool | None = None
    required_commands: tuple[str, ...] = ()
    required_services: tuple[str, ...] = ()
    conflicts_with: tuple[str, ...] = ()
    commands: tuple[str, ...] = ()
    persist_only_commands: tuple[str, ...] = ()
    queries: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    tls_domain_source: str = ""
    config_defaults: tuple[tuple[str, JsonValue], ...] = ()
    subscription_profile_query: str = ""
    subscription_profile_name: str = ""
    subscription_enabled: bool = True
    hydra_v2_subscription_enabled: bool | None = None
    manual_artifacts_query: str = ""
    connection_source: str = "plugin"
    maintenance_tasks: tuple[MaintenanceTask, ...] = ()
    backup_resources: tuple[BackupResource, ...] = ()
    contract_version: int = 1

    @property
    def capabilities(self) -> PluginCapabilities:
        return PluginCapabilities(
            central_apply=self.central_apply != False,
            required_commands=tuple(self.required_commands),
            required_services=tuple(self.required_services),
            conflicts_with=tuple(self.conflicts_with),
            commands=tuple(self.commands),
            persist_only_commands=tuple(self.persist_only_commands),
            queries=tuple(self.queries),
            actions=tuple(self.actions),
            tls_domain_source=self.tls_domain_source,
            config_defaults=tuple(self.config_defaults),
            subscription_profile_query=self.subscription_profile_query,
            subscription_enabled=self.subscription_enabled,
            hydra_v2_subscription_enabled=(
                self.subscription_enabled
                if self.hydra_v2_subscription_enabled is None
                else self.hydra_v2_subscription_enabled
            ),
            manual_artifacts_query=self.manual_artifacts_query,
            connection_source=self.connection_source,
            maintenance_tasks=tuple(self.maintenance_tasks),
            backup_resources=tuple(self.backup_resources),
        )


@dataclass
class PluginStatus:
    installed: bool
    enabled: bool
    running: bool
    port: int = 0
    info: dict = field(default_factory=dict)


class BasePlugin(ABC):
    meta: PluginMeta

    @abstractmethod
    def install(self) -> bool: ...

    @abstractmethod
    def uninstall(self) -> bool: ...

    @abstractmethod
    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus: ...

    @abstractmethod
    def configure(self, state: PluginStateAccess) -> ConfigFragment: ...

    def apply(self, state: PluginStateAccess) -> bool:
        return True

    def install_result(self) -> LifecycleResult:
        return LifecycleResult("install", bool(self.install()))

    def uninstall_result(self) -> LifecycleResult:
        return LifecycleResult("uninstall", bool(self.uninstall()))

    def enable_result(self, state: PluginStateAccess) -> LifecycleResult:
        self.on_enable(state)
        return LifecycleResult("enable", True)

    def disable_result(self, state: PluginStateAccess) -> LifecycleResult:
        self.on_disable(state)
        return LifecycleResult("disable", True)

    def healthcheck(self) -> HealthResult | tuple[bool, str]:
        """Return runtime health without changing plugin state."""
        try:
            status = self.status()
            if status.running:
                return HealthResult(True)
            return HealthResult(False, "service is not active", "error")
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            detail = str(exc)
            return HealthResult(
                False,
                detail if detail else exc.__class__.__name__,
                "unknown",
            )

    def healthcheck_for_state(
        self,
        state: PluginStateAccess,
    ) -> HealthResult | tuple[bool, str]:
        """Check the runtime against the state currently being applied.

        Shared-runtime plugins can override this hook to avoid re-reading a
        stale persisted enablement flag during an apply transaction.
        """
        if "healthcheck" in self.__dict__ or type(self).healthcheck is not BasePlugin.healthcheck:
            return self.healthcheck()
        try:
            status = self.status(state)
            if status.running:
                return HealthResult(True)
            return HealthResult(False, "service is not active", "error")
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            detail = str(exc)
            return HealthResult(
                False,
                detail if detail else exc.__class__.__name__,
                "unknown",
            )

    def health_result(self, state: PluginStateAccess | None = None) -> HealthResult:
        result = self.healthcheck() if state is None else self.healthcheck_for_state(state)
        if isinstance(result, HealthResult):
            return result
        healthy, detail = result
        return HealthResult(bool(healthy), str(detail or ""), "ok" if healthy else "error")

    def snapshot(self, state: PluginStateAccess) -> dict[str, Any]:
        """Capture plugin-owned runtime state before apply.

        The default is an empty snapshot; plugins that own runtime files or
        units override it with the resources needed for rollback.
        """
        return {}

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        """Restore a snapshot captured before ``apply``."""
        return True

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        """Return per-user bytes recorded for this plugin by the daemon.

        Shared traffic accounting stores attributed bytes under the plugin's
        own name, so a transport that does not keep its own counters still
        reports what users moved through it.
        """
        name = self.meta.name
        totals: dict[str, int] = {}
        for user in state.users:
            value = user.credentials.get(name, {}).get(
                "traffic_used_bytes",
                0,
            )
            try:
                totals[user.email] = int(value or 0)
            except (TypeError, ValueError):
                totals[user.email] = 0
        return {email: total for email, total in totals.items() if total > 0}

    def traffic_snapshot(
        self,
        state: PluginStateAccess,
    ) -> dict[str, int] | None:
        """Return a resettable raw per-user counter, when available."""
        return None

    def traffic_source_reason(
        self,
        state: PluginStateAccess,
    ) -> str:
        """Explain why the live counter source is unavailable, if it is.

        Empty means the last read succeeded, or that this protocol has no
        snapshot source to read. A protocol that does have one must report
        every failure here so monitoring can show "unavailable" instead of a
        measured zero.
        """
        del state
        return ""

    def aggregate_traffic_snapshot(
        self,
        state: PluginStateAccess,
    ) -> int | None:
        """Return a resettable protocol-wide counter, when available."""
        return None

    def ingest_traffic(
        self,
        state: PluginStateAccess,
        cursors: dict,
    ) -> None:
        """Merge plugin-owned event/log cursors into authoritative state."""

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_remove(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_block(self, user: User, state: PluginStateAccess) -> None:
        pass

    def generate_client_config(self, user: User, state: PluginStateAccess) -> str:
        return ""

    def generate_singbox_client_config(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> str:
        """Return the plugin-owned projection used by full sing-box exports."""
        return self.generate_client_config(user, state)

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        return ""

    def client_links(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> list[str]:
        link = self.client_link(user, state)
        return [link] if link else []

    def connected_clients(
        self,
        state: PluginStateAccess | None = None,
    ) -> list[dict]:
        return []

    def on_enable(self, state: PluginStateAccess) -> None:
        pass

    def on_disable(self, state: PluginStateAccess) -> None:
        pass
