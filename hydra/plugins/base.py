"""hydra/plugins/base.py — Абстрактный интерфейс плагина v2."""
from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from hydra.core.state import AppState, User
from hydra.plugins.config import ConfigFragment


class PluginCategory(enum.Enum):
    TRANSPORT = "transport"
    ENHANCEMENT = "enhancement"
    SECURITY = "security"


@dataclass(frozen=True)
class PluginCapabilities:
    """Declarative host and orchestration capabilities of a plugin."""

    central_apply: bool
    required_commands: tuple[str, ...] = ()
    required_services: tuple[str, ...] = ()
    conflicts_with: tuple[str, ...] = ()

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


def lifecycle_result(plugin, operation: str, state: AppState | None = None) -> LifecycleResult:
    """Invoke the typed lifecycle adapter while supporting legacy objects."""
    typed = getattr(type(plugin), f"{operation}_result", None)
    if callable(typed):
        return typed(plugin) if state is None else typed(plugin, state)
    callback_name = {
        "install": "install", "uninstall": "uninstall",
        "enable": "on_enable", "disable": "on_disable",
    }[operation]
    callback = getattr(plugin, callback_name)
    value = callback() if state is None else callback(state)
    return LifecycleResult(operation, value is not False)


@dataclass
class PluginMeta:
    name: str
    description: str
    category: PluginCategory = PluginCategory.TRANSPORT
    version: str = "1.0.0"
    needs_domain: bool = False
    central_apply: bool | None = None
    required_commands: tuple[str, ...] = ()
    required_services: tuple[str, ...] = ()
    conflicts_with: tuple[str, ...] = ()

    @property
    def capabilities(self) -> PluginCapabilities:
        return PluginCapabilities(
            central_apply=self.central_apply is not False,
            required_commands=tuple(self.required_commands),
            required_services=tuple(self.required_services),
            conflicts_with=tuple(self.conflicts_with),
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
    def status(self) -> PluginStatus: ...

    @abstractmethod
    def configure(self, state: AppState) -> ConfigFragment: ...

    def apply(self, state: AppState) -> bool:
        return True

    def install_result(self) -> LifecycleResult:
        return LifecycleResult("install", bool(self.install()))

    def uninstall_result(self) -> LifecycleResult:
        return LifecycleResult("uninstall", bool(self.uninstall()))

    def enable_result(self, state: AppState) -> LifecycleResult:
        self.on_enable(state)
        return LifecycleResult("enable", True)

    def disable_result(self, state: AppState) -> LifecycleResult:
        self.on_disable(state)
        return LifecycleResult("disable", True)

    def healthcheck(self) -> HealthResult | tuple[bool, str]:
        """Return runtime health without changing plugin state."""
        try:
            status = self.status()
            if status.running:
                return HealthResult(True)
            return HealthResult(False, "service is not active", "error")
        except Exception as exc:
            return HealthResult(False, str(exc) or exc.__class__.__name__, "unknown")

    def health_result(self) -> HealthResult:
        result = self.healthcheck()
        if isinstance(result, HealthResult):
            return result
        healthy, detail = result
        return HealthResult(bool(healthy), str(detail or ""), "ok" if healthy else "error")

    def snapshot(self, state: AppState):
        """Capture plugin-owned runtime state before apply.

        The default is intentionally a no-op for backwards compatibility.
        Plugins that write external files or units can override this hook.
        """
        return None

    def rollback(self, state: AppState, snapshot) -> bool:
        """Restore a snapshot captured before ``apply``."""
        return True

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_user_add(self, user: User, state: AppState) -> None: pass
    def on_user_remove(self, user: User, state: AppState) -> None: pass
    def on_user_block(self, user: User, state: AppState) -> None: pass

    def generate_client_config(self, user: User, state: AppState) -> str:
        return ""

    def client_link(self, user: User, state: AppState) -> str:
        return ""

    def connected_clients(self) -> list[dict]:
        return []

    def on_enable(self, state: AppState) -> None: pass
    def on_disable(self, state: AppState) -> None: pass
