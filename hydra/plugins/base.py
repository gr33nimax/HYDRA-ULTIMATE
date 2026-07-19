"""hydra/plugins/base.py — Абстрактный интерфейс плагина v2."""
from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from hydra.core.state import AppState, User


class PluginCategory(enum.Enum):
    TRANSPORT = "transport"
    ENHANCEMENT = "enhancement"
    SECURITY = "security"


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


@dataclass
class PluginStatus:
    installed: bool
    enabled: bool
    running: bool
    port: int = 0
    info: dict = field(default_factory=dict)


@dataclass
class ConfigFragment:
    inbounds: list[dict] = field(default_factory=list)
    outbounds: list[dict] = field(default_factory=list)
    route_rules: list[dict] = field(default_factory=list)
    nft_tproxy_ports: list[int] = field(default_factory=list)
    nft_tproxy_ifaces: list[str] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    dns: dict = field(default_factory=dict)


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

    def healthcheck(self) -> tuple[bool, str]:
        """Return runtime health without changing plugin state."""
        try:
            status = self.status()
            if status.running:
                return True, ""
            return False, "сервис не находится в active"
        except Exception as exc:
            return False, str(exc) or exc.__class__.__name__

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
