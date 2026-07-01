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
