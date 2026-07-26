"""Compatibility facade for plugin discovery, catalog and execution."""
from __future__ import annotations

from typing import Optional

from hydra.contracts import ConfigFragment
from hydra.core.host import HOST
from hydra.core.state_models import AppState
from hydra.plugins.base import BasePlugin, PluginCategory, PluginStatus
from hydra.plugins.catalog import PluginCatalog
from hydra.plugins.defaults import (
    AmneziaWGPlugin, AntiDPIPlugin, AnyTLSPlugin, DNSCryptPlugin,
    Fail2banPlugin, HoneypotPlugin, Hysteria2Plugin, IPBanPlugin,
    MieruPlugin, NaivePlugin, ShadowTLSPlugin,
    SnellPlugin, TelemtPlugin, TrustTunnelPlugin, WarpPlugin,
    WdttPlugin, default_plugins,
)
from hydra.plugins.executor import PluginConfigurationError, PluginExecutor


# One process-lifetime instance per plugin is intentional: several plugins
# retain prepared runtime data between configure() and apply().
_PLUGINS: list[BasePlugin] = default_plugins()


def _catalog() -> PluginCatalog:
    """Resolve the current list so legacy monkeypatching remains effective."""
    return PluginCatalog(_PLUGINS)


def _executor() -> PluginExecutor:
    return PluginExecutor(_catalog())


def all_plugins() -> list[BasePlugin]:
    return _catalog().all()


def contract_errors(plugin: BasePlugin) -> list[str]:
    return _catalog().contract_errors(plugin)


def validate_contracts() -> None:
    _catalog().validate_contracts()


def get(name: str) -> Optional[BasePlugin]:
    return _catalog().get(name)


def transports() -> list[BasePlugin]:
    return _catalog().category(PluginCategory.TRANSPORT)


def enhancements() -> list[BasePlugin]:
    return _catalog().category(PluginCategory.ENHANCEMENT)


def security() -> list[BasePlugin]:
    return _catalog().category(PluginCategory.SECURITY)


def enabled(
    state: AppState,
    category: PluginCategory | None = None,
) -> list[BasePlugin]:
    return _catalog().enabled(state, category)


def collect_fragments(state: AppState) -> dict[str, ConfigFragment]:
    from hydra.core.singbox import log

    return _executor().collect_fragments(
        state,
        log_error=lambda message: log("ERROR", message),
    )


def requirements(state: AppState) -> dict[str, dict[str, list[str]]]:
    return _catalog().requirements(state, host=HOST)


def apply_enabled(state: AppState) -> list[tuple[BasePlugin, object]]:
    from hydra.core.singbox import log

    return _executor().apply_enabled(
        state,
        log_error=lambda message: log("ERROR", message),
    )


def rollback(
    plugin: BasePlugin,
    state: AppState,
    snapshot: object,
) -> bool:
    return _executor().rollback(plugin, state, snapshot)


def status_all(state: AppState | None = None) -> dict[str, dict]:
    return _catalog().status_all(state)


def health_all(state: AppState) -> dict[str, str]:
    return _executor().health_all(state)


# Historical names retained for third-party integrations.
get_all = all_plugins
get_enabled = enabled


__all__ = [
    "AmneziaWGPlugin", "AntiDPIPlugin", "AnyTLSPlugin", "DNSCryptPlugin",
    "Fail2banPlugin", "HoneypotPlugin", "Hysteria2Plugin", "IPBanPlugin",
    "MieruPlugin", "NaivePlugin", "ShadowTLSPlugin", "SnellPlugin",
    "TelemtPlugin", "TrustTunnelPlugin", "WarpPlugin", "WdttPlugin",
    "PluginConfigurationError",
    "PluginStatus",
    "all_plugins",
    "apply_enabled",
    "collect_fragments",
    "contract_errors",
    "enabled",
    "enhancements",
    "get",
    "get_all",
    "get_enabled",
    "health_all",
    "requirements",
    "rollback",
    "security",
    "status_all",
    "transports",
    "validate_contracts",
]
