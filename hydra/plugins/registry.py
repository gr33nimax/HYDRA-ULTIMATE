"""hydra/plugins/registry.py — Реестр плагинов: discovery, фильтры, сборка фрагментов."""
from __future__ import annotations

from typing import Optional

from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.plugins.mieru.plugin import MieruPlugin
from hydra.plugins.naive.plugin import NaivePlugin
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin
from hydra.plugins.telemt.plugin import TelemtPlugin
from hydra.plugins.wdtt.plugin import WdttPlugin
from hydra.plugins.dnscrypt.plugin import DNSCryptPlugin
from hydra.plugins.warp.plugin import WarpPlugin
from hydra.plugins.fail2ban.plugin import Fail2banPlugin
from hydra.plugins.honeypot.plugin import HoneypotPlugin
from hydra.plugins.ipban.plugin import IPBanPlugin
from hydra.plugins.shadowtls.plugin import ShadowTLSPlugin
from hydra.plugins.hysteria2.plugin import Hysteria2Plugin
from hydra.plugins.snell.plugin import SnellPlugin
from hydra.core.state import AppState

_PLUGINS: list[BasePlugin] = [
    AmneziaWGPlugin(),
    AnyTLSPlugin(),
    TrustTunnelPlugin(),
    ShadowTLSPlugin(),
    Hysteria2Plugin(),
    SnellPlugin(),
    MieruPlugin(),
    NaivePlugin(),
    TelemtPlugin(),
    WdttPlugin(),
    DNSCryptPlugin(),
    WarpPlugin(),
    Fail2banPlugin(),
    HoneypotPlugin(),
    IPBanPlugin(),
]

# WDTT remains on its legacy manager-controlled lifecycle by explicit product
# decision.  All other plugins use the centralized configure/apply pipeline.
_CENTRAL_APPLY_EXCLUSIONS = frozenset({"wdtt"})


class PluginConfigurationError(RuntimeError):
    """An enabled plugin could not produce a valid configuration."""

    def __init__(self, plugin_name: str, cause: Exception):
        super().__init__(f"Plugin {plugin_name} configuration failed: {cause}")
        self.plugin_name = plugin_name
        self.__cause__ = cause


def all_plugins() -> list[BasePlugin]:
    return _PLUGINS


def get(name: str) -> Optional[BasePlugin]:
    for p in _PLUGINS:
        if p.meta.name == name:
            return p
    return None


def transports() -> list[BasePlugin]:
    return [p for p in _PLUGINS if p.meta.category == PluginCategory.TRANSPORT]


def enhancements() -> list[BasePlugin]:
    return [p for p in _PLUGINS if p.meta.category == PluginCategory.ENHANCEMENT]


def security() -> list[BasePlugin]:
    return [p for p in _PLUGINS if p.meta.category == PluginCategory.SECURITY]


def enabled(state: AppState, category: PluginCategory | None = None) -> list[BasePlugin]:
    pool = _PLUGINS if category is None else [p for p in _PLUGINS if p.meta.category == category]
    return [p for p in pool if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled]


def collect_fragments(state: AppState) -> dict[str, ConfigFragment]:
    fragments: dict[str, ConfigFragment] = {}
    for p in enabled(state):
        try:
            f = p.configure(state)
            if f and (f.inbounds or f.outbounds or f.route_rules or f.nft_tproxy_ports or f.nft_tproxy_ifaces or f.endpoints or f.dns):
                fragments[p.meta.name] = f
        except Exception as e:
            from hydra.core.singbox import _log
            _log("ERROR", f"Error configuring plugin {p.meta.name}: {e}")
            raise PluginConfigurationError(p.meta.name, e) from e
    return fragments


def apply_enabled(state: AppState) -> None:
    """Apply the configuration prepared by every enabled plugin."""
    for plugin in enabled(state):
        if plugin.meta.name in _CENTRAL_APPLY_EXCLUSIONS:
            continue
        try:
            applied = plugin.apply(state)
        except Exception as exc:
            raise RuntimeError(f"Plugin {plugin.meta.name} apply failed: {exc}") from exc
        if not applied:
            raise RuntimeError(f"Plugin {plugin.meta.name} apply returned false")


def status_all() -> dict[str, dict]:
    """Возвращает {name: {running, installed, port, enabled}} для всех плагинов."""
    result: dict[str, dict] = {}
    for p in _PLUGINS:
        try:
            s = p.status()
            result[p.meta.name] = {
                "running": s.running,
                "installed": s.installed,
                "port": s.port,
                "enabled": s.enabled,
                "error": "",
            }
        except Exception as exc:
            # A broken optional service must not make the whole protocol
            # dashboard unusable.  Its own card will expose the failure.
            result[p.meta.name] = {
                "running": False,
                "installed": False,
                "port": 0,
                "enabled": False,
                "error": str(exc) or exc.__class__.__name__,
            }
    return result


# Обратная совместимость
get_all = all_plugins
get_enabled = enabled

