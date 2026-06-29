"""hydra/plugins/registry.py — Реестр плагинов: discovery, фильтры, сборка фрагментов."""
from __future__ import annotations

from typing import Optional

from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.plugins.dnscrypt.plugin import DNSCryptPlugin
from hydra.plugins.warp.plugin import WarpPlugin
from hydra.core.state import AppState

_PLUGINS: list[BasePlugin] = [
    AmneziaWGPlugin(),
    DNSCryptPlugin(),
    WarpPlugin(),
]


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
            if f and (f.inbounds or f.outbounds or f.route_rules or f.nft_tproxy_ports):
                fragments[p.meta.name] = f
        except Exception:
            pass
    return fragments


# Обратная совместимость
get_all = all_plugins
get_enabled = enabled

