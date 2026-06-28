"""
hydra/plugins/registry.py — Реестр плагинов.

Загружает, регистрирует и управляет всеми плагинами.
Предоставляет единую точку для сборки конфига Sing-Box.
"""
from __future__ import annotations

from typing import Optional

from hydra.plugins.base import BasePlugin, ConfigFragment
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.plugins.dnscrypt.plugin import DNSCryptPlugin
from hydra.plugins.warp.plugin import WarpPlugin
from hydra.core.state import AppState


# ═════════════════════════════════════════════════════════════════════════════
#  Реестр — все доступные плагины
# ═════════════════════════════════════════════════════════════════════════════

_ALL_PLUGINS: list[BasePlugin] = [
    AmneziaWGPlugin(),
    DNSCryptPlugin(),
    WarpPlugin(),
]


def get_all() -> list[BasePlugin]:
    """Возвращает список всех зарегистрированных плагинов."""
    return _ALL_PLUGINS


def get(name: str) -> Optional[BasePlugin]:
    """Возвращает плагин по имени."""
    for p in _ALL_PLUGINS:
        if p.meta.name == name:
            return p
    return None


def get_enabled(state: AppState) -> list[BasePlugin]:
    """Возвращает список включённых плагинов."""
    return [
        p for p in _ALL_PLUGINS
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled
    ]


def collect_fragments(state: AppState) -> dict[str, ConfigFragment]:
    """
    Собирает фрагменты конфига со всех включённых плагинов.
    Возвращает {plugin_name: ConfigFragment}.
    """
    fragments: dict[str, ConfigFragment] = {}
    for plugin in get_enabled(state):
        try:
            fragment = plugin.configure(state)
            if fragment and (fragment.inbounds or fragment.outbounds or fragment.route_rules):
                fragments[plugin.meta.name] = fragment
        except Exception:
            pass
    return fragments


def install_all(state: AppState) -> dict[str, bool]:
    """Устанавливает все плагины. Возвращает {name: success}."""
    results = {}
    for plugin in _ALL_PLUGINS:
        try:
            results[plugin.meta.name] = plugin.install()
        except Exception:
            results[plugin.meta.name] = False
    return results


def status_all() -> dict[str, dict]:
    """Возвращает статус всех плагинов."""
    result = {}
    for plugin in _ALL_PLUGINS:
        try:
            s = plugin.status()
            result[plugin.meta.name] = {
                "installed": s.installed,
                "enabled": s.enabled,
                "running": s.running,
                "port": s.port,
            }
        except Exception:
            result[plugin.meta.name] = {
                "installed": False, "enabled": False, "running": False, "port": 0,
            }
    return result
