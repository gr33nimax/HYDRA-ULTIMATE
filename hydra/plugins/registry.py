"""hydra/plugins/registry.py — Реестр плагинов: discovery, фильтры, сборка фрагментов."""
from __future__ import annotations

from typing import Optional

from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory, PluginStatus
from hydra.plugins.config import validate_fragment
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
from hydra.core.host import HOST
from hydra.core.apply_transaction import ApplyTransaction
from hydra.core.errors import PluginError
from hydra.plugins.runtime import assess

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
class PluginConfigurationError(PluginError):
    """An enabled plugin could not produce a valid configuration."""

    def __init__(self, plugin_name: str, cause: Exception):
        super().__init__(f"Plugin {plugin_name} configuration failed: {cause}")
        self.plugin_name = plugin_name
        self.__cause__ = cause


def _uses_central_apply(plugin: BasePlugin) -> bool:
    """Read the capability flag while preserving legacy test/custom plugins."""
    value = getattr(plugin.meta, "central_apply", None)
    return plugin.meta.name != "wdtt" if value is None else value


def all_plugins() -> list[BasePlugin]:
    return _PLUGINS


def contract_errors(plugin: BasePlugin) -> list[str]:
    """Return declarative contract violations without touching the host."""
    errors: list[str] = []
    meta = getattr(plugin, "meta", None)
    if meta is None:
        return ["missing meta"]
    if not isinstance(meta.name, str) or not meta.name.strip():
        errors.append("meta.name must be a non-empty string")
    if not isinstance(meta.description, str):
        errors.append("meta.description must be a string")
    if not isinstance(meta.version, str) or not meta.version.strip():
        errors.append("meta.version must be a non-empty string")
    capabilities = meta.capabilities
    for field_name in ("required_commands", "required_services", "conflicts_with"):
        values = getattr(capabilities, field_name)
        if any(not isinstance(value, str) or not value.strip() for value in values):
            errors.append(f"meta.{field_name} must contain non-empty strings")
    for method_name in (
        "install", "uninstall", "install_result", "uninstall_result",
        "enable_result", "disable_result", "status", "configure",
        "health_result", "snapshot", "rollback",
    ):
        if not callable(getattr(plugin, method_name, None)):
            errors.append(f"missing {method_name}()")
    return errors


def validate_contracts() -> None:
    """Fail fast when a registered plugin violates the static contract."""
    violations = {
        plugin.meta.name: errors
        for plugin in _PLUGINS
        if (errors := contract_errors(plugin))
    }
    if violations:
        raise ValueError(f"plugin contract violations: {violations}")


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
            validate_fragment(f)
            if not f.is_empty():
                fragments[p.meta.name] = f
        except Exception as e:
            from hydra.core.singbox import _log
            _log("ERROR", f"Error configuring plugin {p.meta.name}: {e}")
            raise PluginConfigurationError(p.meta.name, e) from e
    return fragments


def requirements(state: AppState) -> dict[str, dict[str, list[str]]]:
    """Return declarative host/dependency requirements for enabled plugins."""
    active = enabled(state)
    active_names = {plugin.meta.name for plugin in active}
    result: dict[str, dict[str, list[str]]] = {}
    for plugin in active:
        missing = sorted(
            command for command in plugin.meta.required_commands
            if HOST.which(command) is None
        )
        conflicts = sorted(
            name for name in plugin.meta.conflicts_with if name in active_names
        )
        if missing or conflicts:
            result[plugin.meta.name] = {
                "missing_commands": missing,
                "conflicts": conflicts,
            }
    return result


def apply_enabled(state: AppState) -> list[tuple[BasePlugin, object]]:
    """Apply the configuration prepared by every enabled plugin."""
    applied: list[tuple[BasePlugin, object]] = []
    transaction = ApplyTransaction()
    transaction.advance("snapshot")

    def log_rollback_error(message: str) -> None:
        from hydra.core.singbox import _log
        _log("ERROR", message)

    for plugin in enabled(state):
        if not _uses_central_apply(plugin):
            continue
        try:
            snapshot = plugin.snapshot(state)
        except Exception as exc:
            transaction.rollback(log_rollback_error)
            raise RuntimeError(f"Plugin {plugin.meta.name} apply failed: {exc}") from exc

        transaction.add_rollback(
            f"plugin {plugin.meta.name}",
            lambda plugin=plugin, snapshot=snapshot: plugin.rollback(state, snapshot),
            priority=-(len(applied) + 1),
        )
        transaction.advance("apply")
        try:
            apply_result = plugin.apply(state)
        except Exception as exc:
            transaction.rollback(log_rollback_error)
            raise RuntimeError(f"Plugin {plugin.meta.name} apply failed: {exc}") from exc
        if not apply_result:
            transaction.rollback(log_rollback_error)
            raise RuntimeError(f"Plugin {plugin.meta.name} apply returned false")
        applied.append((plugin, snapshot))
    transaction.commit()
    return applied


def status_all(state: AppState | None = None) -> dict[str, dict]:
    """Возвращает {name: {running, installed, port, enabled}} для всех плагинов."""
    result: dict[str, dict] = {}
    for p in _PLUGINS:
        try:
            s = p.status()
            desired_enabled = (
                state.protocols.get(p.meta.name).enabled
                if state is not None and state.protocols.get(p.meta.name)
                else s.enabled
            )
            result[p.meta.name] = {
                "running": s.running,
                "installed": s.installed,
                "port": s.port,
                "enabled": s.enabled,
                "error": "",
                **assess(s, desired_enabled).as_dict(),
            }
        except Exception as exc:
            # A broken optional service must not make the whole protocol
            # dashboard unusable.  Its own card will expose the failure.
            desired_enabled = (
                state.protocols.get(p.meta.name).enabled
                if state is not None and state.protocols.get(p.meta.name)
                else False
            )
            result[p.meta.name] = {
                "running": False,
                "installed": False,
                "port": 0,
                "enabled": False,
                "error": str(exc) or exc.__class__.__name__,
                **assess(
                    PluginStatus(installed=False, enabled=False, running=False),
                    desired_enabled,
                    str(exc) or exc.__class__.__name__,
                ).as_dict(),
            }
    return result


def health_all(state: AppState) -> dict[str, str]:
    """Return failures for enabled plugins without making apply side effects."""
    failures: dict[str, str] = {}
    for plugin in enabled(state):
        if not _uses_central_apply(plugin):
            continue
        try:
            health = plugin.health_result()
            healthy, detail = health.healthy, health.detail
        except Exception as exc:
            healthy, detail = False, str(exc) or exc.__class__.__name__
        if not healthy:
            failures[plugin.meta.name] = detail or "проверка не пройдена"
    return failures


# Обратная совместимость
get_all = all_plugins
get_enabled = enabled

