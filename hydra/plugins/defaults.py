"""Built-in plugin composition, kept separate from the neutral catalog."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin
from hydra.plugins.antidpi.plugin import AntiDPIPlugin
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.base import BasePlugin
from hydra.plugins.dnscrypt.plugin import DNSCryptPlugin
from hydra.plugins.fail2ban.plugin import Fail2banPlugin
from hydra.plugins.honeypot.plugin import HoneypotPlugin
from hydra.plugins.hysteria2.plugin import Hysteria2Plugin
from hydra.plugins.ipban.plugin import IPBanPlugin
from hydra.plugins.mieru.plugin import MieruPlugin
from hydra.plugins.naive.plugin import NaivePlugin
from hydra.plugins.shadowtls.plugin import ShadowTLSPlugin
from hydra.plugins.snell.plugin import SnellPlugin
from hydra.plugins.telemt.plugin import TelemtPlugin
from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin
from hydra.plugins.warp.plugin import WarpPlugin
from hydra.plugins.wdtt.plugin import WdttPlugin


PluginFactory = Callable[[], BasePlugin]

BUILTIN_PLUGIN_FACTORIES: tuple[PluginFactory, ...] = (
    AmneziaWGPlugin,
    AnyTLSPlugin,
    TrustTunnelPlugin,
    ShadowTLSPlugin,
    Hysteria2Plugin,
    SnellPlugin,
    MieruPlugin,
    NaivePlugin,
    TelemtPlugin,
    WdttPlugin,
    DNSCryptPlugin,
    WarpPlugin,
    Fail2banPlugin,
    HoneypotPlugin,
    IPBanPlugin,
)


def default_plugins(
    *,
    notifier: Any = None,
    security_context: Any = None,
    extra_factories: Iterable[PluginFactory] = (),
) -> list[BasePlugin]:
    """Compose built-ins while allowing an outer composition root to extend."""
    plugins = [factory() for factory in BUILTIN_PLUGIN_FACTORIES]
    honeypot = next(
        plugin
        for plugin in plugins
        if isinstance(plugin, HoneypotPlugin)
    )
    plugins.append(
        AntiDPIPlugin(
            notifier=notifier,
            honeypot_bans=honeypot.banned_addresses,
            security_context=security_context,
        ),
    )
    plugins.extend(factory() for factory in extra_factories)
    return plugins


__all__ = [
    "AmneziaWGPlugin",
    "AntiDPIPlugin",
    "AnyTLSPlugin",
    "BUILTIN_PLUGIN_FACTORIES",
    "DNSCryptPlugin",
    "Fail2banPlugin",
    "HoneypotPlugin",
    "Hysteria2Plugin",
    "IPBanPlugin",
    "MieruPlugin",
    "NaivePlugin",
    "PluginFactory",
    "ShadowTLSPlugin",
    "SnellPlugin",
    "TelemtPlugin",
    "TrustTunnelPlugin",
    "WarpPlugin",
    "WdttPlugin",
    "default_plugins",
]
