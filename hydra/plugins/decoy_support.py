"""Shared decoy-theme command for protocols that publish a decoy site."""
from __future__ import annotations

from hydra.core.decoy_sites.registry import get_theme
from hydra.plugins.context import PluginStateAccess


DECOY_THEME_KEY = "decoy_theme"


class DecoyThemeSupport:
    """Mixin giving a plugin one operator-selectable decoy site.

    A plugin opts in by declaring ``set_decoy_theme`` in ``PluginMeta.commands``
    and a ``decoy_theme`` default in ``config_defaults``. Adapters discover the
    capability from the metadata instead of matching plugin names.
    """

    decoy_default_theme = "landing"

    def set_decoy_theme(
        self,
        state: PluginStateAccess,
        theme: str,
    ) -> bool:
        """Select the site served on this protocol's TLS domain."""
        normalized = get_theme(theme).name
        protocol = state.protocols.get(self.meta.name)
        if protocol is None:
            return False
        protocol.config[DECOY_THEME_KEY] = normalized
        return True

    def decoy_theme(self, state: PluginStateAccess) -> str:
        """Return the configured decoy theme, or the plugin default."""
        protocol = state.protocols.get(self.meta.name)
        configured = (
            str(protocol.config.get(DECOY_THEME_KEY, "")).strip()
            if protocol is not None
            else ""
        )
        return configured or self.decoy_default_theme


def supports_decoy_theme(plugin: object) -> bool:
    """Report whether a plugin declares the decoy theme command."""
    capabilities = getattr(getattr(plugin, "meta", None), "capabilities", None)
    return "set_decoy_theme" in tuple(getattr(capabilities, "commands", ()))


__all__ = ["DECOY_THEME_KEY", "DecoyThemeSupport", "supports_decoy_theme"]
