"""Cover site published on the dedicated WEB domain (R15).

Upstream's relay answers a bare ``404 Not Found`` when no public site is
configured, so a browser on the operator-owned WEB domain would see a broken
host. The site is generated from the shared decoy themes into a Hydra-owned
directory, and ``[web] public_dir`` is rendered only after that generation
actually succeeded.
"""

from __future__ import annotations

from hydra.plugins.context import PluginStateAccess

from . import configuration

PLUGIN_NAME = "mtproto_zig"


def _config(state: PluginStateAccess) -> dict:
    protocol = state.protocols.get(PLUGIN_NAME)
    return dict(protocol.config) if protocol else {}


def plan(state: PluginStateAccess, theme: str) -> tuple[str, str, str]:
    """Return ``(config, public_dir, failure)`` for an active WEB mode.

    A generation failure must not fail the transport apply: the relay works
    without a site, so the config is rendered without ``public_dir`` and the
    reason is handed back for status and health.
    """
    from hydra.core.decoy import ensure_decoy_site

    domain = configuration.web_domain(_config(state))
    # Validate the WEB configuration before touching the host: an invalid desired
    # state fails closed instead of publishing a site for an empty domain.
    without_site, _fragment = configuration.plan_configuration(state)
    try:
        directory = str(ensure_decoy_site(PLUGIN_NAME, theme, domain=domain))
    except (OSError, ValueError) as exc:
        reason = f"сайт-заглушка WEB не сгенерирован: {exc}"
        return without_site, "", reason
    rendered, _fragment = configuration.plan_configuration(state, public_dir=directory)
    return rendered, directory, ""


__all__ = ["PLUGIN_NAME", "plan"]
