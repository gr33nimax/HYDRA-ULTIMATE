"""Composition root for the long-running AntiDPI collector."""
from __future__ import annotations

from hydra.core.state import load_state
from hydra.plugins.antidpi.agent import run
from hydra.plugins.antidpi.plugin import AntiDPIPlugin
from hydra.plugins.defaults import default_plugins
from hydra.services.security_intel import notification_fields
from hydra.services.security_notifications import notify_security_event


def production_plugin() -> AntiDPIPlugin:
    """Build the worker dependency without consulting a global registry."""
    plugin = next(
        (
            candidate
            for candidate in default_plugins(
                notifier=notify_security_event,
                security_context=notification_fields,
            )
            if isinstance(candidate, AntiDPIPlugin)
        ),
        None,
    )
    if plugin is None:
        raise RuntimeError("AntiDPI plugin is unavailable")
    return plugin


def main() -> None:
    run(production_plugin(), state_reader=load_state)


if __name__ == "__main__":
    main()
