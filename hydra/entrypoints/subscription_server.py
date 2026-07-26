"""Executable adapter for the HTTPS subscription server."""
from __future__ import annotations

import argparse

from hydra.bootstrap import production_application
from hydra.services.subscriptions import SubscriptionPluginService
from hydra.services.subscriptions.server import run_standalone


def main() -> None:
    parser = argparse.ArgumentParser(description="HYDRA Subscription Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    arguments = parser.parse_args()

    protocols = production_application().protocols
    plugins = SubscriptionPluginService(
        enabled_plugins=protocols.enabled,
        get_plugin=protocols.get,
        invoker=protocols.invoker,
    )
    run_standalone(plugins, arguments.host, arguments.port)


if __name__ == "__main__":
    main()
