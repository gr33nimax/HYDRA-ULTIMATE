"""Narrow state contracts exposed to plugins.

``AppState`` remains the persisted aggregate root.  Plugins intentionally see
only the protocol, user and network slices they currently need; application
settings, Telegram configuration and security policy stay outside this port.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from hydra.core.state_models import NetworkConfig, PluginState, User


@runtime_checkable
class PluginStateAccess(Protocol):
    """Structural v1 state port implemented by ``AppState``."""

    protocols: dict[str, PluginState]
    users: list[User]
    network: NetworkConfig
