"""Read-only status for AmneziaWG, whose tunnel the core serves.

Kernel counters are gone with the interface: per-user traffic arrives through the core's connection
tracker, attributed by the peer's tunnel address, so nothing here shells out to a tool that no longer
exists.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess


class AwgObservationMixin:
    """Observe the core's state without mutating desired or runtime state."""

    if TYPE_CHECKING:

        def __getattr__(self, name: str) -> Any:
            """Static dependency seam for observation."""
            ...

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        installed = self._installed()
        enabled = False
        if state is not None:
            protocol = state.protocols.get("amneziawg")
            if protocol:
                installed = bool(protocol.installed and installed)
                enabled = bool(protocol.enabled and installed)
        port = self._profile_port(state, "desktop") if installed and state is not None else 0
        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=enabled and _core_running(),
            port=port,
        )


def _core_running() -> bool:
    """Whether the core that terminates the tunnel is up."""
    try:
        from hydra.core.singbox import is_running
    except Exception:  # noqa: BLE001 - an unimportable core is not a running core
        return False
    return bool(is_running())
