"""Compatibility alias for :mod:`hydra.ui.plugin_managers.telemt`."""
from __future__ import annotations

import sys

from hydra.ui.plugin_managers import telemt as _implementation


class _InstallProtocols:
    """Select repair vs first install while keeping the UI operation modular."""

    def __init__(self, protocols, admin) -> None:
        self._protocols = protocols
        self._admin = admin

    def __getattr__(self, name):
        return getattr(self._protocols, name)

    def install(self, state, name: str) -> bool:
        protocol = state.protocols.get(name)
        if protocol is None:
            return self._protocols.install(state, name)
        was_installed = protocol.installed
        # Do not let install() apply an empty pending config for an enabled
        # Telemt instance.  enable() below owns the centralized apply.
        protocol.enabled = False
        self._admin.save_state(state)
        if was_installed:
            return self._protocols.reinstall(state, name)
        return self._protocols.install(state, name)


class _InstallApplication:
    def __init__(self, app) -> None:
        self._app = app
        self.protocols = _InstallProtocols(app.protocols, app.admin)

    def __getattr__(self, name):
        return getattr(self._app, name)


_run_install = _implementation._run_install


def _release_compatible_install(state, app) -> None:
    return _run_install(state, _InstallApplication(app))


_implementation._run_install = _release_compatible_install
sys.modules[__name__] = _implementation
