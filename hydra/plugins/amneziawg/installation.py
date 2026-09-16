"""AmneziaWG readiness.

The core terminates the tunnel itself, so there is no module to build, no package to install and
nothing to clone. What is left here is the capability check ("is the core there to serve it") and
the cleanup of artifacts an older HYDRA left on the host.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .constants import AWG_CONF, AWG_CONF_1, AWG_INSTALL_DIR, AWG_PARAMS

if TYPE_CHECKING:
    from hydra.core.state_models import User
    from hydra.plugins.context import PluginStateAccess


def _core_present() -> bool:
    """Whether the installed core is there to serve AmneziaWG itself."""
    try:
        from hydra.core.singbox import is_installed
    except Exception:  # noqa: BLE001 - an unimportable core is a missing core
        return False
    return bool(is_installed())


def _legacy_artifacts() -> tuple[Path, ...]:
    """Files an installer-era HYDRA wrote here. The core reads none of them."""
    return (AWG_CONF, AWG_CONF_1, AWG_PARAMS, AWG_INSTALL_DIR)


class AwgInstallationMixin:
    """Report readiness and leave the host otherwise alone."""

    if TYPE_CHECKING:

        def generate_client_config(
            self,
            user: "User",
            state: "PluginStateAccess",
            profile: str | None = None,
        ) -> str:
            """Rendered client configuration, provided by the client-links mixin."""
            ...

    def install(self) -> bool:
        if not _core_present():
            print("  HydraCore не установлен: обслуживать AmneziaWG нечем")
            return False
        print("  AmneziaWG обслуживается ядром: устанавливать нечего")
        return True

    def uninstall(self) -> bool:
        removed = False
        for path in _legacy_artifacts():
            if not path.exists():
                continue
            _remove(path)
            removed = True
        if removed:
            print("  Остатки прежней схемы удалены")
        print("  AmneziaWG обслуживается ядром: пакеты, модуль и юниты не трогаем")
        return True

    @staticmethod
    def _installed() -> bool:
        """Whether AmneziaWG is available here: the core terminates the tunnel."""
        return _core_present()


def _remove(path: Path) -> None:
    if path.is_dir():
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_file() or child.is_symlink():
                child.unlink(missing_ok=True)
            elif child.is_dir():
                child.rmdir()
        path.rmdir()
        return
    path.unlink(missing_ok=True)
