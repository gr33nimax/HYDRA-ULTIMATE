"""Thin compatibility facade for the modular NaiveProxy plugin."""
from __future__ import annotations

import shutil as shutil  # compatibility monkeypatch seam
import time as time  # compatibility monkeypatch seam
from pathlib import Path

from hydra.contracts import BackupResource
from hydra.core.host import HOST as HOST
from hydra.core.state_models import User as User
from hydra.plugins.base import (
    BasePlugin as BasePlugin,
    ConfigFragment as ConfigFragment,
    PluginCategory as PluginCategory,
    PluginMeta as PluginMeta,
    PluginStatus as PluginStatus,
)
from hydra.utils.crypto import derive_hex_key as derive_hex_key
from hydra.utils.downloader import (
    download_github_asset as download_github_asset,
    verify_elf as verify_elf,
)
from hydra.utils.tls import resolve_tls_material as resolve_tls_material

from .access_logs import NaiveAccessLogMixin
from .configuration import NaiveConfigurationMixin
from .constants import (
    BIN_PATH as BIN_PATH,
    CADDYFILE as CADDYFILE,
    CFG_DIR as CFG_DIR,
    DATA_DIR as DATA_DIR,
    DEFAULT_PORT as DEFAULT_PORT,
    FAKE_SITE_DIR as FAKE_SITE_DIR,
    GITHUB_REPO as GITHUB_REPO,
    LOG_DIR as LOG_DIR,
    SERVICE_FILE as SERVICE_FILE,
    SERVICE_NAME as SERVICE_NAME,
    NaiveRuntimeLayout,
)
from hydra.plugins.decoy_support import DecoyThemeSupport

from .installation import NaiveInstallationMixin
from .observation import NaiveObservationMixin
from .profiles import NaiveProfilesMixin
from .runtime import NaiveRuntimeMixin


class NaivePlugin(
    DecoyThemeSupport,
    NaiveInstallationMixin,
    NaiveRuntimeMixin,
    NaiveConfigurationMixin,
    NaiveProfilesMixin,
    NaiveAccessLogMixin,
    NaiveObservationMixin,
    BasePlugin,
):
    """Coordinate cohesive NaiveProxy capabilities behind the plugin API."""

    decoy_default_theme = "landing"

    meta = PluginMeta(
        name="naive",
        description=(
            "NaiveProxy: Caddy + forwardproxy, Chromium HTTP/2 fingerprint"
        ),
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=True,
        required_commands=("systemctl",),
        commands=("set_domain", "set_transport", "set_decoy_theme"),
        queries=("recent_connections",),
        tls_domain_source="network",
        config_defaults=(
            ("network", "tcp"),
            ("decoy_theme", "landing"),
        ),
        connection_source="recent_connections",
        backup_resources=(
            BackupResource(str(CFG_DIR), "tree"),
            BackupResource(str(SERVICE_FILE), "file"),
        ),
    )

    def __init__(self) -> None:
        self._pending_cfg: str | None = None

    @staticmethod
    def _runtime_layout() -> NaiveRuntimeLayout:
        """Resolve old module-level constants at call time for compatibility."""
        return NaiveRuntimeLayout(
            binary=BIN_PATH,
            config_dir=CFG_DIR,
            caddyfile=CADDYFILE,
            log_dir=LOG_DIR,
            data_dir=DATA_DIR,
            fake_site_dir=FAKE_SITE_DIR,
            service_file=SERVICE_FILE,
            service_name=SERVICE_NAME,
            default_port=DEFAULT_PORT,
            github_repo=GITHUB_REPO,
        )

    @staticmethod
    def _host_backend():
        return HOST

    @staticmethod
    def _installed() -> bool:
        return (
            BIN_PATH.exists()
            or shutil.which("caddy-naive") is not None
        )

    @staticmethod
    def _download_asset(
        repository: str,
        pattern: str,
        destination: Path,
    ) -> bool:
        return download_github_asset(repository, pattern, destination)

    @staticmethod
    def _verify_binary(path: Path) -> bool:
        return verify_elf(path)

    @staticmethod
    def _resolve_tls_material(
        domain: str,
        config: dict,
    ) -> tuple[str, str]:
        return resolve_tls_material(domain, config)


__all__ = [
    "BIN_PATH",
    "CADDYFILE",
    "CFG_DIR",
    "DATA_DIR",
    "DEFAULT_PORT",
    "FAKE_SITE_DIR",
    "GITHUB_REPO",
    "LOG_DIR",
    "NaivePlugin",
    "SERVICE_FILE",
    "SERVICE_NAME",
]
