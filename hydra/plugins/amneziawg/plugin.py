"""AmneziaWG plugin façade.

The public plugin API remains on this class while cohesive production mixins
own configuration rendering, desired profiles, client serialization, host
installation, runtime reconciliation, and observation.
"""
from __future__ import annotations

import subprocess as subprocess  # compatibility monkeypatch seam
from pathlib import Path

from hydra.contracts import BackupResource
from hydra.core.host import HOST as HOST  # compatibility monkeypatch seam
from hydra.plugins.base import BasePlugin, PluginCategory, PluginMeta

from .client_links import AwgClientLinksMixin
from .configuration import AwgConfigurationMixin
from .constants import (
    AWG_BIN as AWG_BIN,
    AWG_CONF as AWG_CONF,
    AWG_CONF_1 as AWG_CONF_1,
    AWG_CONF_DIR as AWG_CONF_DIR,
    AWG_INSTALL_DIR as AWG_INSTALL_DIR,
    AWG_INTERFACE as AWG_INTERFACE,
    AWG_INTERFACE_1 as AWG_INTERFACE_1,
    AWG_PARAMS as AWG_PARAMS,
    AWG_UNIT as AWG_UNIT,
    AWG_UNIT_1 as AWG_UNIT_1,
    DEFAULT_OBFUSCATION as DEFAULT_OBFUSCATION,
    DEFAULT_PORT as DEFAULT_PORT,
    DEFAULT_PORT_1 as DEFAULT_PORT_1,
    KNOWN_SUBNETS,
    OBFUSCATION_KEYS as _OBFUSCATION_KEYS,
    OBFUSCATION_KEYS_EXTENDED as _OBFUSCATION_KEYS_EXTENDED,
    PREFERRED_SUBNETS,
)
from .installation import AwgInstallationMixin
from .observation import AwgObservationMixin
from .profiles import AwgProfileMixin
from .runtime import AwgRuntimeMixin


# These names existed in the original module. Keep their values and mutability
# compatible for integrations that imported them directly.
_KNOWN_SUBNETS = list(KNOWN_SUBNETS)
_PREFERRED_SUBNETS = list(PREFERRED_SUBNETS)
OBFUSCATION_KEYS = list(_OBFUSCATION_KEYS)
OBFUSCATION_KEYS_EXTENDED = list(_OBFUSCATION_KEYS_EXTENDED)


class AmneziaWGPlugin(
    AwgInstallationMixin,
    AwgConfigurationMixin,
    AwgProfileMixin,
    AwgClientLinksMixin,
    AwgObservationMixin,
    AwgRuntimeMixin,
    BasePlugin,
):
    """Coordinate the AmneziaWG capabilities behind the plugin contract."""

    meta = PluginMeta(
        name="amneziawg",
        description=(
            "AmneziaWG 2.0: WireGuard с обфускацией (kernel-модуль)"
        ),
        category=PluginCategory.TRANSPORT,
        version="2.1.0",
        needs_domain=False,
        commands=(
            "add_profile",
            "remove_profile",
            "rotate_obfuscation",
        ),
        queries=("amnezia_link", "get_profiles"),
        subscription_profile_query="get_profiles",
        backup_resources=(
            BackupResource(str(AWG_CONF_DIR), "tree"),
        ),
    )

    def __init__(self) -> None:
        self._pending_conf: str | None = None
        self._pending_conf_1: str | None = None
        self._peer_map: dict[str, tuple[str, str]] = {}

    def traffic_snapshot(self, state):
        """Expose raw interface counters to generic accounting."""
        return self.traffic(state)

    @staticmethod
    def _conf_path(profile_name: str) -> Path:
        """Resolve legacy patchable path seams at the façade boundary."""
        return AWG_CONF_1 if profile_name == "mobile" else AWG_CONF
