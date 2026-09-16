"""AmneziaWG plugin façade.

The public plugin API remains on this class while cohesive production mixins own configuration
rendering, desired profiles, client serialization, readiness, and observation. The core terminates the
tunnel; there is no host-side runtime to reconcile.
"""

from __future__ import annotations

import subprocess as subprocess  # compatibility monkeypatch seam

from hydra.contracts import BackupResource
from hydra.core.host import HOST as HOST  # compatibility monkeypatch seam
from hydra.plugins.base import BasePlugin, PluginCategory, PluginMeta

from .client_links import AwgClientLinksMixin
from .configuration import AwgConfigurationMixin
from .projection import AwgProjectionMixin
from .constants import (
    AWG_CONF as AWG_CONF,
    AWG_CONF_1 as AWG_CONF_1,
    AWG_CONF_DIR as AWG_CONF_DIR,
    AWG_INSTALL_DIR as AWG_INSTALL_DIR,
    AWG_PARAMS as AWG_PARAMS,
    DEFAULT_OBFUSCATION as DEFAULT_OBFUSCATION,
    DEFAULT_PORT as DEFAULT_PORT,
    DEFAULT_PORT_1 as DEFAULT_PORT_1,
    ENDPOINT_TAG_DESKTOP as ENDPOINT_TAG_DESKTOP,
    ENDPOINT_TAG_MOBILE as ENDPOINT_TAG_MOBILE,
    KNOWN_SUBNETS,
    OBFUSCATION_KEYS as _OBFUSCATION_KEYS,
    OBFUSCATION_KEYS_EXTENDED as _OBFUSCATION_KEYS_EXTENDED,
    PREFERRED_SUBNETS,
)
from .installation import AwgInstallationMixin
from .observation import AwgObservationMixin
from .profiles import AwgProfileMixin
from .protocol_mode import AwgProtocolModeMixin


# These names existed in the original module. Keep their values and mutability
# compatible for integrations that imported them directly.
_KNOWN_SUBNETS = list(KNOWN_SUBNETS)
_PREFERRED_SUBNETS = list(PREFERRED_SUBNETS)
OBFUSCATION_KEYS = list(_OBFUSCATION_KEYS)
OBFUSCATION_KEYS_EXTENDED = list(_OBFUSCATION_KEYS_EXTENDED)


class AmneziaWGPlugin(
    AwgInstallationMixin,
    AwgConfigurationMixin,
    AwgProjectionMixin,
    AwgProfileMixin,
    AwgProtocolModeMixin,
    AwgClientLinksMixin,
    AwgObservationMixin,
    BasePlugin,
):
    """Coordinate the AmneziaWG capabilities behind the plugin contract."""

    meta = PluginMeta(
        name="amneziawg",
        description=("AmneziaWG 2.0: WireGuard с обфускацией (обслуживает ядро)"),
        category=PluginCategory.TRANSPORT,
        version="3.0.0",
        needs_domain=False,
        commands=(
            "add_profile",
            "remove_profile",
            "rotate_obfuscation",
            "set_protocol_mode",
        ),
        queries=("amnezia_link", "get_profiles", "protocol_mode_status"),
        subscription_profile_query="get_profiles",
        backup_resources=(BackupResource(str(AWG_CONF_DIR), "tree"),),
    )
