"""Stable AmneziaWG defaults and the paths an older HYDRA wrote.

Mutable test seams for the legacy configuration paths intentionally live in ``plugin.py``: a host that
was never cut over may still carry those files, and they are what ``uninstall`` cleans up.
"""

from __future__ import annotations

from pathlib import Path

from .directives import LEGACY_DIRECTIVE_KEYS

AWG_INSTALL_DIR = Path("/opt/awg-install")
AWG_CONF_DIR = Path("/etc/amnezia/amneziawg")
AWG_CONF = AWG_CONF_DIR / "awg0.conf"
AWG_CONF_1 = AWG_CONF_DIR / "awg1.conf"
AWG_PARAMS = AWG_CONF_DIR / "params"

DEFAULT_PORT = 51820
DEFAULT_PORT_1 = 51821
DEFAULT_NETWORK = "10.67.67.0/24"
MOBILE_NETWORK = "10.68.68.0/24"
DEFAULT_MTU = "1376"
# One place that says which network a profile defaults to: the endpoint and every client artifact
# read it from here, so a profile cannot be served one subnet and handed another.
PROFILE_NETWORKS = {"desktop": DEFAULT_NETWORK, "mobile": MOBILE_NETWORK}
KNOWN_SUBNETS = ("10.66.66.0/16", "172.17.0.0/16")
PREFERRED_SUBNETS = (DEFAULT_NETWORK,)

# The tag each profile carries in the core configuration; the same label reaches the
# operator and the client artifacts.
ENDPOINT_TAG_DESKTOP = "awg-desktop"
ENDPOINT_TAG_MOBILE = "awg-mobile"

DEFAULT_OBFUSCATION = {
    "Jc": "5",
    "Jmin": "50",
    "Jmax": "150",
    "S1": "40",
    "S2": "120",
    "S3": "0",
    "S4": "4",
    "H1": "1847293",
    "H2": "839102847",
    "H3": "49182736",
    "H4": "129384756",
}
OBFUSCATION_KEYS = LEGACY_DIRECTIVE_KEYS[:-1]
OBFUSCATION_KEYS_EXTENDED = LEGACY_DIRECTIVE_KEYS
