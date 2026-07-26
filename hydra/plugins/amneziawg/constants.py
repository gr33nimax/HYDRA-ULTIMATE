"""Stable AmneziaWG runtime defaults.

Mutable test seams for the two configuration paths intentionally live in
``plugin.py``.  Production helpers obtain those paths from the plugin instance
so callers that historically patched ``plugin.AWG_CONF`` keep working.
"""
from __future__ import annotations

from pathlib import Path


AWG_INSTALL_DIR = Path("/opt/awg-install")
AWG_BIN = Path("/usr/bin/awg")
AWG_CONF_DIR = Path("/etc/amnezia/amneziawg")
AWG_CONF = AWG_CONF_DIR / "awg0.conf"
AWG_CONF_1 = AWG_CONF_DIR / "awg1.conf"
AWG_PARAMS = AWG_CONF_DIR / "params"

AWG_INTERFACE = "awg0"
AWG_INTERFACE_1 = "awg1"
AWG_UNIT = "awg-quick@awg0"
AWG_UNIT_1 = "awg-quick@awg1"

DEFAULT_PORT = 51820
DEFAULT_PORT_1 = 51821
KNOWN_SUBNETS = ("10.66.66.0/16", "172.17.0.0/16")
PREFERRED_SUBNETS = ("10.67.67.0/24",)

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
OBFUSCATION_KEYS = (
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
)
OBFUSCATION_KEYS_EXTENDED = (*OBFUSCATION_KEYS, "I1")
