"""Pure ipset/iptables constants for the AntiScan ban path.

AntiScan owns exactly one enforcement mechanism: the IPv4/IPv6 ban sets and
the DROP rules that read them.  The former scan/UDP/Mieru telemetry rules are
gone; their names survive here only so an upgraded host can remove the rules a
previous version installed.
"""

from __future__ import annotations

SET_V4, SET_V6 = "hydra_antidpi", "hydra_antidpi6"
RULE_COMMENT = "hydra-antidpi"

# Obsolete AntiDPI-owned telemetry.  Reconciliation deletes any rule carrying
# these comments or prefixes so the contraction actually reaches the host.
OBSOLETE_RULE_COMMENTS = (
    "hydra-antidpi-scan",
    "hydra-antidpi-udp-probes",
    "hydra-antidpi-mieru-probes",
)
OBSOLETE_UDP_PROBE_CHAIN = "HYDRA_ANTIDPI_UDP"
OBSOLETE_LOG_PREFIXES = (
    "HYDRA_SCAN_TCP ",
    "HYDRA_SCAN_UDP ",
    "HYDRA_UDP_PROBE ",
    "HYDRA_MIERU_SHORT ",
)
