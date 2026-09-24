"""Stable filesystem locations and catalogs used by the WARP plugin."""

from pathlib import Path

WARP_EXTERNAL_CACHE = Path("/var/lib/hydra/warp_external.json")
WARP_PROFILES_DIR = Path("/etc/hydra/warp_profiles")
WARP_CATALOG_CACHE = Path("/var/lib/hydra/warp_catalog.json")
RUSSIA_TLD_SUFFIXES = [".ru", ".su", ".рф", ".xn--p1ai"]

# The rule catalogue is published as data and cached locally, so a service added
# upstream reaches the operator without a HYDRA release.
CATALOG_URL = "https://raw.githubusercontent.com/Ground-Zerro/Geo-Aggregator/main/db/catalog.json"
CATALOG_BASE = "https://raw.githubusercontent.com/Ground-Zerro/Geo-Aggregator/main/"

# Only individual services are routable. The upstream rollups overlap them and
# made a seemingly precise choice route unrelated destinations as well.
EXTRA_SOURCES: dict[str, dict[str, str]] = {}
EXTERNAL_LISTS: dict[str, dict[str, str]] = {}


def is_granular_source(key: str) -> bool:
    name = key.lower()
    return name not in {"refilter", "antifilter"} and not name.startswith(("category-", "itdog-"))


# Files an older HYDRA release installed for the wgcf transport. The transport no
# longer uses them, but an updated host still carries a downloaded binary and a
# live Cloudflare credential in them, so uninstall removes them.
LEGACY_WGCF_PATHS = (
    Path("/usr/local/bin/wgcf"),
    Path("/etc/wireguard/wgcf-profile.conf"),
    Path("/etc/wireguard/wgcf-account.toml"),
    Path("/var/log/hydra/warp_install.log"),
)

DEFAULT_WARP_DOMAINS = [
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "chatgpt.com",
    "sora.com",
    "gemini.google.com",
    "bard.google.com",
]

__all__ = [
    "CATALOG_BASE",
    "CATALOG_URL",
    "DEFAULT_WARP_DOMAINS",
    "EXTERNAL_LISTS",
    "EXTRA_SOURCES",
    "LEGACY_WGCF_PATHS",
    "RUSSIA_TLD_SUFFIXES",
    "is_granular_source",
    "WARP_CATALOG_CACHE",
    "WARP_EXTERNAL_CACHE",
    "WARP_PROFILES_DIR",
]
