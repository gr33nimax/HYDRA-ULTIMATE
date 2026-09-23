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

# Published in the raw tag index but not curated into db/catalog.json. These are
# the lists this plugin needs most: resources that only work from a foreign
# address, which is what WARP provides.
EXTRA_SOURCES = {
    "refilter": {
        "name": "Реестр РКН",
        "url": CATALOG_BASE + "source2/refilter.txt",
        "desc": "Заблокированное в РФ",
        "group": "blocked",
    },
    "antifilter": {
        "name": "Антифильтр (IP)",
        "url": CATALOG_BASE + "source1/antifilter.txt",
        "desc": "Заблокированные IP-диапазоны",
        "group": "blocked",
    },
}

# Builtin copy of the catalogue used before the first refresh and by install
# preloading: a fresh host must be able to route something without a network
# round trip to GitHub.
EXTERNAL_LISTS = {
    **EXTRA_SOURCES,
    "category-ru": {
        "name": "Все российские сервисы",
        "url": CATALOG_BASE + "source1/category-ru.txt",
        "desc": "Российские сервисы",
        "group": "ru",
    },
    "category-ai": {
        "name": "Все AI-сервисы",
        "url": CATALOG_BASE + "source1/category-ai.txt",
        "desc": "AI",
        "group": "ai",
    },
}

# The source whose rule also carries the Russian TLDs: ``list_targets`` routes it
# somewhere, and every ``.ru``/``.su`` domain follows it.
RU_TLD_SOURCE = "category-ru"

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
    "RU_TLD_SOURCE",
    "RUSSIA_TLD_SUFFIXES",
    "WARP_CATALOG_CACHE",
    "WARP_EXTERNAL_CACHE",
    "WARP_PROFILES_DIR",
]
