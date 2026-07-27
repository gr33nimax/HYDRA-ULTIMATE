"""Stable filesystem locations and catalogs used by the WARP plugin."""

from pathlib import Path

WGCF_BIN = Path("/usr/local/bin/wgcf")
WGCF_PROFILE = Path("/etc/wireguard/wgcf-profile.conf")
WGCF_ACCOUNT = Path("/etc/wireguard/wgcf-account.toml")
WARP_INTERFACE = "wgcf"
WARP_EXTERNAL_CACHE = Path("/var/lib/hydra/warp_external.json")
WARP_PROFILES_DIR = Path("/etc/hydra/warp_profiles")
WARP_INSTALL_LOG = Path("/var/log/hydra/warp_install.log")
RUSSIA_TLD_SUFFIXES = [".ru", ".su"]

DEFAULT_WARP_DOMAINS = [
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "chatgpt.com",
    "sora.com",
    "gemini.google.com",
    "bard.google.com",
]

EXTERNAL_LISTS = {
    "russia": {
        "name": "РФ-сервисы",
        "url": (
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/"
            "main/Russia/outside-raw.lst"
        ),
        "desc": (
            "Российские сервисы, доступные только с IP-адресов РФ "
            "(outside-raw.lst)"
        ),
    },
    "geoblock": {
        "name": "GEO-block",
        "url": (
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/"
            "main/Categories/geoblock.lst"
        ),
        "desc": "Заблокированные в РФ иностранные ресурсы (geoblock.lst)",
    },
    "google_ai": {
        "name": "GoogleAI",
        "url": (
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/"
            "main/Services/google_ai.lst"
        ),
        "desc": "Сервисы ИИ от Google: Gemini, AI Studio и др. (google_ai.lst)",
    },
}

__all__ = [
    "DEFAULT_WARP_DOMAINS",
    "EXTERNAL_LISTS",
    "RUSSIA_TLD_SUFFIXES",
    "WARP_EXTERNAL_CACHE",
    "WARP_INTERFACE",
    "WARP_INSTALL_LOG",
    "WARP_PROFILES_DIR",
    "WGCF_ACCOUNT",
    "WGCF_BIN",
    "WGCF_PROFILE",
]
