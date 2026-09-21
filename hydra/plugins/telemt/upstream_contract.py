"""Pinned, reviewable Telemt upstream 3.5.7 compatibility contract."""

from __future__ import annotations

RELEASE_TAG = "3.5.7"

RELEASE_ARCHIVES = {
    "aarch64": {
        "gnu": "telemt-aarch64-linux-gnu.tar.gz",
        "musl": "telemt-aarch64-linux-musl.tar.gz",
    },
    "x86_64": {
        "gnu": "telemt-x86_64-linux-gnu.tar.gz",
        "musl": "telemt-x86_64-linux-musl.tar.gz",
    },
    "x86_64_v3": {
        "gnu": "telemt-x86_64-v3-linux-gnu.tar.gz",
        "musl": "telemt-x86_64-v3-linux-musl.tar.gz",
    },
}

UPSTREAM_TOML_PATHS = frozenset(
    {
        "log_level",
        "general.use_middle_proxy",
        "general.modes.classic",
        "general.modes.secure",
        "general.modes.tls",
        "general.links.show",
        "server.port",
        "server.log_level",
        "server.listeners.ip",
        "server.api.enabled",
        "server.api.listen",
        "server.api.whitelist",
        "server.api.minimal_runtime_enabled",
        "server.api.minimal_runtime_cache_ttl_ms",
        "censorship.tls_domain",
        "censorship.mask",
        "censorship.tls_emulation",
        "censorship.tls_front_dir",
        "access.users",
    }
)


def release_archive(
    architecture: str,
    *,
    libc: str = "gnu",
    supports_v3: bool = False,
) -> str:
    """Return one exact release archive for a supported target."""
    target = "x86_64_v3" if architecture == "x86_64" and supports_v3 else architecture
    try:
        return RELEASE_ARCHIVES[target][libc]
    except KeyError as exc:
        raise ValueError(f"unsupported Telemt target: {architecture}/{libc}") from exc


def unsupported_toml_paths(paths: set[str]) -> set[str]:
    """Return fields not present in the pinned upstream configuration contract."""
    return paths - UPSTREAM_TOML_PATHS
