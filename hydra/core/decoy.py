"""Stable facade for static decoy-site generation."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import builder, registry
from hydra.core.decoy_sites.identity import build_identity


DECOY_DIRS = {
    "naive": Path("/var/www/decoy-a"),
    "anytls": Path("/var/www/decoy-b"),
    "trusttunnel": Path("/var/www/decoy-c"),
    "hysteria2": Path("/var/www/decoy-hysteria2"),
}

DEFAULT_THEMES = {
    "naive": "landing",
    "anytls": "blog",
    "trusttunnel": "docs",
    "hysteria2": "status",
}
# Historical alias kept for callers written before themes became configurable.
DECOY_THEMES = DEFAULT_THEMES
SUPPORTED_THEMES = frozenset(registry.THEME_NAMES)


def default_theme(plugin_name: str) -> str:
    """Return the theme a plugin serves when the operator picked none."""
    return DEFAULT_THEMES.get(plugin_name, "landing")


def ensure_decoy_site(
    plugin_name: str,
    theme: str = "",
    *,
    domain: str = "",
) -> Path:
    """Publish a plugin's decoy site and return its directory."""
    site_dir = DECOY_DIRS.get(plugin_name)
    if site_dir is None:
        raise ValueError(f"Unknown plugin for decoy: {plugin_name}")
    return ensure_site(
        site_dir,
        theme or default_theme(plugin_name),
        domain=domain,
    )


def ensure_site(site_dir: Path | str, theme: str, *, domain: str = "") -> Path:
    """Publish one validated decoy site, rebuilding it when it drifted."""
    selected = registry.get_theme(theme)
    path = Path(site_dir)
    normalized = path.as_posix()
    if (
        not path.is_absolute()
        or not normalized.startswith("/var/www/decoy-")
        or ".." in path.parts
        or path.is_symlink()
    ):
        raise ValueError("Decoy site must be under /var/www/decoy-*")
    identity = build_identity(domain or path.name)
    if not builder.is_current(path, selected.name, identity):
        builder.build(path, selected.name, selected.render, identity)
    return path


__all__ = [
    "DECOY_DIRS",
    "DECOY_THEMES",
    "DEFAULT_THEMES",
    "SUPPORTED_THEMES",
    "default_theme",
    "ensure_decoy_site",
    "ensure_site",
]
