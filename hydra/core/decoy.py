"""Stable facade for static decoy-site generation."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites.blog import generate as _generate_blog
from hydra.core.decoy_sites.bootstrap import prepare_site as _prepare_site
from hydra.core.decoy_sites.docs import generate as _generate_docs
from hydra.core.decoy_sites.landing import generate as _generate_landing
from hydra.core.decoy_sites.status import generate as _generate_status


DECOY_DIRS = {
    "naive": Path("/var/www/decoy-a"),
    "anytls": Path("/var/www/decoy-b"),
    "trusttunnel": Path("/var/www/decoy-c"),
    "hysteria2": Path("/var/www/decoy-hysteria2"),
}

DECOY_THEMES = {
    "naive": "landing",
    "anytls": "blog",
    "trusttunnel": "docs",
    "hysteria2": "status",
}


def ensure_decoy_site(plugin_name: str) -> Path:
    """Create a plugin's decoy site when needed and return its directory."""
    site_dir = DECOY_DIRS.get(plugin_name)
    theme = DECOY_THEMES.get(plugin_name)
    if not site_dir or not theme:
        raise ValueError(f"Unknown plugin for decoy: {plugin_name}")

    if not (site_dir / "index.html").exists():
        _create_site(site_dir, theme)
    return site_dir


def _create_site(site_dir: Path, theme: str) -> None:
    """Bootstrap shared files and dispatch to the selected theme renderer."""
    _prepare_site(site_dir)
    if theme == "landing":
        _generate_landing(site_dir)
    elif theme == "blog":
        _generate_blog(site_dir)
    elif theme == "docs":
        _generate_docs(site_dir)
    elif theme == "status":
        _generate_status(site_dir)
