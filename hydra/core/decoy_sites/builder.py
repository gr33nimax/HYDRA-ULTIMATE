"""Reproducible, atomically swapped decoy-site generation."""
from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.bootstrap import prepare_site
from hydra.core.decoy_sites.identity import SiteIdentity


MARKER_NAME = ".hydra-decoy.json"

Renderer = Callable[[Path, SiteIdentity], None]


def _marker(site_dir: Path) -> dict[str, str]:
    try:
        payload = json.loads(
            (site_dir / MARKER_NAME).read_text(encoding="utf-8"),
        )
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def is_current(site_dir: Path, theme: str, identity: SiteIdentity) -> bool:
    """Report whether the published site already matches theme and identity.

    A site without our marker was put there by the operator; it is treated as
    current so a hand-maintained page is never silently replaced.
    """
    if not (site_dir / "index.html").exists():
        return False
    marker = _marker(site_dir)
    if not marker:
        return True
    return (
        marker.get("theme") == theme
        and marker.get("identity") == identity.fingerprint
    )


def build(
    site_dir: Path,
    theme: str,
    render: Renderer,
    identity: SiteIdentity,
) -> None:
    """Render the site into a staging directory, then swap it into place.

    Publishing is a rename, so a visitor never observes a half-written site,
    and a failed render leaves the previous site untouched.
    """
    staging = site_dir.with_name(f"{site_dir.name}.staging")
    previous = site_dir.with_name(f"{site_dir.name}.previous")
    shutil.rmtree(staging, ignore_errors=True)
    try:
        prepare_site(staging, identity)
        render(staging, identity)
        kit.write_robots(staging, identity)
        kit.write_text(
            staging,
            MARKER_NAME,
            json.dumps(
                {
                    "theme": theme,
                    "identity": identity.fingerprint,
                    "domain": identity.domain,
                },
                indent=2,
            )
            + "\n",
        )
        _publish(site_dir, staging, previous)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(previous, ignore_errors=True)


def _publish(site_dir: Path, staging: Path, previous: Path) -> None:
    shutil.rmtree(previous, ignore_errors=True)
    replaced = False
    if site_dir.exists():
        os.rename(site_dir, previous)
        replaced = True
    try:
        os.rename(staging, site_dir)
    except OSError:
        if replaced:
            os.rename(previous, site_dir)
        raise


__all__ = ["MARKER_NAME", "Renderer", "build", "is_current"]
