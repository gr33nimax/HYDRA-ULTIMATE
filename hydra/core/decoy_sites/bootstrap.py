"""Shared filesystem bootstrap for decoy-site renderers."""
from __future__ import annotations

import struct
from pathlib import Path

from hydra.core.decoy_sites.identity import SiteIdentity


_ICON_SIZE = 16


def _favicon(identity: SiteIdentity) -> bytes:
    """Render a solid 16×16 icon in the site's accent colour."""
    accent = identity.accent.lstrip("#")
    red, green, blue = (int(accent[index:index + 2], 16) for index in (0, 2, 4))
    pixels = bytes((blue, green, red, 255)) * (_ICON_SIZE * _ICON_SIZE)
    mask = bytes(_ICON_SIZE * _ICON_SIZE // 8)
    header = struct.pack("<3H", 0, 1, 1)
    info = struct.pack(
        "<3I2H6I",
        40,
        _ICON_SIZE,
        _ICON_SIZE * 2,
        1,
        32,
        0,
        len(pixels) + len(mask),
        0,
        0,
        0,
        0,
    )
    entry = struct.pack(
        "<4B2H2I",
        _ICON_SIZE,
        _ICON_SIZE,
        0,
        0,
        1,
        32,
        len(info) + len(pixels) + len(mask),
        len(header) + 16,
    )
    return header + entry + info + pixels + mask


def prepare_site(site_dir: Path, identity: SiteIdentity) -> None:
    """Create the directory tree and assets shared by every theme."""
    site_dir.mkdir(parents=True, exist_ok=True)
    for child in ("css", "js", "images"):
        (site_dir / child).mkdir(exist_ok=True)
    (site_dir / "favicon.ico").write_bytes(_favicon(identity))


__all__ = ["prepare_site"]
