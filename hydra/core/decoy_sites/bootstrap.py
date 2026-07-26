"""Shared filesystem bootstrap for decoy-site renderers."""
from __future__ import annotations

from pathlib import Path


_FAVICON = (
    b"\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x18\x00"
    b"\x30\x00\x00\x00\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\xff\xff\xff\x00\x00\x00\x00\x00"
)


def prepare_site(site_dir: Path) -> None:
    """Create the directory tree and files shared by every theme."""
    site_dir.mkdir(parents=True, exist_ok=True)
    for child in ("css", "js", "images"):
        (site_dir / child).mkdir(exist_ok=True)

    (site_dir / "robots.txt").write_text(
        "User-agent: *\n"
        "Allow: /\n"
        "Sitemap: https://example.com/sitemap.xml\n",
        encoding="utf-8",
    )
    (site_dir / "favicon.ico").write_bytes(_FAVICON)
