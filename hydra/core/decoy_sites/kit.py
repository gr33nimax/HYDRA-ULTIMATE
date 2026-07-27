"""Shared mechanics for decoy renderers.

The kit owns document plumbing only — head, asset paths, atomic-safe writes.
Layout, wording and stylesheet body stay with each theme so the generated
sites do not read as one template in different colours.
"""
from __future__ import annotations

import html
from collections.abc import Iterable
from pathlib import Path

from hydra.core.decoy_sites.identity import SiteIdentity


def esc(value: object) -> str:
    """Escape one interpolated value for HTML output."""
    return html.escape(str(value), quote=True)


def write_text(site_dir: Path, relative: str, content: str) -> None:
    """Write one UTF-8 text file inside the site directory."""
    target = site_dir / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def variables(identity: SiteIdentity) -> str:
    """Return the CSS custom properties every theme stylesheet starts with."""
    return (
        ":root{"
        f"--accent:{identity.accent};"
        f"--accent-dark:{identity.accent_dark};"
        f"--tint:{identity.tint};"
        f"--surface:{identity.surface};"
        f"--backdrop:{identity.backdrop};"
        f"--radius:{identity.radius};"
        f"--font:{identity.font};"
        "color-scheme:light}"
        "*{box-sizing:border-box}"
        "body{margin:0;font-family:var(--font);background:var(--backdrop);"
        "color:#1b2130;line-height:1.6;-webkit-font-smoothing:antialiased}"
        "a{color:var(--accent);text-decoration:none}"
        "a:hover{color:var(--accent-dark)}"
        "img{max-width:100%}"
    )


def page(
    *,
    title: str,
    description: str,
    body: str,
    stylesheet: str = "css/style.css",
    lang: str = "en",
    head_extra: str = "",
) -> str:
    """Assemble one complete HTML document."""
    return (
        "<!DOCTYPE html>\n"
        f"<html lang=\"{esc(lang)}\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"  <meta name=\"description\" content=\"{esc(description)}\">\n"
        f"  <title>{esc(title)}</title>\n"
        "  <link rel=\"icon\" href=\"/favicon.ico\">\n"
        f"  <link rel=\"stylesheet\" href=\"/{stylesheet}\">\n"
        f"{head_extra}"
        "</head>\n"
        "<body>\n"
        f"{body}"
        "</body>\n"
        "</html>\n"
    )


def nav(items: Iterable[tuple[str, str]], *, current: str = "") -> str:
    """Render one navigation list from (href, label) pairs."""
    links = []
    for href, label in items:
        marker = " class=\"current\"" if href == current else ""
        links.append(f"<a href=\"{esc(href)}\"{marker}>{esc(label)}</a>")
    return "<nav>" + "".join(links) + "</nav>"


def write_sitemap(site_dir: Path, identity: SiteIdentity, paths: Iterable[str]) -> None:
    """Write a sitemap consistent with the pages a theme generated."""
    entries = "".join(
        f"  <url><loc>https://{esc(identity.domain)}{esc(path)}</loc></url>\n"
        for path in paths
    )
    write_text(
        site_dir,
        "sitemap.xml",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
        f"{entries}"
        "</urlset>\n",
    )


def write_robots(site_dir: Path, identity: SiteIdentity) -> None:
    """Write robots.txt pointing at this site's own sitemap."""
    write_text(
        site_dir,
        "robots.txt",
        "User-agent: *\n"
        "Allow: /\n"
        f"Sitemap: https://{identity.domain}/sitemap.xml\n",
    )


def write_not_found(
    site_dir: Path,
    identity: SiteIdentity,
    *,
    home_label: str = "Back to home",
) -> None:
    """Write a plain 404 page in the theme's own shell."""
    write_text(
        site_dir,
        "404.html",
        page(
            title=f"Page not found — {identity.brand}",
            description="The requested page does not exist.",
            body=(
                "<main class=\"notfound\">"
                "<h1>404</h1>"
                "<p>This page does not exist or has been moved.</p>"
                f"<p><a href=\"/\">{esc(home_label)}</a></p>"
                "</main>\n"
            ),
        ),
    )


__all__ = [
    "esc",
    "nav",
    "page",
    "variables",
    "write_not_found",
    "write_robots",
    "write_sitemap",
    "write_text",
]
