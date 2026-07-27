"""Photography portfolio renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/series.html", "/about.html")

_SERIES = (
    ("Harbour, winter", "12 photographs"),
    ("Night shift", "9 photographs"),
    ("Empty stadiums", "16 photographs"),
    ("The long road east", "21 photographs"),
    ("Rooftops", "8 photographs"),
    ("Market days", "14 photographs"),
)


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a photography site with a grid, a series page and a bio."""
    _write_styles(site_dir, identity)
    _write_index(site_dir, identity)
    _write_series(site_dir, identity)
    _write_about(site_dir, identity)
    kit.write_not_found(site_dir, identity, home_label="Back to the index")
    kit.write_sitemap(site_dir, identity, PAGES)


def _header(identity: SiteIdentity, current: str) -> str:
    links = kit.nav(
        (("/", "Index"), ("/series.html", "Series"), ("/about.html", "About")),
        current=current,
    )
    return (
        "<header class=\"bar\">"
        f"<a class=\"who\" href=\"/\">{kit.esc(identity.person)}</a>"
        f"{links}"
        "</header>\n"
    )


def _frames(identity: SiteIdentity, count: int) -> str:
    tones = ("a", "b", "c", "d")
    frames = []
    for index in range(count):
        tone = tones[identity.number(f"gallery-tone-{index}", 0, len(tones) - 1)]
        tall = " tall" if identity.number(f"gallery-tall-{index}", 0, 3) == 0 else ""
        frames.append(f"<figure class=\"frame {tone}{tall}\"></figure>")
    return "".join(frames)


def _write_index(site_dir: Path, identity: SiteIdentity) -> None:
    body = (
        f"{_header(identity, '/')}"
        "<main>"
        f"<section class=\"grid\">{_frames(identity, 9)}</section>"
        "</main>\n"
        f"<footer class=\"foot\"><span>{kit.esc(identity.person)} · "
        f"{kit.esc(identity.city)}</span>"
        f"<a href=\"mailto:{kit.esc(identity.email)}\">Prints and licensing</a>"
        "</footer>\n"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{identity.person} — photography",
            description=f"Photographs by {identity.person}, {identity.city}.",
            body=body,
        ),
    )


def _write_series(site_dir: Path, identity: SiteIdentity) -> None:
    items = "".join(
        "<li><a href=\"/\">"
        f"<span class=\"title\">{kit.esc(title)}</span>"
        f"<span class=\"count\">{kit.esc(count)}</span>"
        "</a></li>"
        for title, count in _SERIES
    )
    body = (
        f"{_header(identity, '/series.html')}"
        "<main class=\"page\">"
        "<h1>Series</h1>"
        f"<ul class=\"series\">{items}</ul>"
        f"<section class=\"grid small\">{_frames(identity, 6)}</section>"
        "</main>\n"
        f"<footer class=\"foot\"><span>{kit.esc(identity.person)}</span>"
        f"<a href=\"mailto:{kit.esc(identity.email)}\">Contact</a></footer>\n"
    )
    kit.write_text(
        site_dir,
        "series.html",
        kit.page(
            title=f"Series — {identity.person}",
            description="Photographic series and ongoing work.",
            body=body,
        ),
    )


def _write_about(site_dir: Path, identity: SiteIdentity) -> None:
    subject = identity.pick(
        "gallery-subject",
        (
            "working landscapes and the people in them",
            "cities after the evening rush",
            "coastlines, ports and the trade that moves through them",
        ),
    )
    body = (
        f"{_header(identity, '/about.html')}"
        "<main class=\"page narrow\">"
        "<h1>About</h1>"
        f"<p>{kit.esc(identity.person)} photographs {kit.esc(subject)}. Based "
        f"in {kit.esc(identity.city)} since {identity.founded}, working on "
        "long-form series and occasional editorial commissions.</p>"
        "<p>Work has been shown in group exhibitions and published in print. "
        "Archival prints are available in two sizes, editioned and signed.</p>"
        "<h2>Contact</h2>"
        f"<p><a href=\"mailto:{kit.esc(identity.email)}\">"
        f"{kit.esc(identity.email)}</a></p>"
        "</main>\n"
        f"<footer class=\"foot\"><span>{kit.esc(identity.person)}</span>"
        f"<span>{kit.esc(identity.city)}</span></footer>\n"
    )
    kit.write_text(
        site_dir,
        "about.html",
        kit.page(
            title=f"About — {identity.person}",
            description=f"About the photographer {identity.person}.",
            body=body,
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            "body{background:#111;color:#e8e8e8}"
            "a{color:#e8e8e8}a:hover{color:var(--accent)}"
            ".bar,main,.foot{width:min(1180px,calc(100% - 36px));margin:0 auto}"
            ".bar{display:flex;align-items:baseline;justify-content:space-between;"
            "padding:30px 0 26px;gap:16px;flex-wrap:wrap}"
            ".bar .who{font-size:16px;letter-spacing:.22em;text-transform:uppercase}"
            ".bar nav a{margin-left:22px;font-size:13px;letter-spacing:.14em;"
            "text-transform:uppercase;color:#9a9a9a}"
            ".bar nav a.current{color:var(--accent)}"
            ".grid{display:grid;gap:14px;grid-template-columns:repeat(3,1fr);"
            "grid-auto-rows:220px;padding-bottom:40px}"
            ".grid.small{grid-auto-rows:150px;padding-top:20px}"
            ".frame{margin:0;border-radius:2px;background:#1c1c1c}"
            ".frame.a{background:linear-gradient(160deg,#2a2a2a,#141414)}"
            ".frame.b{background:linear-gradient(140deg,#232323,#101010)}"
            ".frame.c{background:linear-gradient(200deg,#303030,#171717)}"
            ".frame.d{background:linear-gradient(120deg,#1d1d1d,#242424)}"
            ".frame.tall{grid-row:span 2}"
            ".page{padding-bottom:40px}"
            ".page.narrow{max-width:62ch}"
            ".page h1{font-size:15px;letter-spacing:.2em;text-transform:uppercase;"
            "color:#9a9a9a;margin:14px 0 22px}"
            ".page h2{font-size:13px;letter-spacing:.18em;text-transform:uppercase;"
            "color:#9a9a9a;margin:30px 0 8px}"
            ".page p{color:#c2c2c2;font-size:16px}"
            ".series{list-style:none;padding:0;margin:0}"
            ".series li{border-bottom:1px solid #262626}"
            ".series a{display:flex;justify-content:space-between;padding:16px 0;"
            "font-size:18px}"
            ".series .count{color:#7a7a7a;font-size:14px}"
            ".foot{display:flex;justify-content:space-between;gap:12px;"
            "border-top:1px solid #262626;padding:22px 0 46px;color:#7a7a7a;"
            "font-size:13px;letter-spacing:.06em}"
            ".notfound{padding:120px 20px;text-align:center}"
            ".notfound h1{font-size:58px;margin:0;color:var(--accent)}"
            "@media(max-width:720px){.grid{grid-template-columns:repeat(2,1fr);"
            "grid-auto-rows:160px}}"
        ),
    )


__all__ = ["PAGES", "generate"]
