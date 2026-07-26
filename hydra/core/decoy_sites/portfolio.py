"""Personal portfolio and CV renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/work.html", "/cv.html")


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a one-person portfolio with work and CV pages."""
    _write_styles(site_dir, identity)
    _write_index(site_dir, identity)
    _write_work(site_dir, identity)
    _write_cv(site_dir, identity)
    kit.write_not_found(site_dir, identity, home_label="Back to the start")
    kit.write_sitemap(site_dir, identity, PAGES)


def _discipline(identity: SiteIdentity) -> str:
    return identity.pick(
        "portfolio-discipline",
        (
            "product designer",
            "interaction designer",
            "design engineer",
            "brand and interface designer",
        ),
    )


def _header(identity: SiteIdentity, current: str) -> str:
    links = kit.nav(
        (("/", "Start"), ("/work.html", "Work"), ("/cv.html", "CV")),
        current=current,
    )
    return (
        "<header class=\"bar\">"
        f"<a class=\"name\" href=\"/\">{kit.esc(identity.person)}</a>"
        f"{links}"
        "</header>\n"
    )


def _footer(identity: SiteIdentity) -> str:
    return (
        "<footer class=\"foot\">"
        f"<a href=\"mailto:{kit.esc(identity.email)}\">{kit.esc(identity.email)}</a>"
        f"<span>{kit.esc(identity.city)}</span>"
        "</footer>\n"
    )


def _projects(identity: SiteIdentity) -> tuple[tuple[str, str, str], ...]:
    return (
        (
            "Field service app",
            f"{identity.number('portfolio-year-a', 2021, 2025)}",
            "Scheduling and reporting for technicians who work offline for "
            "most of the day.",
        ),
        (
            "Payments dashboard",
            f"{identity.number('portfolio-year-b', 2019, 2023)}",
            "A reconciliation view that finance could actually read, replacing "
            "four spreadsheets.",
        ),
        (
            "Public transport wayfinding",
            f"{identity.number('portfolio-year-c', 2018, 2022)}",
            "Signage and screen system for a regional operator, from pilot "
            "station to rollout.",
        ),
    )


def _write_index(site_dir: Path, identity: SiteIdentity) -> None:
    tiles = "".join(
        "<a class=\"tile\" href=\"/work.html\">"
        f"<span class=\"year\">{kit.esc(year)}</span>"
        f"<h3>{kit.esc(title)}</h3>"
        f"<p>{kit.esc(text)}</p>"
        "</a>"
        for title, year, text in _projects(identity)
    )
    body = (
        f"{_header(identity, '/')}"
        "<main>"
        "<section class=\"intro\">"
        f"<h1>{kit.esc(identity.person)}</h1>"
        f"<p>I am a {kit.esc(_discipline(identity))} in "
        f"{kit.esc(identity.city)}. I work with small teams on interfaces "
        "that people use every day at work — dense, unglamorous and worth "
        "getting right.</p>"
        f"<p class=\"available\">Currently taking projects from "
        f"{identity.number('portfolio-month', 1, 12):02d}/"
        f"{identity.number('portfolio-avail', 2026, 2027)}.</p>"
        "</section>"
        f"<section class=\"tiles\">{tiles}</section>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{identity.person} — {_discipline(identity)}",
            description=(
                f"Portfolio of {identity.person}, {_discipline(identity)} "
                f"in {identity.city}."
            ),
            body=body,
        ),
    )


def _write_work(site_dir: Path, identity: SiteIdentity) -> None:
    blocks = "".join(
        "<article class=\"case\">"
        f"<h2>{kit.esc(title)}</h2>"
        f"<span class=\"year\">{kit.esc(year)}</span>"
        f"<p>{kit.esc(text)}</p>"
        "<p class=\"role\">Role: research, interface design, design system "
        "handover.</p>"
        "</article>"
        for title, year, text in _projects(identity)
    )
    body = (
        f"{_header(identity, '/work.html')}"
        f"<main><h1 class=\"page-title\">Selected work</h1>{blocks}</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "work.html",
        kit.page(
            title=f"Work — {identity.person}",
            description="Selected projects and case notes.",
            body=body,
        ),
    )


def _write_cv(site_dir: Path, identity: SiteIdentity) -> None:
    start = identity.number("portfolio-start", 2010, 2016)
    roles = (
        (f"{start + 8}–now", "Independent practice", identity.city),
        (f"{start + 4}–{start + 8}", "Senior designer", f"{identity.brand}"),
        (f"{start}–{start + 4}", "Designer", "Agency work"),
    )
    rows = "".join(
        f"<tr><td>{kit.esc(period)}</td><td>{kit.esc(role)}</td>"
        f"<td>{kit.esc(place)}</td></tr>"
        for period, role, place in roles
    )
    body = (
        f"{_header(identity, '/cv.html')}"
        "<main>"
        "<h1 class=\"page-title\">Curriculum vitae</h1>"
        f"<table class=\"cv\"><tbody>{rows}</tbody></table>"
        "<h2>Practice</h2>"
        "<p>Interface design, design systems, and enough front-end to hand "
        "over something that survives implementation.</p>"
        "<h2>Speaking</h2>"
        "<p>Occasional workshops on design systems for in-house teams. "
        f"Available on request at <a href=\"mailto:{kit.esc(identity.email)}\">"
        f"{kit.esc(identity.email)}</a>.</p>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "cv.html",
        kit.page(
            title=f"CV — {identity.person}",
            description=f"Curriculum vitae of {identity.person}.",
            body=body,
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            "body{background:var(--surface)}"
            ".bar,main,.foot{width:min(880px,calc(100% - 40px));margin:0 auto}"
            ".bar{display:flex;align-items:baseline;justify-content:space-between;"
            "padding:34px 0;gap:16px;flex-wrap:wrap}"
            ".bar .name{font-size:17px;font-weight:600;color:#161616;"
            "letter-spacing:.01em}"
            ".bar nav a{margin-left:22px;font-size:15px;color:#6b6b6b}"
            ".bar nav a.current{color:#161616;text-decoration:underline;"
            "text-underline-offset:5px}"
            ".intro{padding:40px 0 56px;border-bottom:1px solid #ececec}"
            ".intro h1{font-size:clamp(38px,7vw,68px);line-height:1;margin:0 0 24px;"
            "letter-spacing:-.03em}"
            ".intro p{font-size:19px;color:#4a4a4a;max-width:56ch;margin:0 0 14px}"
            ".available{color:var(--accent);font-weight:600}"
            ".tiles{display:grid;gap:1px;background:#ececec;margin:56px 0;"
            "grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}"
            ".tile{background:var(--surface);padding:26px 24px 30px;display:block}"
            ".tile:hover{background:var(--tint)}"
            ".year{font-size:12px;letter-spacing:.12em;color:#9a9a9a}"
            ".tile h3{margin:10px 0 8px;font-size:18px;color:#161616}"
            ".tile p{margin:0;color:#5c5c5c;font-size:15px}"
            ".page-title{font-size:34px;margin:12px 0 34px;letter-spacing:-.02em}"
            ".case{padding:26px 0;border-top:1px solid #ececec;max-width:64ch}"
            ".case h2{margin:0 0 4px;font-size:22px}"
            ".case p{color:#4a4a4a}"
            ".case .role{color:#8a8a8a;font-size:14px}"
            ".cv{width:100%;border-collapse:collapse;margin-bottom:36px}"
            ".cv td{padding:14px 0;border-bottom:1px solid #ececec;"
            "vertical-align:top;color:#4a4a4a}"
            ".cv td:first-child{width:9rem;color:#9a9a9a;font-size:14px}"
            "main h2{font-size:19px;margin:28px 0 8px}"
            "main>p{color:#4a4a4a;max-width:64ch}"
            ".foot{display:flex;justify-content:space-between;gap:12px;"
            "padding:44px 0 56px;margin-top:40px;border-top:1px solid #ececec;"
            "color:#8a8a8a;font-size:14px}"
            ".notfound{padding:110px 20px;text-align:center}"
            ".notfound h1{font-size:60px;margin:0;color:var(--accent)}"
            "@media(max-width:640px){.bar{padding:24px 0}"
            ".bar nav a{margin:0 18px 0 0}.intro{padding:24px 0 36px}"
            ".intro p{font-size:17px}.tiles{margin:36px 0}"
            ".cv td:first-child{width:7rem}}"
        ),
    )


__all__ = ["PAGES", "generate"]
