"""Conference and event landing renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/schedule.html", "/venue.html")

_TALKS = (
    ("09:30", "Opening remarks", "Programme committee"),
    ("10:00", "Keeping legacy systems boring", "Track: Operations"),
    ("11:15", "What the incident report left out", "Track: Reliability"),
    ("13:30", "Designing for the second year of a product", "Track: Product"),
    ("15:00", "Small teams, large estates", "Track: Operations"),
    ("16:30", "Closing panel", "All tracks"),
)


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate an event landing page with schedule and venue pages."""
    _write_styles(site_dir, identity)
    _write_index(site_dir, identity)
    _write_schedule(site_dir, identity)
    _write_venue(site_dir, identity)
    kit.write_not_found(site_dir, identity, home_label="Back to the programme")
    kit.write_sitemap(site_dir, identity, PAGES)


def _event(identity: SiteIdentity) -> str:
    return identity.pick(
        "conf-name",
        (
            f"{identity.slug.capitalize()}Conf",
            f"{identity.city} Systems Days",
            f"{identity.slug.capitalize()} Summit",
        ),
    )


def _dates(identity: SiteIdentity) -> str:
    month = identity.pick(
        "conf-month",
        ("March", "April", "May", "September", "October", "November"),
    )
    day = identity.number("conf-day", 3, 24)
    return f"{month} {day}–{day + 1}, 2027"


def _header(identity: SiteIdentity, current: str) -> str:
    links = kit.nav(
        (
            ("/", "Overview"),
            ("/schedule.html", "Schedule"),
            ("/venue.html", "Venue"),
        ),
        current=current,
    )
    return (
        "<header class=\"bar\"><div class=\"wrap\">"
        f"<a class=\"event\" href=\"/\">{kit.esc(_event(identity))}</a>"
        f"{links}"
        "</div></header>\n"
    )


def _footer(identity: SiteIdentity) -> str:
    return (
        "<footer class=\"foot\"><div class=\"wrap\">"
        f"<span>{kit.esc(_event(identity))} · {kit.esc(_dates(identity))} · "
        f"{kit.esc(identity.city)}</span>"
        f"<a href=\"mailto:{kit.esc(identity.email)}\">{kit.esc(identity.email)}</a>"
        "</div></footer>\n"
    )


def _write_index(site_dir: Path, identity: SiteIdentity) -> None:
    seats = identity.number("conf-seats", 180, 460)
    body = (
        f"{_header(identity, '/')}"
        "<main>"
        "<section class=\"hero\"><div class=\"wrap\">"
        f"<span class=\"date\">{kit.esc(_dates(identity))} · "
        f"{kit.esc(identity.city)}</span>"
        f"<h1>{kit.esc(_event(identity))}</h1>"
        "<p>Two days about running software that other people depend on. "
        "One track of talks, one track of workshops, and a hallway that is "
        "deliberately wide.</p>"
        "<a class=\"cta\" href=\"/schedule.html\">See the programme</a>"
        f"<span class=\"note\">{seats} seats · tickets released in two waves</span>"
        "</div></section>"
        "<section class=\"pillars\"><div class=\"wrap\">"
        "<article><h3>Practitioners only</h3>"
        "<p>Every speaker runs the system they talk about.</p></article>"
        "<article><h3>No vendor keynotes</h3>"
        "<p>Sponsors get a table, not the main stage.</p></article>"
        "<article><h3>Recorded, then published</h3>"
        "<p>Talks go online four weeks after the event, free.</p></article>"
        "</div></section>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{_event(identity)} — {_dates(identity)}",
            description=(
                f"{_event(identity)}, a two-day conference in {identity.city}."
            ),
            body=body,
        ),
    )


def _write_schedule(site_dir: Path, identity: SiteIdentity) -> None:
    rows = "".join(
        "<li>"
        f"<time>{kit.esc(time)}</time>"
        f"<div><h3>{kit.esc(title)}</h3><span>{kit.esc(track)}</span></div>"
        "</li>"
        for time, title, track in _TALKS
    )
    body = (
        f"{_header(identity, '/schedule.html')}"
        "<main class=\"page\"><div class=\"wrap\">"
        "<h1>Day one</h1>"
        f"<p class=\"lead\">All talks are in the main hall. "
        f"{kit.esc(_dates(identity))}.</p>"
        f"<ul class=\"agenda\">{rows}</ul>"
        "<p class=\"lead\">Day two follows the same shape with workshops in "
        "the afternoon.</p>"
        "</div></main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "schedule.html",
        kit.page(
            title=f"Schedule — {_event(identity)}",
            description="Talk schedule for day one.",
            body=body,
        ),
    )


def _write_venue(site_dir: Path, identity: SiteIdentity) -> None:
    hall = identity.pick(
        "conf-venue",
        ("Old Exchange", "Harbour Pavilion", "Textile Hall", "Municipal Library"),
    )
    body = (
        f"{_header(identity, '/venue.html')}"
        "<main class=\"page\"><div class=\"wrap\">"
        "<h1>Venue &amp; travel</h1>"
        f"<p class=\"lead\">The {kit.esc(hall)}, {kit.esc(identity.city)} — "
        "fifteen minutes on foot from the central station.</p>"
        "<h2>Getting there</h2>"
        "<ul>"
        "<li>Tram lines 2 and 7 stop directly outside.</li>"
        "<li>Bicycle parking is available in the courtyard.</li>"
        "<li>The building is step-free with lifts to every floor.</li>"
        "</ul>"
        "<h2>Staying over</h2>"
        "<p>We hold a small block of rooms in two nearby hotels until four "
        "weeks before the event. Ask for the conference rate when booking.</p>"
        "<h2>Food</h2>"
        "<p>Lunch and coffee are included. Tell us about dietary requirements "
        "in your ticket order and the kitchen will plan for them.</p>"
        "</div></main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "venue.html",
        kit.page(
            title=f"Venue — {_event(identity)}",
            description=f"Venue and travel information for {identity.city}.",
            body=body,
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            ".wrap{width:min(960px,calc(100% - 40px));margin:0 auto}"
            ".bar{background:#101322;color:#fff}"
            ".bar .wrap{display:flex;align-items:center;justify-content:space-between;"
            "height:68px;flex-wrap:wrap;gap:10px}"
            ".bar .event{font-weight:700;font-size:18px;color:#fff}"
            ".bar nav a{margin-left:22px;color:#aab0c6;font-size:15px}"
            ".bar nav a.current{color:var(--accent)}"
            ".hero{background:#101322;color:#fff;padding:70px 0 84px}"
            ".hero .date{display:block;color:var(--accent);font-weight:600;"
            "letter-spacing:.08em;text-transform:uppercase;font-size:13px}"
            ".hero h1{font-size:clamp(38px,8vw,76px);margin:14px 0 18px;line-height:1;"
            "letter-spacing:-.03em}"
            ".hero p{font-size:19px;color:#b7bdd0;max-width:56ch;margin:0 0 30px}"
            ".cta{display:inline-block;background:var(--accent);color:#fff;"
            "padding:15px 30px;border-radius:var(--radius);font-weight:700}"
            ".cta:hover{background:var(--accent-dark);color:#fff}"
            ".hero .note{display:block;margin-top:16px;color:#8890a8;font-size:14px}"
            ".pillars .wrap{display:grid;gap:26px;padding:56px 0;"
            "grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}"
            ".pillars article{border-top:3px solid var(--accent);padding-top:16px}"
            ".pillars h3{margin:0 0 8px;font-size:17px}"
            ".pillars p{margin:0;color:#5a6076}"
            ".page{padding:52px 0 20px}"
            ".page h1{font-size:34px;margin:0 0 12px}"
            ".page h2{font-size:20px;margin:32px 0 10px}"
            ".page .lead{color:#5a6076;font-size:17px}"
            ".page li{color:#5a6076}"
            ".agenda{list-style:none;padding:0;margin:26px 0}"
            ".agenda li{display:flex;gap:22px;padding:18px 0;"
            "border-bottom:1px solid #e4e6ef}"
            ".agenda time{min-width:64px;font-weight:700;color:var(--accent-dark)}"
            ".agenda h3{margin:0 0 4px;font-size:17px}"
            ".agenda span{color:#7c8399;font-size:14px}"
            ".foot{border-top:1px solid #e4e6ef;margin-top:40px}"
            ".foot .wrap{display:flex;justify-content:space-between;flex-wrap:wrap;"
            "gap:10px;padding:26px 0 46px;color:#7c8399;font-size:14px}"
            ".notfound{padding:110px 20px;text-align:center}"
            ".notfound h1{font-size:60px;margin:0;color:var(--accent)}"
            "@media(max-width:640px){.bar .wrap{height:auto;padding:14px 0}"
            ".bar nav a{margin:0 16px 0 0}.hero{padding:46px 0 56px}"
            ".hero p{font-size:17px}.agenda li{flex-direction:column;gap:6px}"
            ".agenda time{min-width:0}}"
        ),
    )


__all__ = ["PAGES", "generate"]
