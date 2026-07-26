"""Editorial magazine renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = (
    "/",
    "/technology.html",
    "/business.html",
    "/culture.html",
    "/article.html",
)

_SECTIONS = {
    "technology": (
        (
            "Infrastructure",
            "The quiet systems keeping modern cities moving",
            "From traffic signals to water sensors, public infrastructure is "
            "becoming more responsive without becoming more visible.",
        ),
        (
            "Work",
            "Small teams are changing how products reach the market",
            "A new generation of tools is helping compact groups test ideas "
            "and serve customers at a much larger scale.",
        ),
        (
            "Research",
            "Inside the race to make batteries easier to recycle",
            "Labs and manufacturers are rethinking materials and recovery "
            "long before the first cell leaves the factory.",
        ),
    ),
    "business": (
        (
            "Markets",
            "Why mid-sized suppliers are rebuilding their logistics",
            "Shorter routes and regional warehouses are replacing the "
            "single-hub model that dominated the last decade.",
        ),
        (
            "Policy",
            "The new reporting rules nobody budgeted for",
            "Compliance teams are discovering that the data they need was "
            "never collected in a usable form.",
        ),
        (
            "Founders",
            "Bootstrapping is quietly back in fashion",
            "Slower growth and cleaner books are proving easier to defend "
            "than another round at a lower valuation.",
        ),
    ),
    "culture": (
        (
            "Cities",
            "The return of the neighbourhood cinema",
            "Independent screens are finding audiences by programming for "
            "the street they stand on.",
        ),
        (
            "Design",
            "Typography is getting slower, and readers approve",
            "Publishers are trading density for legibility and seeing longer "
            "sessions in return.",
        ),
        (
            "Music",
            "Small venues learn to share their calendars",
            "Coordinated booking is helping independent stages avoid "
            "competing for the same weekend.",
        ),
    ),
}


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a digital magazine with section pages and one article."""
    _write_styles(site_dir, identity)
    _write_index(site_dir, identity)
    for section in _SECTIONS:
        _write_section(site_dir, identity, section)
    _write_article(site_dir, identity)
    kit.write_not_found(site_dir, identity, home_label="Back to the front page")
    kit.write_sitemap(site_dir, identity, PAGES)


def _publication(identity: SiteIdentity) -> str:
    return identity.pick(
        "media-name",
        (
            f"The {identity.slug.capitalize()} Review",
            f"{identity.slug.capitalize()} Weekly",
            f"The {identity.slug.capitalize()} Dispatch",
            f"{identity.slug.capitalize()} Quarterly",
        ),
    )


def _header(identity: SiteIdentity, current: str) -> str:
    links = kit.nav(
        (
            ("/", "Front page"),
            ("/technology.html", "Technology"),
            ("/business.html", "Business"),
            ("/culture.html", "Culture"),
        ),
        current=current,
    )
    return (
        "<header class=\"masthead\">"
        f"<a class=\"logo\" href=\"/\">{kit.esc(_publication(identity))}</a>"
        f"<span class=\"strap\">Independent reporting from "
        f"{kit.esc(identity.city)}</span>"
        f"{links}"
        "</header>\n"
    )


def _footer(identity: SiteIdentity) -> str:
    return (
        "<footer class=\"foot\">"
        f"<span>{kit.esc(_publication(identity))} · published by "
        f"{kit.esc(identity.brand)}</span>"
        f"<span>© {identity.founded}</span>"
        "</footer>\n"
    )


def _cards(items: tuple[tuple[str, str, str], ...], *, link: str) -> str:
    return "".join(
        "<article class=\"card\">"
        f"<span class=\"kicker\">{kit.esc(kicker)}</span>"
        f"<h3><a href=\"{kit.esc(link)}\">{kit.esc(title)}</a></h3>"
        f"<p>{kit.esc(text)}</p>"
        "</article>"
        for kicker, title, text in items
    )


def _write_index(site_dir: Path, identity: SiteIdentity) -> None:
    lead = _SECTIONS["technology"][0]
    rest = tuple(items[1] for items in _SECTIONS.values())
    body = (
        f"{_header(identity, '/')}"
        "<main>"
        "<section class=\"lead\">"
        f"<span class=\"kicker\">{kit.esc(lead[0])}</span>"
        f"<h1><a href=\"/article.html\">{kit.esc(lead[1])}</a></h1>"
        f"<p>{kit.esc(lead[2])}</p>"
        "<a class=\"more\" href=\"/article.html\">Read the report</a>"
        "</section>"
        f"<section class=\"grid\">{_cards(rest, link='/article.html')}</section>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=_publication(identity),
            description=(
                f"{_publication(identity)} — technology, business and culture "
                f"reporting from {identity.city}."
            ),
            body=body,
        ),
    )


def _write_section(
    site_dir: Path,
    identity: SiteIdentity,
    section: str,
) -> None:
    items = _SECTIONS[section]
    body = (
        f"{_header(identity, f'/{section}.html')}"
        "<main>"
        f"<h1 class=\"section-title\">{kit.esc(section.capitalize())}</h1>"
        f"<section class=\"grid\">{_cards(items, link='/article.html')}</section>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        f"{section}.html",
        kit.page(
            title=f"{section.capitalize()} — {_publication(identity)}",
            description=f"{section.capitalize()} coverage.",
            body=body,
        ),
    )


def _write_article(site_dir: Path, identity: SiteIdentity) -> None:
    kicker, title, standfirst = _SECTIONS["technology"][0]
    body = (
        f"{_header(identity, '')}"
        "<main class=\"article\">"
        f"<span class=\"kicker\">{kit.esc(kicker)}</span>"
        f"<h1>{kit.esc(title)}</h1>"
        f"<p class=\"standfirst\">{kit.esc(standfirst)}</p>"
        f"<p class=\"byline\">By {kit.esc(identity.person)} · "
        f"{kit.esc(identity.city)}</p>"
        "<p>The upgrade rarely arrives as a single project. A sensor is "
        "replaced here, a controller there, and after a few budget cycles the "
        "network behaves differently even though no one announced a "
        "transformation.</p>"
        "<p>Operators describe the change in maintenance terms rather than "
        "technological ones. Fewer call-outs, faster diagnosis, and a clearer "
        "picture of which assets are close to failing.</p>"
        "<blockquote>The goal was never a smart city. It was a city that "
        "tells us when something is about to break.</blockquote>"
        "<p>That framing matters for funding. Programmes sold as innovation "
        "compete with everything else; programmes sold as deferred repair "
        "tend to survive the next council term.</p>"
        "<p class=\"back\"><a href=\"/\">← Front page</a></p>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "article.html",
        kit.page(
            title=f"{title} — {_publication(identity)}",
            description=standfirst,
            body=body,
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            ".masthead,main,.foot{width:min(1100px,calc(100% - 40px));margin:0 auto}"
            ".masthead{padding:40px 0 18px;border-bottom:3px solid #16181d;"
            "text-align:center}"
            ".masthead .logo{display:block;font-size:clamp(30px,5vw,46px);"
            "font-weight:800;letter-spacing:-.03em;color:#16181d}"
            ".masthead .strap{display:block;margin:6px 0 18px;color:#78747c;"
            "font-size:14px;text-transform:uppercase;letter-spacing:.14em}"
            ".masthead nav{display:flex;justify-content:center;flex-wrap:wrap;gap:22px;"
            "border-top:1px solid #e3e1e6;padding-top:14px}"
            ".masthead nav a{color:#3b3940;font-size:15px;font-weight:600}"
            ".masthead nav a.current{color:var(--accent)}"
            ".kicker{font-size:12px;font-weight:700;letter-spacing:.14em;"
            "text-transform:uppercase;color:var(--accent)}"
            ".lead{padding:44px 0 34px;border-bottom:1px solid #e3e1e6}"
            ".lead h1{font-size:clamp(28px,4.4vw,46px);line-height:1.12;margin:10px 0 14px;"
            "max-width:22ch}"
            ".lead h1 a{color:#16181d}.lead h1 a:hover{color:var(--accent)}"
            ".lead p{font-size:19px;color:#4d4a52;max-width:62ch;margin:0 0 18px}"
            ".more{font-weight:700}"
            ".grid{display:grid;gap:30px;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));"
            "padding:34px 0}"
            ".card h3{margin:8px 0 10px;font-size:20px;line-height:1.3}"
            ".card h3 a{color:#16181d}.card h3 a:hover{color:var(--accent)}"
            ".card p{margin:0;color:#5a565f}"
            ".section-title{font-size:30px;margin:34px 0 0;padding-bottom:10px;"
            "border-bottom:1px solid #e3e1e6}"
            ".article{max-width:720px;padding:34px 0 20px}"
            ".article h1{font-size:clamp(28px,4vw,42px);line-height:1.15;margin:10px 0 16px}"
            ".article .standfirst{font-size:20px;color:#4d4a52}"
            ".article .byline{font-size:14px;color:#8b8791;text-transform:uppercase;"
            "letter-spacing:.08em;margin:18px 0 26px;padding-bottom:18px;"
            "border-bottom:1px solid #e3e1e6}"
            ".article p{font-size:17.5px;color:#33313a;margin:0 0 20px}"
            ".article blockquote{margin:28px 0;padding-left:20px;"
            "border-left:3px solid var(--accent);font-size:21px;color:#2a2830;font-style:italic}"
            ".article .back{margin-top:32px;font-size:15px}"
            ".foot{display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;"
            "border-top:1px solid #e3e1e6;padding:22px 0 46px;color:#8b8791;font-size:14px}"
            ".notfound{padding:110px 20px;text-align:center}"
            ".notfound h1{font-size:62px;margin:0;color:var(--accent)}"
            "@media(max-width:620px){.masthead{padding:26px 0 14px}"
            ".masthead nav{gap:14px;font-size:14px}.lead{padding:28px 0 24px}"
            ".grid{gap:22px;padding:24px 0}.article .standfirst{font-size:18px}"
            ".article blockquote{font-size:18px}}"
        ),
    )


__all__ = ["PAGES", "generate"]
