"""Neighbourhood cafe renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/menu.html", "/visit.html")

_BREAKFAST = (
    ("Sourdough toast, cultured butter", 5),
    ("Baked eggs, tomato, herbs", 11),
    ("Porridge, roasted plum, hazelnut", 8),
    ("Seasonal pastry", 4),
)
_KITCHEN = (
    ("Soup of the day, bread", 9),
    ("Roast vegetable plate", 14),
    ("Fish of the day", 19),
    ("Cheese and pickles", 12),
)
_COFFEE = (
    ("Espresso", 3),
    ("Flat white", 4),
    ("Filter, single origin", 4),
    ("Cold brew", 5),
)


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a cafe site with a menu and a visiting page."""
    _write_styles(site_dir, identity)
    _write_index(site_dir, identity)
    _write_menu(site_dir, identity)
    _write_visit(site_dir, identity)
    kit.write_not_found(site_dir, identity, home_label="Back to the cafe")
    kit.write_sitemap(site_dir, identity, PAGES)


def _place(identity: SiteIdentity) -> str:
    return identity.pick(
        "cafe-name",
        (
            f"Café {identity.slug.capitalize()}",
            f"{identity.slug.capitalize()} Kitchen",
            f"The {identity.slug.capitalize()} Room",
            f"{identity.slug.capitalize()} & Daughters",
        ),
    )


def _street(identity: SiteIdentity) -> str:
    name = identity.pick(
        "cafe-street",
        ("Mill Lane", "Kettle Street", "Old Wharf", "Linden Road", "Market Row"),
    )
    return f"{identity.number('cafe-number', 2, 96)} {name}"


def _header(identity: SiteIdentity, current: str) -> str:
    links = kit.nav(
        (("/", "Home"), ("/menu.html", "Menu"), ("/visit.html", "Visit")),
        current=current,
    )
    return (
        "<header class=\"bar\">"
        f"<a class=\"place\" href=\"/\">{kit.esc(_place(identity))}</a>"
        f"{links}"
        "</header>\n"
    )


def _footer(identity: SiteIdentity) -> str:
    return (
        "<footer class=\"foot\">"
        f"<span>{kit.esc(_street(identity))}, {kit.esc(identity.city)}</span>"
        "<span>Open Tuesday to Sunday, 08:00–16:00</span>"
        "</footer>\n"
    )


def _price_list(items: tuple[tuple[str, int], ...], symbol: str) -> str:
    return "".join(
        f"<li><span>{kit.esc(name)}</span><b>{kit.esc(symbol)}{price}</b></li>"
        for name, price in items
    )


def _write_index(site_dir: Path, identity: SiteIdentity) -> None:
    line = identity.pick(
        "cafe-line",
        (
            "Breakfast all morning, a short lunch menu, and coffee we roast "
            "ourselves.",
            "A small kitchen, a daily menu, and bread baked the same morning.",
            "Coffee, cooking and a corner table that is worth the wait.",
        ),
    )
    body = (
        f"{_header(identity, '/')}"
        "<main>"
        "<section class=\"hero\">"
        f"<h1>{kit.esc(_place(identity))}</h1>"
        f"<p>{kit.esc(line)}</p>"
        f"<p class=\"where\">{kit.esc(_street(identity))} · "
        f"{kit.esc(identity.city)}</p>"
        "</section>"
        "<section class=\"cols\">"
        "<article><h2>Kitchen</h2><p>The menu changes with what the market "
        "has. Everything is cooked to order, so lunch takes a little longer "
        "than you expect and that is on purpose.</p>"
        "<a href=\"/menu.html\">See the menu →</a></article>"
        "<article><h2>Coffee</h2><p>Two espresso blends and a rotating filter. "
        f"Beans are roasted in {kit.esc(identity.city)} every week and sold by "
        "the bag at the counter.</p>"
        "<a href=\"/visit.html\">Opening hours →</a></article>"
        "</section>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{_place(identity)} — {identity.city}",
            description=(
                f"{_place(identity)}, a neighbourhood cafe in {identity.city}."
            ),
            body=body,
        ),
    )


def _write_menu(site_dir: Path, identity: SiteIdentity) -> None:
    symbol = identity.pick("cafe-currency", ("€", "£"))
    body = (
        f"{_header(identity, '/menu.html')}"
        "<main class=\"page\">"
        "<h1>Menu</h1>"
        "<p class=\"lead\">Served until the kitchen runs out, which on a good "
        "Saturday happens early.</p>"
        "<section class=\"menu\">"
        f"<h2>Morning</h2><ul>{_price_list(_BREAKFAST, symbol)}</ul>"
        f"<h2>Kitchen</h2><ul>{_price_list(_KITCHEN, symbol)}</ul>"
        f"<h2>Coffee</h2><ul>{_price_list(_COFFEE, symbol)}</ul>"
        "</section>"
        "<p class=\"note\">Ask about allergens — the kitchen keeps a written "
        "list for every dish.</p>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "menu.html",
        kit.page(
            title=f"Menu — {_place(identity)}",
            description="Breakfast, lunch and coffee menu.",
            body=body,
        ),
    )


def _write_visit(site_dir: Path, identity: SiteIdentity) -> None:
    body = (
        f"{_header(identity, '/visit.html')}"
        "<main class=\"page\">"
        "<h1>Visit</h1>"
        "<dl class=\"hours\">"
        "<dt>Tuesday – Friday</dt><dd>08:00 – 16:00</dd>"
        "<dt>Saturday</dt><dd>09:00 – 16:00</dd>"
        "<dt>Sunday</dt><dd>09:00 – 15:00</dd>"
        "<dt>Monday</dt><dd>Closed</dd>"
        "</dl>"
        "<h2>Finding us</h2>"
        f"<p>{kit.esc(_street(identity))}, {kit.esc(identity.city)}. The "
        "entrance is on the side street; the courtyard tables open when the "
        "weather allows.</p>"
        "<h2>Tables</h2>"
        "<p>We keep most of the room for walk-ins. Groups of six or more can "
        f"book by email at <a href=\"mailto:{kit.esc(identity.email)}\">"
        f"{kit.esc(identity.email)}</a>.</p>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "visit.html",
        kit.page(
            title=f"Visit — {_place(identity)}",
            description="Opening hours, address and bookings.",
            body=body,
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            "body{background:#fbf7f0;color:#2f2620}"
            ".bar,main,.foot{width:min(820px,calc(100% - 36px));margin:0 auto}"
            ".bar{display:flex;align-items:baseline;justify-content:space-between;"
            "padding:28px 0;gap:14px;flex-wrap:wrap;border-bottom:1px solid #e8ddcd}"
            ".bar .place{font-size:21px;font-weight:700;letter-spacing:.01em;"
            "color:#2f2620}"
            ".bar nav a{margin-left:20px;font-size:15px;color:#7d6f61}"
            ".bar nav a.current{color:var(--accent)}"
            ".hero{padding:60px 0 44px;text-align:center}"
            ".hero h1{font-size:clamp(32px,6vw,54px);margin:0 0 16px;line-height:1.05}"
            ".hero p{font-size:19px;color:#6a5d51;max-width:50ch;margin:0 auto}"
            ".hero .where{margin-top:18px;font-size:14px;letter-spacing:.1em;"
            "text-transform:uppercase;color:#a2907c}"
            ".cols{display:grid;gap:32px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));"
            "padding:24px 0 56px;border-top:1px solid #e8ddcd}"
            ".cols h2{font-size:18px;margin:28px 0 10px}"
            ".cols p{color:#6a5d51;margin:0 0 12px}"
            ".page{padding:40px 0 20px}"
            ".page h1{font-size:34px;margin:0 0 10px}"
            ".page .lead{color:#6a5d51;margin-bottom:26px}"
            ".menu h2{font-size:14px;letter-spacing:.16em;text-transform:uppercase;"
            "color:#a2907c;margin:30px 0 10px}"
            ".menu ul{list-style:none;padding:0;margin:0}"
            ".menu li{display:flex;justify-content:space-between;gap:16px;padding:11px 0;"
            "border-bottom:1px dotted #ddcdb8}"
            ".menu b{color:var(--accent-dark);font-weight:600}"
            ".note{margin-top:28px;color:#8a7a6b;font-size:14px}"
            ".hours{display:grid;grid-template-columns:auto 1fr;gap:8px 26px;margin:20px 0 8px}"
            ".hours dt{color:#6a5d51}.hours dd{margin:0;font-weight:600}"
            ".page h2{font-size:18px;margin:30px 0 8px}"
            ".page p{color:#6a5d51}"
            ".foot{display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px;"
            "border-top:1px solid #e8ddcd;margin-top:40px;padding:24px 0 46px;"
            "color:#8a7a6b;font-size:14px}"
            ".notfound{padding:110px 20px;text-align:center}"
            ".notfound h1{font-size:58px;margin:0;color:var(--accent)}"
            "@media(max-width:600px){.bar{padding:20px 0}"
            ".bar nav a{margin:0 16px 0 0}.hero{padding:40px 0 32px}"
            ".hero p{font-size:17px}.cols{gap:20px;padding:16px 0 40px}"
            ".hours{grid-template-columns:1fr;gap:2px 0}"
            ".hours dd{margin-bottom:10px}}"
        ),
    )


__all__ = ["PAGES", "generate"]
