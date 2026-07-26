"""Small online shop renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/shipping.html", "/product.html")

_PRODUCTS = (
    ("Canvas weekender", "Waxed cotton, leather trim, 38 litres.", 189),
    ("Field notebook, pack of 3", "Dot grid, 90 gsm, stitched spine.", 24),
    ("Enamel travel mug", "400 ml, dishwasher safe, matte finish.", 32),
    ("Merino watch cap", "Single-ply, unlined, one size.", 45),
    ("Cotton apron", "Split-leg, adjustable, deep pockets.", 68),
    ("Leather card holder", "Vegetable tanned, four slots.", 39),
)


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a small catalogue shop with a product and shipping page."""
    _write_styles(site_dir, identity)
    _write_index(site_dir, identity)
    _write_product(site_dir, identity)
    _write_shipping(site_dir, identity)
    kit.write_not_found(site_dir, identity, home_label="Back to the shop")
    kit.write_sitemap(site_dir, identity, PAGES)


def _store(identity: SiteIdentity) -> str:
    return identity.pick(
        "shop-name",
        (
            f"{identity.slug.capitalize()} & Co.",
            f"{identity.slug.capitalize()} Goods",
            f"{identity.slug.capitalize()} Supply Co.",
            f"House of {identity.slug.capitalize()}",
        ),
    )


def _currency(identity: SiteIdentity) -> str:
    return identity.pick("shop-currency", ("€", "£", "$"))


def _header(identity: SiteIdentity, current: str) -> str:
    links = kit.nav(
        (
            ("/", "Shop"),
            ("/product.html", "New in"),
            ("/shipping.html", "Shipping"),
        ),
        current=current,
    )
    return (
        "<header class=\"bar\">"
        f"<a class=\"store\" href=\"/\">{kit.esc(_store(identity))}</a>"
        f"{links}"
        "<span class=\"cart\">Bag (0)</span>"
        "</header>\n"
    )


def _footer(identity: SiteIdentity) -> str:
    return (
        "<footer class=\"foot\">"
        f"<span>{kit.esc(_store(identity))}, {kit.esc(identity.city)} — "
        f"since {identity.founded}</span>"
        f"<a href=\"mailto:{kit.esc(identity.email)}\">{kit.esc(identity.email)}</a>"
        "</footer>\n"
    )


def _write_index(site_dir: Path, identity: SiteIdentity) -> None:
    symbol = _currency(identity)
    cards = "".join(
        "<a class=\"product\" href=\"/product.html\">"
        "<div class=\"shot\"></div>"
        f"<h3>{kit.esc(title)}</h3>"
        f"<p>{kit.esc(text)}</p>"
        f"<span class=\"price\">{kit.esc(symbol)}{price}</span>"
        "</a>"
        for title, text, price in _PRODUCTS
    )
    body = (
        f"{_header(identity, '/')}"
        "<main>"
        "<section class=\"promo\">"
        f"<h1>{kit.esc(identity.pick('shop-promo', ('Made to be used', 'Built for daily wear', 'Everyday goods, honestly made')))}</h1>"
        f"<p>Small batches, produced in {kit.esc(identity.city)} and finished "
        "by hand. Free returns within 30 days.</p>"
        "</section>"
        f"<section class=\"catalogue\">{cards}</section>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{_store(identity)} — everyday goods",
            description=f"{_store(identity)} sells small-batch everyday goods.",
            body=body,
        ),
    )


def _write_product(site_dir: Path, identity: SiteIdentity) -> None:
    title, text, price = _PRODUCTS[identity.number("shop-feature", 0, len(_PRODUCTS) - 1)]
    symbol = _currency(identity)
    body = (
        f"{_header(identity, '/product.html')}"
        "<main class=\"detail\">"
        "<div class=\"shot large\"></div>"
        "<div class=\"info\">"
        f"<h1>{kit.esc(title)}</h1>"
        f"<span class=\"price\">{kit.esc(symbol)}{price}</span>"
        f"<p>{kit.esc(text)}</p>"
        "<p>Every piece is checked before it leaves the workshop. Minor "
        "variation in grain and colour is expected and not a defect.</p>"
        "<button type=\"button\">Add to bag</button>"
        "<ul class=\"facts\">"
        "<li>Ships in 2–4 working days</li>"
        "<li>30-day returns</li>"
        "<li>Two-year repair service</li>"
        "</ul>"
        "</div>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "product.html",
        kit.page(
            title=f"{title} — {_store(identity)}",
            description=text,
            body=body,
        ),
    )


def _write_shipping(site_dir: Path, identity: SiteIdentity) -> None:
    symbol = _currency(identity)
    threshold = identity.number("shop-threshold", 60, 140)
    body = (
        f"{_header(identity, '/shipping.html')}"
        "<main class=\"page\">"
        "<h1>Shipping &amp; returns</h1>"
        f"<p>Orders leave {kit.esc(identity.city)} within two working days. "
        f"Delivery is free above {kit.esc(symbol)}{threshold}.</p>"
        "<table>"
        "<thead><tr><th>Destination</th><th>Time</th><th>Cost</th></tr></thead>"
        "<tbody>"
        f"<tr><td>Domestic</td><td>1–3 days</td><td>{kit.esc(symbol)}5</td></tr>"
        f"<tr><td>Europe</td><td>3–6 days</td><td>{kit.esc(symbol)}12</td></tr>"
        f"<tr><td>Rest of world</td><td>7–14 days</td><td>{kit.esc(symbol)}24</td></tr>"
        "</tbody></table>"
        "<h2>Returns</h2>"
        "<p>Unused items can be returned within 30 days. Write to us first so "
        "we can include a return label with your refund.</p>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "shipping.html",
        kit.page(
            title=f"Shipping — {_store(identity)}",
            description="Delivery times, costs and the returns policy.",
            body=body,
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            ".bar,main,.foot{width:min(1120px,calc(100% - 40px));margin:0 auto}"
            ".bar{display:flex;align-items:center;gap:20px;padding:22px 0;"
            "border-bottom:1px solid #e8e4de;flex-wrap:wrap}"
            ".bar .store{font-size:20px;font-weight:700;color:#231f1c;"
            "letter-spacing:.02em;margin-right:auto}"
            ".bar nav a{margin-right:20px;color:#6d655d;font-size:15px}"
            ".bar nav a.current{color:var(--accent)}"
            ".bar .cart{font-size:14px;color:#6d655d}"
            ".promo{padding:56px 0 40px;text-align:center}"
            ".promo h1{font-size:clamp(28px,4.6vw,44px);margin:0 0 12px;"
            "letter-spacing:-.02em}"
            ".promo p{color:#6d655d;max-width:52ch;margin:0 auto}"
            ".catalogue{display:grid;gap:34px 26px;padding-bottom:56px;"
            "grid-template-columns:repeat(auto-fill,minmax(230px,1fr))}"
            ".product{display:block;color:inherit}"
            ".shot{aspect-ratio:4/5;border-radius:var(--radius);"
            "background:linear-gradient(140deg,var(--tint),#e9e4dd)}"
            ".product h3{margin:14px 0 4px;font-size:16px;font-weight:600;color:#231f1c}"
            ".product p{margin:0 0 8px;font-size:14px;color:#7b736a}"
            ".price{font-weight:700;color:var(--accent-dark)}"
            ".detail{display:grid;grid-template-columns:1.1fr 1fr;gap:44px;"
            "padding:48px 0 64px;align-items:start}"
            ".shot.large{aspect-ratio:1;border-radius:var(--radius)}"
            ".info h1{font-size:30px;margin:0 0 10px}"
            ".info p{color:#5f584f}"
            ".info button{margin:22px 0 8px;background:#231f1c;color:#fff;border:0;"
            "padding:15px 34px;border-radius:var(--radius);font-size:15px;cursor:pointer}"
            ".info button:hover{background:var(--accent-dark)}"
            ".facts{padding-left:18px;color:#7b736a;font-size:14px}"
            ".page{padding:48px 0 64px;max-width:70ch}"
            ".page h1{font-size:32px;margin:0 0 14px}"
            ".page h2{font-size:20px;margin:32px 0 10px}"
            ".page p{color:#5f584f}"
            "table{width:100%;border-collapse:collapse;margin-top:18px;font-size:15px}"
            "th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #e8e4de}"
            "th{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:#8a8177}"
            ".foot{display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px;"
            "border-top:1px solid #e8e4de;padding:24px 0 48px;color:#8a8177;font-size:14px}"
            ".notfound{padding:110px 20px;text-align:center}"
            ".notfound h1{font-size:60px;margin:0;color:var(--accent)}"
            "@media(max-width:760px){.detail{grid-template-columns:1fr;gap:26px}}"
        ),
    )


__all__ = ["PAGES", "generate"]
