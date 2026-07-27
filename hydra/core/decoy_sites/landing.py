"""Digital agency landing page renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/about.html", "/contact.html")


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a small agency site with home, about and contact pages."""
    _write_styles(site_dir, identity)
    _write_index(site_dir, identity)
    _write_about(site_dir, identity)
    _write_contact(site_dir, identity)
    kit.write_not_found(site_dir, identity)
    kit.write_sitemap(site_dir, identity, PAGES)


def _header(identity: SiteIdentity, current: str) -> str:
    links = kit.nav(
        (
            ("/", "Home"),
            ("/about.html", "About"),
            ("/contact.html", "Contact"),
        ),
        current=current,
    )
    return (
        "<header class=\"top\"><div class=\"wrap\">"
        f"<a class=\"brand\" href=\"/\">{kit.esc(identity.brand)}</a>"
        f"{links}"
        "</div></header>\n"
    )


def _footer(identity: SiteIdentity) -> str:
    return (
        "<footer class=\"foot\"><div class=\"wrap\">"
        f"<span>© {identity.founded} {kit.esc(identity.brand)}</span>"
        f"<span>{kit.esc(identity.city)} · "
        f"<a href=\"mailto:{kit.esc(identity.email)}\">{kit.esc(identity.email)}</a>"
        "</span>"
        "</div></footer>\n"
    )


def _write_index(site_dir: Path, identity: SiteIdentity) -> None:
    promise = identity.pick(
        "landing-hero",
        (
            "Digital products that earn their keep",
            "Strategy, design and delivery under one roof",
            "We build the software behind growing businesses",
            "Product teams that ship, not slide decks",
        ),
    )
    services = (
        ("Product strategy", "Discovery workshops, roadmaps and measurable scope."),
        ("Design systems", "Interfaces that stay consistent as the team grows."),
        ("Platform engineering", "Reliable delivery pipelines and cloud foundations."),
    )
    cards = "".join(
        f"<article><h3>{kit.esc(title)}</h3><p>{kit.esc(text)}</p></article>"
        for title, text in services
    )
    delivered = identity.number("landing-projects", 40, 120)
    body = (
        f"{_header(identity, '/')}"
        "<main>"
        "<section class=\"hero\"><div class=\"wrap\">"
        f"<h1>{kit.esc(promise)}</h1>"
        f"<p>{kit.esc(identity.brand)} is an independent studio in "
        f"{kit.esc(identity.city)} working with founders and in-house teams "
        "from first sketch to production.</p>"
        "<a class=\"cta\" href=\"/contact.html\">Start a project</a>"
        "</div></section>"
        f"<section class=\"services\"><div class=\"wrap\">{cards}</div></section>"
        "<section class=\"proof\"><div class=\"wrap\">"
        f"<strong>{delivered}+</strong>"
        f"<span>projects delivered since {identity.founded}</span>"
        "</div></section>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{identity.brand} — digital studio",
            description=(
                f"{identity.brand} builds digital products in {identity.city}."
            ),
            body=body,
        ),
    )


def _write_about(site_dir: Path, identity: SiteIdentity) -> None:
    body = (
        f"{_header(identity, '/about.html')}"
        "<main class=\"page\"><div class=\"wrap\">"
        "<h1>About the studio</h1>"
        f"<p>{kit.esc(identity.brand)} started in {identity.founded} as a "
        "two-person consultancy and now works as a small senior team. We take "
        "a limited number of engagements so every project keeps the people who "
        "scoped it.</p>"
        "<h2>How we work</h2>"
        "<ul>"
        "<li>A fixed discovery phase before any estimate.</li>"
        "<li>Weekly demos instead of status reports.</li>"
        "<li>Handover with documentation, not a support contract.</li>"
        "</ul>"
        f"<p>The studio is based in {kit.esc(identity.city)} and collaborates "
        "remotely across European time zones.</p>"
        "</div></main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "about.html",
        kit.page(
            title=f"About — {identity.brand}",
            description=f"How {identity.brand} runs projects.",
            body=body,
        ),
    )


def _write_contact(site_dir: Path, identity: SiteIdentity) -> None:
    body = (
        f"{_header(identity, '/contact.html')}"
        "<main class=\"page\"><div class=\"wrap\">"
        "<h1>Contact</h1>"
        "<p>Tell us what you are building and when it needs to be live. "
        "We reply within two working days.</p>"
        "<dl class=\"contact\">"
        f"<dt>Email</dt><dd><a href=\"mailto:{kit.esc(identity.email)}\">"
        f"{kit.esc(identity.email)}</a></dd>"
        f"<dt>Studio</dt><dd>{kit.esc(identity.city)}</dd>"
        "<dt>Hours</dt><dd>Monday to Friday, 09:00–18:00 CET</dd>"
        "</dl>"
        "</div></main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "contact.html",
        kit.page(
            title=f"Contact — {identity.brand}",
            description=f"Get in touch with {identity.brand}.",
            body=body,
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            ".wrap{width:min(1080px,calc(100% - 40px));margin:0 auto}"
            ".top{background:var(--surface);border-bottom:1px solid #e6e8ef;"
            "position:sticky;top:0}"
            ".top .wrap{display:flex;align-items:center;justify-content:space-between;"
            "height:72px}"
            ".brand{font-weight:700;font-size:19px;color:#141a26;letter-spacing:-.01em}"
            "nav a{margin-left:26px;color:#5b6478;font-size:15px}"
            "nav a.current{color:var(--accent);font-weight:600}"
            ".hero{padding:96px 0 72px;"
            "background:linear-gradient(180deg,var(--tint),var(--backdrop))}"
            ".hero h1{font-size:clamp(32px,5vw,52px);line-height:1.1;margin:0 0 20px;"
            "max-width:16ch}"
            ".hero p{font-size:19px;color:#4a5364;max-width:60ch;margin:0 0 32px}"
            ".cta{display:inline-block;background:var(--accent);color:#fff;"
            "padding:14px 28px;border-radius:var(--radius);font-weight:600}"
            ".cta:hover{background:var(--accent-dark);color:#fff}"
            ".services .wrap{display:grid;gap:24px;"
            "grid-template-columns:repeat(auto-fit,minmax(260px,1fr));padding:64px 0}"
            ".services article{background:var(--surface);border:1px solid #e6e8ef;"
            "border-radius:var(--radius);padding:28px}"
            ".services h3{margin:0 0 10px;font-size:18px}"
            ".services p{margin:0;color:#5b6478}"
            ".proof{background:#141a26;color:#fff;padding:48px 0}"
            ".proof .wrap{display:flex;align-items:baseline;gap:16px}"
            ".proof strong{font-size:40px;color:var(--accent)}"
            ".proof span{color:#aeb6c6}"
            ".page{padding:64px 0}.page h1{font-size:36px;margin:0 0 18px}"
            ".page h2{font-size:22px;margin:32px 0 12px}"
            ".page p,.page li{color:#4a5364;max-width:70ch}"
            ".contact dt{font-weight:600;margin-top:16px}"
            ".contact dd{margin:4px 0 0;color:#4a5364}"
            ".foot{border-top:1px solid #e6e8ef;background:var(--surface);"
            "padding:28px 0;margin-top:40px}"
            ".foot .wrap{display:flex;justify-content:space-between;flex-wrap:wrap;"
            "gap:12px;color:#7a8296;font-size:14px}"
            ".notfound{padding:120px 20px;text-align:center}"
            ".notfound h1{font-size:64px;margin:0;color:var(--accent)}"
            "@media(max-width:640px){.top .wrap{height:auto;padding:16px 0;"
            "flex-direction:column;gap:12px}nav a{margin:0 14px 0 0}"
            ".hero{padding:56px 0 44px}}"
        ),
    )


__all__ = ["PAGES", "generate"]
