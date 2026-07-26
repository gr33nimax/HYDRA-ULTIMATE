"""Editorial media-theme decoy site renderer."""
from __future__ import annotations

from html import escape
from pathlib import Path


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
            "Labs and manufacturers are rethinking materials, recovery, and "
            "the long life of everyday energy storage.",
        ),
        (
            "Design",
            "Why calmer software is having a moment",
            "Product teams are trading endless alerts for interfaces built "
            "around focus, context, and deliberate choices.",
        ),
    ),
    "business": (
        (
            "Markets",
            "Local manufacturers find new paths to global customers",
            "Flexible production and regional logistics are changing the "
            "economics of exporting for mid-sized companies.",
        ),
        (
            "Retail",
            "The neighborhood store gets a digital second act",
            "Independent retailers are blending personal service with faster "
            "inventory, delivery, and online discovery.",
        ),
        (
            "Leadership",
            "What long-term planning looks like in an uncertain year",
            "Executives are replacing single forecasts with decisions that "
            "remain useful across several plausible futures.",
        ),
        (
            "Economy",
            "A practical guide to the next wave of urban investment",
            "Housing, transit, and public space are drawing renewed attention "
            "from cities seeking durable growth.",
        ),
    ),
    "culture": (
        (
            "Books",
            "The independent bookshop becomes a community newsroom",
            "Events, local publishing, and thoughtful recommendations are "
            "giving small shops a wider cultural role.",
        ),
        (
            "Food",
            "A seasonal pantry built for busy weeks",
            "Chefs share a flexible approach to grains, greens, sauces, and "
            "the ingredients that make simple meals feel complete.",
        ),
        (
            "Architecture",
            "Old industrial spaces find a more public future",
            "Across several cities, careful renovations are turning former "
            "factories into libraries, workshops, and gathering places.",
        ),
        (
            "Travel",
            "The case for seeing one place slowly",
            "Longer stays and lighter schedules can reveal the everyday "
            "rhythms that hurried itineraries routinely miss.",
        ),
    ),
}


def generate(site_dir: Path) -> None:
    """Render every file in the media theme."""
    _write_index(site_dir)
    for section, stories in _SECTIONS.items():
        _write_section(site_dir, section, stories)
    _write_about(site_dir)
    _write_assets(site_dir)
    _write_metadata(site_dir)


def _write_index(site_dir: Path) -> None:
    latest = [
        (*_SECTIONS["technology"][1], "technology.html"),
        (*_SECTIONS["business"][0], "business.html"),
        (*_SECTIONS["culture"][2], "culture.html"),
        (*_SECTIONS["technology"][3], "technology.html"),
    ]
    cards = "".join(
        _story_card(kicker, title, summary, link)
        for kicker, title, summary, link in latest
    )
    content = f"""
<main id="main">
  <section class="edition shell">
    <p>Independent reporting on the ideas shaping everyday life.</p>
    <span>Sunday edition · Updated throughout the day</span>
  </section>
  <section class="lead-grid shell">
    <article class="lead-story">
      <div class="visual visual-coral"><span>Field notes</span></div>
      <p class="kicker">Cities</p>
      <h1>How public spaces are being redesigned for a warmer world</h1>
      <p class="dek">Shade, water, and flexible streets are moving from
      experiments to essential parts of urban planning.</p>
      <a class="story-link" href="technology.html">Read the report</a>
    </article>
    <div class="side-stories">
      <article>
        <div class="visual visual-blue"><span>Business</span></div>
        <p class="kicker">New economy</p>
        <h2>Small manufacturers find a global audience</h2>
        <a href="business.html">6 min read</a>
      </article>
      <article class="brief">
        <p class="kicker">Culture</p>
        <h2>Why the local library is becoming a creative studio</h2>
        <p>Workshops and shared tools expand a familiar civic institution.</p>
        <a href="culture.html">4 min read</a>
      </article>
    </div>
  </section>
  <section class="story-section shell">
    <div class="section-heading">
      <h2>Latest stories</h2><a href="technology.html">View all</a>
    </div>
    <div class="card-grid">{cards}</div>
  </section>
  <section class="dispatch shell">
    <div>
      <p class="kicker">The weekend dispatch</p>
      <h2>A useful briefing, without the noise</h2>
      <p>Our editors select the week’s clearest reporting on technology,
      business, cities, and culture.</p>
    </div>
    <form><label for="email">Email address</label>
      <div><input id="email" type="email" placeholder="you@example.com">
      <button type="button">Subscribe</button></div>
    </form>
  </section>
  <section class="most-read shell">
    <div class="section-heading"><h2>Most read</h2></div>
    <ol>
      <li><a href="business.html">The new economics of the neighborhood shop</a>
      <span>Business · 8 min</span></li>
      <li><a href="technology.html">What quieter software gets right</a>
      <span>Technology · 5 min</span></li>
      <li><a href="culture.html">A better way to spend a day in a new city</a>
      <span>Travel · 7 min</span></li>
    </ol>
  </section>
</main>"""
    (site_dir / "index.html").write_text(
        _page("Independent news and ideas", "", content),
        encoding="utf-8",
    )


def _write_section(
    site_dir: Path,
    section: str,
    stories: tuple[tuple[str, str, str], ...],
) -> None:
    cards = "".join(
        _story_card(kicker, title, summary, f"{section}.html")
        for kicker, title, summary in stories
    )
    title = section.title()
    content = f"""
<main id="main" class="shell section-page">
  <header class="section-title">
    <p class="kicker">Meridian desk</p>
    <h1>{title}</h1>
    <p>Clear reporting and useful perspective from our {section} editors.</p>
  </header>
  <div class="section-lead">
    <div class="visual visual-{_section_color(section)}">
      <span>Editor’s pick</span>
    </div>
    <div>
      <p class="kicker">{escape(stories[0][0])}</p>
      <h2>{escape(stories[0][1])}</h2>
      <p>{escape(stories[0][2])}</p>
      <span class="byline">By the Meridian Daily newsroom · 7 min read</span>
    </div>
  </div>
  <div class="section-heading"><h2>More from {title}</h2></div>
  <div class="card-grid">{cards}</div>
</main>"""
    (site_dir / f"{section}.html").write_text(
        _page(f"{title} news and analysis", section, content),
        encoding="utf-8",
    )


def _write_about(site_dir: Path) -> None:
    content = """
<main id="main" class="shell about-page">
  <header class="section-title">
    <p class="kicker">About us</p>
    <h1>Reporting for curious people</h1>
    <p>Meridian Daily is an independent digital publication focused on the
    decisions, ideas, and culture shaping modern life.</p>
  </header>
  <div class="about-grid">
    <section><h2>Our approach</h2><p>We value clarity over volume. Our editors
    work across technology, business, cities, and culture to explain what
    changed, why it matters, and what deserves attention next.</p></section>
    <section><h2>Our standards</h2><p>Every story is reviewed for accuracy,
    context, and fairness. Corrections are made transparently, and reporting
    is kept separate from commercial partnerships.</p></section>
    <section><h2>Our readers</h2><p>Meridian reaches professionals, students,
    builders, and lifelong learners across more than 40 countries.</p></section>
    <section><h2>Contact</h2><p>News tips and general correspondence can be
    sent to the editorial desk. We review messages during business hours.</p>
    </section>
  </div>
</main>"""
    (site_dir / "about.html").write_text(
        _page("About", "about", content),
        encoding="utf-8",
    )


def _story_card(kicker: str, title: str, summary: str, link: str) -> str:
    return f"""
<article class="story-card">
  <div class="visual visual-small"><span>{escape(kicker)}</span></div>
  <p class="kicker">{escape(kicker)}</p>
  <h3><a href="{escape(link)}">{escape(title)}</a></h3>
  <p>{escape(summary)}</p><span class="byline">5 min read</span>
</article>"""


def _page(title: str, active: str, content: str) -> str:
    navigation = "".join(
        '<a href="{}"{}>{}</a>'.format(
            href,
            ' class="active"' if key == active else "",
            label,
        )
        for key, label, href in (
            ("technology", "Technology", "technology.html"),
            ("business", "Business", "business.html"),
            ("culture", "Culture", "culture.html"),
            ("about", "About", "about.html"),
        )
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="description" content="Independent reporting on technology,
  business, cities, and culture.">
  <title>{escape(title)} | Meridian Daily</title>
  <link rel="icon" href="favicon.ico">
  <link rel="manifest" href="site.webmanifest">
  <link rel="stylesheet" href="css/style.css">
</head>
<body>
  <a class="skip-link" href="#main">Skip to content</a>
  <div class="topline"><div class="shell">
    <span id="current-date">Today</span><span>Global edition</span>
  </div></div>
  <header class="site-header">
    <div class="brand-row shell">
      <a class="brand" href="index.html">Meridian <b>Daily</b></a>
      <button class="menu-button" aria-expanded="false"
      aria-controls="site-nav">Sections</button>
    </div>
    <nav id="site-nav" class="site-nav shell" aria-label="Primary">
      <a href="index.html"{' class="active"' if not active else ""}>Latest</a>
      {navigation}
    </nav>
  </header>
  {content}
  <footer class="site-footer"><div class="shell footer-grid">
    <div><a class="brand light" href="index.html">Meridian <b>Daily</b></a>
    <p>Independent news and ideas for a changing world.</p></div>
    <div><h2>Sections</h2><a href="technology.html">Technology</a>
    <a href="business.html">Business</a><a href="culture.html">Culture</a></div>
    <div><h2>Company</h2><a href="about.html">About</a>
    <a href="about.html">Editorial standards</a>
    <a href="about.html">Contact</a></div>
  </div><div class="shell legal">© <span id="current-year"></span>
  Meridian Daily</div></footer>
  <script src="js/site.js"></script>
</body>
</html>
"""


def _section_color(section: str) -> str:
    return {"technology": "blue", "business": "gold", "culture": "coral"}[
        section
    ]


def _write_assets(site_dir: Path) -> None:
    (site_dir / "css" / "style.css").write_text(_STYLES, encoding="utf-8")
    (site_dir / "js" / "site.js").write_text(_SCRIPT, encoding="utf-8")


def _write_metadata(site_dir: Path) -> None:
    (site_dir / "robots.txt").write_text(
        "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n",
        encoding="utf-8",
    )
    pages = ("", "technology.html", "business.html", "culture.html", "about.html")
    urls = "".join(f"<url><loc>/{page}</loc></url>" for page in pages)
    (site_dir / "sitemap.xml").write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{urls}</urlset>\n",
        encoding="utf-8",
    )
    (site_dir / "site.webmanifest").write_text(
        '{"name":"Meridian Daily","short_name":"Meridian",'
        '"start_url":"/","display":"standalone",'
        '"background_color":"#f6f3ec","theme_color":"#181815"}\n',
        encoding="utf-8",
    )


_SCRIPT = """const button = document.querySelector(".menu-button");
const nav = document.querySelector(".site-nav");
const date = document.querySelector("#current-date");
const year = document.querySelector("#current-year");
if (date) date.textContent = new Intl.DateTimeFormat("en", {dateStyle: "full"}).format(new Date());
if (year) year.textContent = String(new Date().getFullYear());
if (button && nav) {
  button.addEventListener("click", () => {
    const open = button.getAttribute("aria-expanded") === "true";
    button.setAttribute("aria-expanded", String(!open));
    nav.classList.toggle("open", !open);
  });
}
"""


_STYLES = """
:root {
  --paper: #f6f3ec; --ink: #181815; --muted: #68675f;
  --line: #d7d1c5; --accent: #d9472f; --white: #fffdf8;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0; color: var(--ink); background: var(--paper);
  font-family: Arial, Helvetica, sans-serif; line-height: 1.55;
}
a { color: inherit; text-decoration-color: #9b978e; }
a:hover { color: var(--accent); }
.shell { width: min(1180px, calc(100% - 40px)); margin: 0 auto; }
.skip-link { position: absolute; left: -9999px; }
.skip-link:focus { left: 16px; top: 16px; z-index: 10; background: white; padding: 10px; }
.topline { background: var(--ink); color: #ddd8cf; font-size: .74rem; }
.topline .shell { min-height: 34px; display: flex; align-items: center;
  justify-content: space-between; letter-spacing: .04em; }
.site-header { background: var(--white); border-bottom: 1px solid var(--ink); }
.brand-row { min-height: 94px; display: flex; align-items: center;
  justify-content: space-between; }
.brand { color: var(--ink); font: 700 clamp(2rem, 5vw, 3.65rem)/1 Georgia, serif;
  letter-spacing: -.055em; text-decoration: none; }
.brand b { color: var(--accent); font-weight: inherit; }
.site-nav { display: flex; gap: 30px; align-items: center; min-height: 46px;
  border-top: 1px solid var(--line); font-size: .78rem; font-weight: 700;
  letter-spacing: .09em; text-transform: uppercase; }
.site-nav a { text-decoration: none; }
.site-nav a.active { color: var(--accent); }
.menu-button { display: none; border: 1px solid var(--ink); background: transparent;
  padding: 8px 11px; font-weight: 700; }
.edition { display: flex; justify-content: space-between; gap: 24px;
  padding: 22px 0; border-bottom: 1px solid var(--line); color: var(--muted); }
.edition p { margin: 0; color: var(--ink); font-family: Georgia, serif; }
.edition span { font-size: .8rem; }
.lead-grid { display: grid; grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
  gap: 38px; padding: 34px 0 48px; border-bottom: 1px solid var(--ink); }
.visual { min-height: 260px; padding: 18px; display: flex; align-items: flex-end;
  color: white; overflow: hidden; position: relative; }
.visual::before { content: ""; position: absolute; inset: 12% 9%;
  border: 1px solid rgba(255,255,255,.45); transform: rotate(-4deg); }
.visual span { z-index: 1; font-size: .72rem; font-weight: 700;
  letter-spacing: .12em; text-transform: uppercase; }
.visual-coral { background: linear-gradient(135deg, #762f29, #db664e 55%, #e7af7c); }
.visual-blue { background: linear-gradient(135deg, #17364b, #407e99 55%, #9bc4c7); }
.visual-gold { background: linear-gradient(135deg, #544321, #ab812f 55%, #dbc58a); }
.lead-story h1 { max-width: 820px; margin: 8px 0 12px;
  font: 700 clamp(2.25rem, 5vw, 4.55rem)/.98 Georgia, serif;
  letter-spacing: -.045em; }
.kicker { margin: 18px 0 6px; color: var(--accent); font-size: .7rem;
  font-weight: 800; letter-spacing: .13em; text-transform: uppercase; }
.dek { max-width: 740px; color: var(--muted); font: 1.2rem/1.55 Georgia, serif; }
.story-link { font-weight: 700; text-underline-offset: 4px; }
.side-stories { display: grid; gap: 26px; }
.side-stories article + article { border-top: 1px solid var(--line); }
.side-stories h2 { margin: 5px 0 10px; font: 700 1.7rem/1.08 Georgia, serif; }
.side-stories p { color: var(--muted); }
.side-stories a, .byline { color: var(--muted); font-size: .76rem; }
.story-section, .most-read { padding: 50px 0; }
.section-heading { display: flex; align-items: baseline; justify-content: space-between;
  margin-bottom: 24px; border-top: 3px solid var(--ink); }
.section-heading h2 { margin: 12px 0 0; font: 700 1.65rem/1 Georgia, serif; }
.section-heading a { font-size: .75rem; font-weight: 700; }
.card-grid {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px;
}
.story-card { min-width: 0; }
.visual-small { min-height: 145px; background: linear-gradient(145deg, #353a38, #77817b); }
.story-card:nth-child(2) .visual-small { background: linear-gradient(145deg, #283e55, #7994a5); }
.story-card:nth-child(3) .visual-small { background: linear-gradient(145deg, #643c35, #c98872); }
.story-card:nth-child(4) .visual-small { background: linear-gradient(145deg, #514525, #b09a57); }
.story-card h3 { margin: 5px 0 8px; font: 700 1.25rem/1.16 Georgia, serif; }
.story-card h3 a { text-decoration: none; }
.story-card > p:not(.kicker) { color: var(--muted); font-size: .9rem; }
.dispatch { display: grid; grid-template-columns: 1fr 1fr; gap: 60px;
  padding: 42px; background: #243f46; color: white; }
.dispatch h2 { margin: 5px 0; font: 700 2rem/1.1 Georgia, serif; }
.dispatch p { color: #d8e1df; }
.dispatch label { display: block; margin-bottom: 8px; font-size: .8rem; }
.dispatch form { align-self: center; }
.dispatch form div { display: flex; }
.dispatch input { min-width: 0; flex: 1; border: 0; padding: 13px; font: inherit; }
.dispatch button { border: 0; background: var(--accent); color: white;
  padding: 0 18px; font-weight: 700; }
.most-read ol { list-style: none; counter-reset: item; margin: 0; padding: 0;
  display: grid; grid-template-columns: repeat(3, 1fr); }
.most-read li { counter-increment: item; display: grid; grid-template-columns: 42px 1fr;
  padding: 0 26px; border-left: 1px solid var(--line); }
.most-read li::before { content: "0" counter(item); grid-row: 1 / 3;
  color: var(--accent); font: 700 1.35rem Georgia, serif; }
.most-read li a { font: 700 1.05rem/1.2 Georgia, serif; }
.most-read li span { grid-column: 2; color: var(--muted); font-size: .72rem; }
.section-page, .about-page { padding-bottom: 70px; }
.section-title { max-width: 790px; padding: 62px 0 36px; }
.section-title h1 { margin: 5px 0 12px;
  font: 700 clamp(3rem, 7vw, 6rem)/.92 Georgia, serif; letter-spacing: -.055em; }
.section-title > p:last-child { color: var(--muted); font-size: 1.12rem; }
.section-lead { display: grid; grid-template-columns: 1.25fr 1fr; gap: 38px;
  align-items: center; padding-bottom: 50px; }
.section-lead h2 { margin: 6px 0 12px; font: 700 2.3rem/1.03 Georgia, serif; }
.section-lead > div:last-child > p:not(.kicker) { color: var(--muted); }
.about-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 60px;
  border-top: 3px solid var(--ink); }
.about-grid section { padding: 26px 0; border-bottom: 1px solid var(--line); }
.about-grid h2 { font: 700 1.45rem Georgia, serif; }
.about-grid p { color: var(--muted); }
.site-footer { background: var(--ink); color: #d1ccc2; padding: 54px 0 24px; }
.brand.light { color: white; font-size: 2rem; }
.footer-grid { display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 50px; }
.footer-grid h2 { color: white; font-size: .72rem; letter-spacing: .12em;
  text-transform: uppercase; }
.footer-grid a:not(.brand) { display: block; margin: 8px 0; font-size: .86rem; }
.legal { margin-top: 42px; padding-top: 20px; border-top: 1px solid #444;
  color: #918d86; font-size: .72rem; }
@media (max-width: 820px) {
  .menu-button { display: block; }
  .site-nav { display: none; flex-wrap: wrap; gap: 15px 24px; padding: 14px 0; }
  .site-nav.open { display: flex; }
  .lead-grid, .section-lead { grid-template-columns: 1fr; }
  .card-grid { grid-template-columns: 1fr 1fr; }
  .dispatch { grid-template-columns: 1fr; gap: 20px; padding: 30px; }
  .most-read ol { grid-template-columns: 1fr; gap: 24px; }
  .footer-grid { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 540px) {
  .shell { width: min(100% - 24px, 1180px); }
  .brand-row { min-height: 74px; }
  .brand { font-size: 2.25rem; }
  .edition { display: block; }
  .edition span { display: block; margin-top: 5px; }
  .lead-grid { gap: 28px; padding-top: 22px; }
  .visual { min-height: 210px; }
  .card-grid, .about-grid { grid-template-columns: 1fr; }
  .dispatch form div { display: block; }
  .dispatch input, .dispatch button { width: 100%; min-height: 46px; }
  .footer-grid { grid-template-columns: 1fr; gap: 20px; }
}
"""
