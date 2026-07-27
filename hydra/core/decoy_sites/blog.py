"""Personal engineering blog renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/about.html", "/posts/queues.html", "/posts/migrations.html")

_POSTS = (
    (
        "posts/queues.html",
        "What I learned running a queue nobody owned",
        "March 4",
        (
            "The queue had been in production for six years and had no owner. "
            "Every team pushed into it, nobody watched it, and the retry policy "
            "was whatever the first client had configured in 2019.",
            "The fix was not a rewrite. We added a dashboard, named an owner, "
            "and wrote down which messages were allowed to be lost. Two of "
            "those three cost nothing.",
            "A year later the queue is still the same software. It is simply "
            "no longer a mystery, which turns out to be most of the value.",
        ),
    ),
    (
        "posts/migrations.html",
        "Migrations that can be stopped halfway",
        "January 22",
        (
            "A migration you cannot abort is a deployment with a hostage. The "
            "useful question is not how long it takes, but what happens if you "
            "stop it at minute three.",
            "Writing the rollback first changes the design. Suddenly you want "
            "the new column to be nullable, the backfill to be idempotent and "
            "the switch to be one small commit.",
            "None of this is clever. It is just the difference between a "
            "Tuesday and an incident review.",
        ),
    ),
)


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a personal blog with two posts and an about page."""
    _write_styles(site_dir, identity)
    _write_index(site_dir, identity)
    _write_about(site_dir, identity)
    for relative, title, date, paragraphs in _POSTS:
        _write_post(site_dir, identity, relative, title, date, paragraphs)
    kit.write_not_found(site_dir, identity)
    kit.write_sitemap(site_dir, identity, PAGES)


def _masthead(identity: SiteIdentity) -> str:
    subtitle = identity.pick(
        "blog-subtitle",
        (
            "notes on backend systems and the teams that run them",
            "writing about software that has to stay up",
            "field notes from distributed systems work",
        ),
    )
    return (
        "<header class=\"masthead\">"
        f"<a class=\"title\" href=\"/\">{kit.esc(identity.person)}</a>"
        f"<p>{kit.esc(subtitle)}</p>"
        "<nav><a href=\"/\">Posts</a><a href=\"/about.html\">About</a>"
        f"<a href=\"mailto:{kit.esc(identity.email)}\">Email</a></nav>"
        "</header>\n"
    )


def _footer(identity: SiteIdentity) -> str:
    return (
        "<footer class=\"foot\">"
        f"<span>{kit.esc(identity.person)} · {kit.esc(identity.city)}</span>"
        f"<span>© {identity.founded}–{identity.founded + 6}</span>"
        "</footer>\n"
    )


def _write_index(site_dir: Path, identity: SiteIdentity) -> None:
    entries = "".join(
        "<article class=\"entry\">"
        f"<time>{kit.esc(date)}</time>"
        f"<h2><a href=\"/{kit.esc(relative)}\">{kit.esc(title)}</a></h2>"
        f"<p>{kit.esc(paragraphs[0])}</p>"
        f"<a class=\"more\" href=\"/{kit.esc(relative)}\">Read the post →</a>"
        "</article>"
        for relative, title, date, paragraphs in _POSTS
    )
    body = (
        f"{_masthead(identity)}"
        f"<main class=\"feed\">{entries}</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{identity.person} — notes",
            description=f"Writing by {identity.person} about backend systems.",
            body=body,
        ),
    )


def _write_post(
    site_dir: Path,
    identity: SiteIdentity,
    relative: str,
    title: str,
    date: str,
    paragraphs: tuple[str, ...],
) -> None:
    text = "".join(f"<p>{kit.esc(item)}</p>" for item in paragraphs)
    body = (
        "<header class=\"masthead compact\">"
        f"<a class=\"title\" href=\"/\">{kit.esc(identity.person)}</a>"
        "</header>\n"
        "<main class=\"post\">"
        f"<time>{kit.esc(date)}</time>"
        f"<h1>{kit.esc(title)}</h1>"
        f"{text}"
        "<p class=\"back\"><a href=\"/\">← All posts</a></p>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        relative,
        kit.page(
            title=f"{title} — {identity.person}",
            description=paragraphs[0][:150],
            body=body,
            stylesheet="css/style.css",
        ),
    )


def _write_about(site_dir: Path, identity: SiteIdentity) -> None:
    role = identity.pick(
        "blog-role",
        (
            "platform engineer",
            "backend engineer",
            "site reliability engineer",
        ),
    )
    body = (
        f"{_masthead(identity)}"
        "<main class=\"post\">"
        "<h1>About</h1>"
        f"<p>I am {kit.esc(identity.person)}, a {kit.esc(role)} based in "
        f"{kit.esc(identity.city)}. I have spent the last "
        f"{identity.number('blog-years', 6, 14)} years on systems that were "
        "already in production when I arrived.</p>"
        "<p>This site is where I write things down so I stop explaining them "
        "twice. No newsletter, no comments — replies by email are welcome.</p>"
        f"<p><a href=\"mailto:{kit.esc(identity.email)}\">"
        f"{kit.esc(identity.email)}</a></p>"
        "</main>\n"
        f"{_footer(identity)}"
    )
    kit.write_text(
        site_dir,
        "about.html",
        kit.page(
            title=f"About — {identity.person}",
            description=f"About {identity.person}.",
            body=body,
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            "body{background:var(--backdrop)}"
            ".masthead,.feed,.post,.foot{width:min(680px,calc(100% - 40px));"
            "margin:0 auto}"
            ".masthead{padding:64px 0 34px;border-bottom:1px solid #e2e0dc}"
            ".masthead.compact{padding:34px 0 24px}"
            ".masthead .title{font-size:30px;font-weight:700;color:#1c1a17;"
            "letter-spacing:-.02em}"
            ".masthead p{margin:8px 0 18px;color:#6f6a63}"
            ".masthead nav a{margin-right:20px;font-size:15px}"
            ".feed{padding:12px 0 40px}"
            ".entry{padding:34px 0;border-bottom:1px solid #e9e7e3}"
            ".entry time,.post time{display:block;font-size:13px;"
            "text-transform:uppercase;letter-spacing:.08em;color:#9a938a}"
            ".entry h2{margin:8px 0 12px;font-size:25px;line-height:1.25}"
            ".entry h2 a{color:#1c1a17}"
            ".entry h2 a:hover{color:var(--accent)}"
            ".entry p{margin:0 0 14px;color:#544e47}"
            ".more{font-size:15px;font-weight:600}"
            ".post{padding:24px 0 56px}"
            ".post h1{font-size:33px;line-height:1.2;margin:10px 0 22px}"
            ".post p{color:#3f3a34;font-size:17px;margin:0 0 20px}"
            ".post .back{margin-top:34px;font-size:15px}"
            ".foot{display:flex;justify-content:space-between;gap:12px;"
            "padding:24px 0 48px;border-top:1px solid #e2e0dc;color:#8d8780;"
            "font-size:14px}"
            ".notfound{text-align:center;padding:110px 20px}"
            ".notfound h1{font-size:58px;margin:0;color:var(--accent)}"
            "@media(max-width:620px){.masthead{padding:40px 0 26px}"
            ".masthead .title{font-size:26px}.entry h2{font-size:22px}"
            ".post h1{font-size:28px}.post p{font-size:16px}}"
        ),
    )


__all__ = ["PAGES", "generate"]
