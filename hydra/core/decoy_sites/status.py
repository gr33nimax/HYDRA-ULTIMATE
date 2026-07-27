"""Service status page renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/history.html")

_COMPONENTS = (
    "Edge network",
    "Public API",
    "Object storage",
    "Dashboard",
    "Webhooks",
)


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a status page with a component list and incident history."""
    _write_styles(site_dir, identity)
    _write_index(site_dir, identity)
    _write_history(site_dir, identity)
    _write_status_json(site_dir, identity)
    kit.write_not_found(site_dir, identity, home_label="Back to status")
    kit.write_sitemap(site_dir, identity, PAGES)


def _platform(identity: SiteIdentity) -> str:
    return identity.pick(
        "status-platform",
        (
            f"{identity.brand} Cloud",
            f"{identity.brand} Platform",
            f"{identity.slug.capitalize()} Services",
        ),
    )


def _header(identity: SiteIdentity, current: str) -> str:
    links = kit.nav(
        (("/", "Current status"), ("/history.html", "History")),
        current=current,
    )
    return (
        "<header class=\"bar\">"
        f"<a class=\"brand\" href=\"/\">{kit.esc(_platform(identity))}</a>"
        f"{links}"
        "</header>\n"
    )


def _write_index(site_dir: Path, identity: SiteIdentity) -> None:
    rows = "".join(
        f"<li><span>{kit.esc(component)}</span><b>Operational</b></li>"
        for component in _COMPONENTS
    )
    uptime = identity.number("status-uptime", 9990, 9999) / 100
    body = (
        f"{_header(identity, '/')}"
        "<main>"
        "<section class=\"summary\">"
        "<i></i><strong>All systems operational</strong>"
        "<p>No incidents reported in the last 14 days.</p>"
        "</section>"
        f"<ul class=\"components\">{rows}</ul>"
        "<section class=\"metrics\">"
        f"<div><b>{uptime:.2f}%</b><span>uptime, 90 days</span></div>"
        f"<div><b>{identity.number('status-latency', 60, 180)} ms</b>"
        "<span>median API latency</span></div>"
        f"<div><b>{identity.number('status-regions', 3, 9)}</b>"
        "<span>regions monitored</span></div>"
        "</section>"
        "</main>\n"
        "<footer class=\"foot\">Status updates are published automatically "
        f"by {kit.esc(identity.brand)}.</footer>\n"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{_platform(identity)} status",
            description=f"Live service status for {_platform(identity)}.",
            body=body,
        ),
    )


def _write_history(site_dir: Path, identity: SiteIdentity) -> None:
    incidents = (
        (
            "Elevated API latency in one region",
            "Resolved",
            "A storage node was rotated out after failing its health check. "
            "Requests were served from the remaining nodes with higher latency "
            "for 22 minutes.",
        ),
        (
            "Scheduled maintenance: storage layer",
            "Completed",
            "Rolling upgrade of the storage layer. No downtime was expected "
            "and none was observed.",
        ),
        (
            "Dashboard sign-in errors",
            "Resolved",
            "A configuration change rejected sessions issued before the "
            "deploy. Affected users were signed out once.",
        ),
    )
    rows = "".join(
        "<article>"
        f"<h3>{kit.esc(title)}</h3>"
        f"<span class=\"tag\">{kit.esc(state)}</span>"
        f"<p>{kit.esc(text)}</p>"
        "</article>"
        for title, state, text in incidents
    )
    body = (
        f"{_header(identity, '/history.html')}"
        f"<main><h1>Incident history</h1><div class=\"history\">{rows}</div></main>\n"
        "<footer class=\"foot\">Older incidents are archived after 12 months."
        "</footer>\n"
    )
    kit.write_text(
        site_dir,
        "history.html",
        kit.page(
            title=f"Incident history — {_platform(identity)}",
            description="Past incidents and maintenance windows.",
            body=body,
        ),
    )


def _write_status_json(site_dir: Path, identity: SiteIdentity) -> None:
    components = ",".join(
        f'{{"name":"{component}","status":"operational"}}'
        for component in _COMPONENTS
    )
    kit.write_text(
        site_dir,
        "status.json",
        '{"status":"operational","page":"'
        + identity.domain
        + '","components":['
        + components
        + "]}\n",
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            ".bar,main,.foot{width:min(760px,calc(100% - 32px));margin:0 auto}"
            ".bar{display:flex;align-items:center;justify-content:space-between;"
            "padding:26px 0;flex-wrap:wrap;gap:12px}"
            ".bar .brand{font-size:19px;font-weight:700;color:#172033}"
            ".bar nav a{margin-left:18px;font-size:14px;color:#657086}"
            ".bar nav a.current{color:var(--accent);font-weight:600}"
            ".summary,.components,.metrics,.history article{background:var(--surface);"
            "border:1px solid #e3e8f1;border-radius:var(--radius);"
            "box-shadow:0 8px 24px rgba(24,39,75,.05)}"
            ".summary{padding:26px 28px;margin-bottom:16px}"
            ".summary i{display:inline-block;width:11px;height:11px;border-radius:50%;"
            "background:#22a06b;margin-right:10px}"
            ".summary strong{font-size:18px}"
            ".summary p{margin:8px 0 0 25px;color:#718096}"
            ".components{list-style:none;margin:0;padding:0 28px}"
            ".components li{display:flex;justify-content:space-between;padding:18px 0;"
            "border-bottom:1px solid #edf0f5}"
            ".components li:last-child{border:0}"
            ".components b{color:#16845a;font-size:14px}"
            ".metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;"
            "margin-top:16px;padding:22px 28px;text-align:center}"
            ".metrics b{display:block;font-size:22px;color:#172033}"
            ".metrics span{font-size:13px;color:#8892a4}"
            "h1{font-size:26px;margin:8px 0 16px}"
            ".history{display:grid;gap:12px}"
            ".history article{padding:20px 24px}"
            ".history h3{margin:0 0 6px;font-size:17px}"
            ".tag{display:inline-block;font-size:12px;color:var(--accent-dark);"
            "background:var(--tint);border-radius:999px;padding:2px 10px}"
            ".history p{margin:10px 0 0;color:#5c667a;font-size:15px}"
            ".foot{text-align:center;color:#929bad;font-size:13px;padding:26px 0 44px}"
            ".notfound{text-align:center;padding:100px 20px}"
            ".notfound h1{font-size:56px;color:var(--accent)}"
            "@media(max-width:560px){.metrics{grid-template-columns:1fr}}"
        ),
    )


__all__ = ["PAGES", "generate"]
