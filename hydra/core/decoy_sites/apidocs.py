"""Developer API reference renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/authentication.html", "/errors.html")

_NAV = (
    ("/", "Quickstart"),
    ("/authentication.html", "Authentication"),
    ("/errors.html", "Errors"),
)


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a dark developer reference with request and response samples."""
    _write_styles(site_dir, identity)
    _write_quickstart(site_dir, identity)
    _write_authentication(site_dir, identity)
    _write_errors(site_dir, identity)
    kit.write_not_found(site_dir, identity, home_label="Back to the quickstart")
    kit.write_sitemap(site_dir, identity, PAGES)


def _api(identity: SiteIdentity) -> str:
    return identity.pick(
        "api-name",
        (
            f"{identity.brand} API",
            f"{identity.slug.capitalize()} Cloud API",
            f"{identity.slug.capitalize()} Platform API",
        ),
    )


def _shell(identity: SiteIdentity, current: str, content: str) -> str:
    links = "".join(
        "<a href=\"{href}\"{mark}>{label}</a>".format(
            href=kit.esc(href),
            mark=" class=\"current\"" if href == current else "",
            label=kit.esc(label),
        )
        for href, label in _NAV
    )
    return (
        "<div class=\"shell\">"
        "<aside>"
        f"<a class=\"api\" href=\"/\">{kit.esc(_api(identity))}</a>"
        f"<span class=\"rev\">2026-0{identity.number('api-rev', 1, 9)}</span>"
        f"<nav>{links}</nav>"
        "</aside>"
        f"<main>{content}</main>"
        "</div>\n"
    )


def _endpoint(identity: SiteIdentity) -> str:
    return f"https://api.{identity.domain}/v{identity.number('api-major', 1, 3)}"


def _write_quickstart(site_dir: Path, identity: SiteIdentity) -> None:
    base = _endpoint(identity)
    content = (
        "<h1>Quickstart</h1>"
        f"<p class=\"lead\">The {kit.esc(_api(identity))} is a JSON over HTTPS "
        "interface. Every request needs a bearer token and every response is "
        "UTF-8 encoded JSON.</p>"
        "<h2>Your first request</h2>"
        f"<pre><code><span class=\"m\">GET</span> {kit.esc(base)}/projects\n"
        "Authorization: Bearer sk_live_&lt;token&gt;\n"
        "Accept: application/json</code></pre>"
        "<h2>Response</h2>"
        "<pre><code>{\n"
        "  \"object\": \"list\",\n"
        "  \"has_more\": false,\n"
        "  \"data\": [\n"
        "    { \"id\": \"prj_8fZ2\", \"name\": \"Staging\", \"region\": \"eu-central\" }\n"
        "  ]\n"
        "}</code></pre>"
        "<h2>Rate limits</h2>"
        "<p>Tokens are limited to "
        f"{identity.number('api-rate', 60, 600)} requests per minute. The "
        "remaining budget is returned in <code>X-RateLimit-Remaining</code>.</p>"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{_api(identity)} — quickstart",
            description=f"Developer reference for the {_api(identity)}.",
            body=_shell(identity, "/", content),
        ),
    )


def _write_authentication(site_dir: Path, identity: SiteIdentity) -> None:
    base = _endpoint(identity)
    content = (
        "<h1>Authentication</h1>"
        "<p class=\"lead\">Tokens are issued per environment and never "
        "expire on their own. Rotating a token revokes the previous one after "
        "a five minute overlap.</p>"
        "<h2>Header</h2>"
        "<pre><code>Authorization: Bearer sk_live_&lt;token&gt;</code></pre>"
        "<h2>Scopes</h2>"
        "<table><thead><tr><th>Scope</th><th>Grants</th></tr></thead><tbody>"
        "<tr><td><code>projects:read</code></td><td>List and read projects</td></tr>"
        "<tr><td><code>projects:write</code></td><td>Create and update projects</td></tr>"
        "<tr><td><code>events:read</code></td><td>Stream delivery events</td></tr>"
        "</tbody></table>"
        "<h2>Rotating a token</h2>"
        f"<pre><code><span class=\"m\">POST</span> {kit.esc(base)}/tokens/rotate\n"
        "Content-Type: application/json\n\n"
        "{ \"token_id\": \"tok_31aC\" }</code></pre>"
        "<div class=\"warn\">Never ship a live token to a browser client. "
        "Use a short-lived exchange token instead.</div>"
    )
    kit.write_text(
        site_dir,
        "authentication.html",
        kit.page(
            title=f"Authentication — {_api(identity)}",
            description="Bearer tokens, scopes and rotation.",
            body=_shell(identity, "/authentication.html", content),
        ),
    )


def _write_errors(site_dir: Path, identity: SiteIdentity) -> None:
    content = (
        "<h1>Errors</h1>"
        "<p class=\"lead\">Errors use standard status codes and a stable "
        "machine-readable <code>code</code>. Only the human message changes "
        "between releases.</p>"
        "<pre><code>{\n"
        "  \"error\": {\n"
        "    \"code\": \"invalid_request\",\n"
        "    \"message\": \"region is not supported\",\n"
        "    \"request_id\": \"req_5Nk09\"\n"
        "  }\n"
        "}</code></pre>"
        "<table><thead><tr><th>Status</th><th>Code</th><th>Meaning</th></tr>"
        "</thead><tbody>"
        "<tr><td>400</td><td><code>invalid_request</code></td>"
        "<td>The payload failed validation.</td></tr>"
        "<tr><td>401</td><td><code>unauthorized</code></td>"
        "<td>Missing, revoked or malformed token.</td></tr>"
        "<tr><td>409</td><td><code>conflict</code></td>"
        "<td>The resource changed since you read it.</td></tr>"
        "<tr><td>429</td><td><code>rate_limited</code></td>"
        "<td>Retry after the seconds given in the header.</td></tr>"
        "</tbody></table>"
        "<p>Always log <code>request_id</code>; support cannot trace a report "
        "without it.</p>"
    )
    kit.write_text(
        site_dir,
        "errors.html",
        kit.page(
            title=f"Errors — {_api(identity)}",
            description="Error format and status code reference.",
            body=_shell(identity, "/errors.html", content),
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            "body{background:#0d1117;color:#c9d1d9}"
            "a{color:var(--accent)}"
            ".shell{display:grid;grid-template-columns:250px 1fr;min-height:100vh}"
            "aside{border-right:1px solid #1c232d;padding:30px 22px;position:sticky;"
            "top:0;height:100vh}"
            "aside .api{display:block;font-size:17px;font-weight:700;color:#f0f6fc}"
            "aside .rev{display:inline-block;margin:8px 0 24px;font-size:12px;"
            "color:#7d8590;border:1px solid #262d38;border-radius:999px;padding:2px 10px}"
            "aside nav{display:flex;flex-direction:column;gap:2px}"
            "aside nav a{color:#96a0ad;padding:8px 10px;border-radius:6px;font-size:15px}"
            "aside nav a:hover{background:#161c24;color:#f0f6fc}"
            "aside nav a.current{background:var(--accent);color:#fff;font-weight:600}"
            "main{padding:52px 46px;max-width:880px}"
            "h1{font-size:32px;margin:0 0 12px;color:#f0f6fc}"
            "h2{font-size:19px;margin:36px 0 12px;color:#f0f6fc}"
            ".lead{font-size:17px;color:#a8b3c0}"
            "p,td{color:#a8b3c0}"
            "pre{background:#161b22;border:1px solid #21262d;border-radius:var(--radius);"
            "padding:16px 18px;overflow:auto;font-size:14px;line-height:1.6;color:#d5dce4}"
            "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}"
            "p code,td code{background:#161b22;border:1px solid #21262d;padding:1px 6px;"
            "border-radius:5px;color:var(--accent);font-size:.92em}"
            "pre .m{color:var(--accent);font-weight:700}"
            "table{width:100%;border-collapse:collapse;margin:16px 0;font-size:15px}"
            "th,td{text-align:left;padding:11px 12px;border-bottom:1px solid #21262d}"
            "th{color:#7d8590;font-size:12px;text-transform:uppercase;letter-spacing:.08em}"
            ".warn{border-left:3px solid var(--accent);background:#161b22;padding:14px 18px;"
            "margin:26px 0;border-radius:0 var(--radius) var(--radius) 0;color:#c9d1d9}"
            ".notfound{padding:120px 20px;text-align:center}"
            ".notfound h1{font-size:58px;color:var(--accent)}"
            "@media(max-width:820px){.shell{grid-template-columns:1fr}"
            "aside{position:static;height:auto}main{padding:34px 20px}}"
        ),
    )


__all__ = ["PAGES", "generate"]
