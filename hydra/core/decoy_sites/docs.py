"""Product documentation renderer."""
from __future__ import annotations

from pathlib import Path

from hydra.core.decoy_sites import kit
from hydra.core.decoy_sites.identity import SiteIdentity


PAGES = ("/", "/install.html", "/configuration.html")

_NAV = (
    ("/", "Overview"),
    ("/install.html", "Installation"),
    ("/configuration.html", "Configuration"),
)


def generate(site_dir: Path, identity: SiteIdentity) -> None:
    """Generate a documentation site with sidebar navigation."""
    _write_styles(site_dir, identity)
    _write_overview(site_dir, identity)
    _write_install(site_dir, identity)
    _write_configuration(site_dir, identity)
    kit.write_not_found(site_dir, identity)
    kit.write_sitemap(site_dir, identity, PAGES)


def _product(identity: SiteIdentity) -> str:
    return identity.pick(
        "docs-product",
        (
            f"{identity.slug.capitalize()}DB",
            f"{identity.slug.capitalize()}Queue",
            f"{identity.slug.capitalize()}Mesh",
            f"{identity.slug.capitalize()}Store",
        ),
    )


def _shell(identity: SiteIdentity, current: str, content: str) -> str:
    product = _product(identity)
    links = "".join(
        "<a href=\"{href}\"{mark}>{label}</a>".format(
            href=kit.esc(href),
            mark=" class=\"current\"" if href == current else "",
            label=kit.esc(label),
        )
        for href, label in _NAV
    )
    return (
        "<div class=\"layout\">"
        "<aside>"
        f"<a class=\"product\" href=\"/\">{kit.esc(product)}</a>"
        f"<span class=\"version\">v{identity.number('docs-major', 2, 6)}."
        f"{identity.number('docs-minor', 0, 9)}</span>"
        f"<nav>{links}</nav>"
        f"<p class=\"vendor\">Maintained by {kit.esc(identity.brand)}</p>"
        "</aside>"
        f"<main>{content}</main>"
        "</div>\n"
    )


def _write_overview(site_dir: Path, identity: SiteIdentity) -> None:
    product = _product(identity)
    content = (
        f"<h1>{kit.esc(product)} documentation</h1>"
        f"<p class=\"lead\">{kit.esc(product)} stores append-only event "
        "streams and serves them back with predictable latency. This "
        "documentation covers self-hosted deployments.</p>"
        "<h2>Where to start</h2>"
        "<ul>"
        "<li><a href=\"/install.html\">Install the server</a> on a single "
        "node and confirm it accepts writes.</li>"
        "<li><a href=\"/configuration.html\">Review the configuration</a> "
        "before exposing the node to other services.</li>"
        "</ul>"
        "<h2>Supported platforms</h2>"
        "<table><thead><tr><th>Platform</th><th>Status</th></tr></thead>"
        "<tbody>"
        "<tr><td>Linux x86-64</td><td>Supported</td></tr>"
        "<tr><td>Linux arm64</td><td>Supported</td></tr>"
        "<tr><td>macOS</td><td>Development only</td></tr>"
        "</tbody></table>"
    )
    kit.write_text(
        site_dir,
        "index.html",
        kit.page(
            title=f"{product} documentation",
            description=f"Self-hosting guide for {product}.",
            body=_shell(identity, "/", content),
        ),
    )


def _write_install(site_dir: Path, identity: SiteIdentity) -> None:
    product = _product(identity)
    package = identity.slug
    content = (
        "<h1>Installation</h1>"
        "<p class=\"lead\">Packages are published for Debian and RPM based "
        "distributions. Every release is signed.</p>"
        "<h2>Package repository</h2>"
        "<pre><code>curl -fsSL https://"
        f"{kit.esc(identity.domain)}/keys/release.asc | sudo tee \\\n"
        f"  /etc/apt/keyrings/{kit.esc(package)}.asc &gt; /dev/null\n"
        f"sudo apt-get update &amp;&amp; sudo apt-get install {kit.esc(package)}"
        "</code></pre>"
        "<h2>Verify the service</h2>"
        f"<pre><code>systemctl status {kit.esc(package)}\n"
        f"{kit.esc(package)}ctl health --wait 30s</code></pre>"
        "<p>A healthy node answers within a second and reports the storage "
        "directory it opened at startup.</p>"
        "<div class=\"note\">Run the server as its own system user. "
        f"{kit.esc(product)} never requires root after installation.</div>"
    )
    kit.write_text(
        site_dir,
        "install.html",
        kit.page(
            title=f"Installation — {product}",
            description=f"Install {product} from the package repository.",
            body=_shell(identity, "/install.html", content),
        ),
    )


def _write_configuration(site_dir: Path, identity: SiteIdentity) -> None:
    product = _product(identity)
    package = identity.slug
    content = (
        "<h1>Configuration</h1>"
        f"<p class=\"lead\">Configuration lives in "
        f"<code>/etc/{kit.esc(package)}/config.toml</code>. Changes are picked "
        "up on reload; only listener changes require a restart.</p>"
        "<pre><code>[server]\n"
        "listen = \"127.0.0.1:7431\"\n"
        "workers = 4\n\n"
        "[storage]\n"
        f"path = \"/var/lib/{kit.esc(package)}\"\n"
        "retention = \"30d\"\n\n"
        "[telemetry]\n"
        "metrics = true</code></pre>"
        "<h2>Options</h2>"
        "<table><thead><tr><th>Key</th><th>Default</th><th>Notes</th></tr>"
        "</thead><tbody>"
        "<tr><td><code>server.workers</code></td><td>4</td>"
        "<td>One per physical core is usually enough.</td></tr>"
        "<tr><td><code>storage.retention</code></td><td>30d</td>"
        "<td>Segments older than this are compacted away.</td></tr>"
        "<tr><td><code>telemetry.metrics</code></td><td>true</td>"
        "<td>Exposes Prometheus metrics on the admin port.</td></tr>"
        "</tbody></table>"
        "<div class=\"note\">Keep the listener on loopback and terminate TLS "
        "in front of it.</div>"
    )
    kit.write_text(
        site_dir,
        "configuration.html",
        kit.page(
            title=f"Configuration — {product}",
            description=f"Configuration reference for {product}.",
            body=_shell(identity, "/configuration.html", content),
        ),
    )


def _write_styles(site_dir: Path, identity: SiteIdentity) -> None:
    kit.write_text(
        site_dir,
        "css/style.css",
        kit.variables(identity)
        + (
            ".layout{display:grid;grid-template-columns:264px 1fr;min-height:100vh}"
            "aside{background:#12161f;color:#c6ccd8;padding:32px 24px;"
            "position:sticky;top:0;height:100vh}"
            "aside .product{display:block;font-size:20px;font-weight:700;color:#fff}"
            "aside .version{display:inline-block;margin:6px 0 22px;font-size:12px;"
            "color:#8b93a5;border:1px solid #2a3140;border-radius:999px;padding:2px 10px}"
            "aside nav{display:flex;flex-direction:column;gap:2px}"
            "aside nav a{color:#aab2c2;padding:8px 10px;border-radius:6px;font-size:15px}"
            "aside nav a:hover{background:#1b2231;color:#fff}"
            "aside nav a.current{background:var(--accent);color:#fff;font-weight:600}"
            "aside .vendor{margin-top:28px;font-size:13px;color:#6e768a}"
            "main{background:var(--surface);padding:56px 48px;max-width:860px}"
            "h1{font-size:34px;margin:0 0 14px}"
            "h2{font-size:21px;margin:38px 0 12px;padding-top:8px}"
            ".lead{font-size:18px;color:#4b5364}"
            "p,li,td{color:#404a5c}"
            "pre{background:#12161f;color:#e6e9f0;padding:18px 20px;overflow:auto;"
            "border-radius:var(--radius);font-size:14px;line-height:1.55}"
            "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.94em}"
            "main>p code,td code{background:var(--tint);color:var(--accent-dark);"
            "padding:1px 6px;border-radius:4px}"
            "table{border-collapse:collapse;width:100%;margin:14px 0;font-size:15px}"
            "th,td{text-align:left;padding:11px 12px;border-bottom:1px solid #e6e8ef}"
            "th{color:#69718a;font-size:13px;text-transform:uppercase;letter-spacing:.06em}"
            ".note{border-left:3px solid var(--accent);background:var(--tint);"
            "padding:14px 18px;margin:26px 0;border-radius:0 var(--radius) var(--radius) 0}"
            ".notfound{padding:120px 20px;text-align:center}"
            ".notfound h1{font-size:60px;color:var(--accent)}"
            "@media(max-width:820px){.layout{grid-template-columns:1fr}"
            "aside{position:static;height:auto}main{padding:36px 22px}}"
        ),
    )


__all__ = ["PAGES", "generate"]
