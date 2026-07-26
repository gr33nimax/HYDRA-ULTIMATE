"""Service-status decoy site renderer."""
from __future__ import annotations

from pathlib import Path


def generate(site_dir: Path) -> None:
    """Generate a small, plausible service-status site for Hysteria2 probes."""
    _write_index(site_dir)
    _write_styles(site_dir)
    _write_status(site_dir)


def _write_index(site_dir: Path) -> None:
    (site_dir / "index.html").write_text(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        "  <meta charset=\"UTF-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "  <meta name=\"description\" content=\"Northstar Cloud service status\">\n"
        "  <title>Northstar Cloud Status</title>\n"
        "  <link rel=\"icon\" href=\"favicon.ico\">\n"
        "  <link rel=\"stylesheet\" href=\"css/style.css\">\n"
        "</head>\n<body>\n"
        "  <main class=\"container\">\n"
        "    <header><div class=\"brand\">Northstar Cloud</div><span>Service Status</span></header>\n"
        "    <section class=\"summary\"><i></i><strong>All systems operational</strong>"
        "<p>No incidents reported.</p></section>\n"
        "    <section class=\"services\">\n"
        "      <div><span>Edge Network</span><b>Operational</b></div>\n"
        "      <div><span>Cloud API</span><b>Operational</b></div>\n"
        "      <div><span>Object Storage</span><b>Operational</b></div>\n"
        "      <div><span>Monitoring</span><b>Operational</b></div>\n"
        "    </section>\n"
        "    <footer>Northstar Cloud infrastructure status</footer>\n"
        "  </main>\n"
        "</body>\n</html>\n",
        encoding="utf-8",
    )


def _write_styles(site_dir: Path) -> None:
    (site_dir / "css" / "style.css").write_text(
        ":root{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;"
        "color:#172033;background:#f5f7fb}*{box-sizing:border-box}body{margin:0}.container{"
        "width:min(760px,calc(100% - 32px));margin:64px auto}header{display:flex;align-items:center;"
        "justify-content:space-between;margin-bottom:28px;color:#657086}.brand{font-size:20px;font-weight:700;"
        "color:#172033}.summary,.services{background:#fff;border:1px solid #e3e8f1;border-radius:12px;"
        "box-shadow:0 8px 24px rgba(24,39,75,.05)}.summary{padding:26px 28px;margin-bottom:18px}"
        ".summary i{display:inline-block;width:11px;height:11px;border-radius:50%;background:#22a06b;"
        "margin-right:10px}.summary strong{font-size:18px}.summary p{margin:8px 0 0 25px;color:#718096}"
        ".services{padding:0 28px}.services div{display:flex;justify-content:space-between;padding:20px 0;"
        "border-bottom:1px solid #edf0f5}.services div:last-child{border:0}.services b{color:#16845a;"
        "font-size:14px}footer{text-align:center;color:#929bad;font-size:13px;margin-top:28px}"
        "@media(max-width:520px){.container{margin:28px auto}.services div{align-items:center;gap:16px}}\n",
        encoding="utf-8",
    )


def _write_status(site_dir: Path) -> None:
    (site_dir / "status.json").write_text(
        '{"status":"operational","updated":null}\n',
        encoding="utf-8",
    )
