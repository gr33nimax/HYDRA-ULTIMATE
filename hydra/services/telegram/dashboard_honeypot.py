"""Honeypot dashboard renderers."""
from __future__ import annotations

import html

from hydra.services.application import ApplicationService
from hydra.services.telegram.dashboard_common import (
    _format_security_timestamp,
    _mapping_projection,
    _network_label,
)

def _legacy_honeypot_status_text(app: ApplicationService) -> str:
    status = app.protocols.status("honeypot")
    data = _mapping_projection(
        app.plugin_query("honeypot", "management_snapshot"),
    )
    banned = (
        data.get("banned", {})
        if isinstance(data.get("banned"), dict)
        else {}
    )
    ordered = sorted(
        banned.items(),
        key=lambda item: str(item[1].get("banned_at", "")),
        reverse=True,
    )
    rows = []
    for address, metadata in ordered[:8]:
        when = str(metadata.get("banned_at", "—")).replace("T", " ")[:19]
        backend = str(metadata.get("backend", "firewall"))
        rows.append(
            f"• <code>{html.escape(address)}</code> · "
            f"{html.escape(when)} · {html.escape(backend)}",
        )
    if len(ordered) > 8:
        rows.append(f"<i>…и ещё {len(ordered) - 8} адресов</i>")
    return (
        "<b>🍯 Honeypot — отдельная ловушка</b>\n\n"
        f"<b>Сервис:</b> "
        f"{'🟢 работает' if status.running else '🔴 остановлен'}\n"
        f"<b>Порт ловушки:</b> "
        f"<code>{int(data.get('port', status.port or 0))}</code>/TCP\n"
        f"<b>Заблокировано адресов:</b> {len(ordered)}\n"
        f"<b>Whitelist:</b> {len(data.get('whitelist', []))}\n\n"
        "<b>Последние срабатывания:</b>\n"
        + ("\n".join(rows) if rows else "<i>Подключений пока нет</i>")
    )

def get_honeypot_status_text(
    app: ApplicationService,
    *,
    lookup_intel,
) -> str:
    """Render the compact Honeypot dashboard."""
    status = app.protocols.status("honeypot")
    data = _mapping_projection(
        app.plugin_query("honeypot", "management_snapshot"),
    )
    banned = (
        data.get("banned", {})
        if isinstance(data.get("banned"), dict)
        else {}
    )
    ordered = sorted(
        banned.items(),
        key=lambda item: str((item[1] or {}).get("banned_at", "")),
        reverse=True,
    )
    latest = ordered[:5]
    intel = lookup_intel(
        [str(address) for address, _ in latest],
    )
    rows = []
    port = int(data.get("port", status.port or 0))
    for address, metadata in latest:
        details = intel.get(str(address), {})
        flag = html.escape(str(details.get("flag", "🌐")))
        when = _format_security_timestamp(
            (metadata or {}).get("banned_at"),
        )
        backend = html.escape(
            str((metadata or {}).get("backend", "firewall")),
        )
        owner = _network_label(details)
        suffix = f" · {html.escape(owner)}" if owner else ""
        rows.append(
            f"• {flag} <code>{html.escape(str(address))}</code> · "
            f"{html.escape(when)}\n"
            f"  <code>TCP/{port}</code> · {backend}{suffix}",
        )
    service = "🟢 работает" if status.running else "🔴 остановлен"
    return (
        "<b>🍯 Honeypot</b>\n\n"
        f"{service} · <code>{port}/TCP</code>\n"
        f"<b>Активных блокировок:</b> {len(ordered)}\n\n"
        "<b>Последние блокировки:</b>\n"
        + ("\n\n".join(rows) if rows else "<i>Блокировок нет</i>")
    )
