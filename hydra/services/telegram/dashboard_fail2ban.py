"""Fail2ban dashboard renderers and log projections."""
from __future__ import annotations

import html
import re

from hydra.services.application import ApplicationService
from hydra.services.telegram.dashboard_common import (
    _format_period,
    _format_security_timestamp,
    _mapping_projection,
    _network_label,
    _parse_fail2ban_ban_lines,
)

def get_fail2ban_status_text(app: ApplicationService) -> str:
    """Render the detailed legacy Fail2ban status view."""
    status = app.protocols.status("fail2ban")
    running_icon = (
        "🟢 Активен"
        if status.running
        else ("⚠️ Установлен" if status.installed else "🔴 Отключен")
    )

    jails_info = []
    total_banned = status.info.get("banned_ips", 0)
    if status.running:
        try:
            overall = app.admin.run_command(
                ["fail2ban-client", "status"],
                timeout=10,
                text=True,
            )
            match = re.search(
                r"Jail list:\s*(.*)",
                str(overall.stdout or ""),
            )
            if match:
                for jail in (
                    item.strip()
                    for item in match.group(1).split(",")
                ):
                    if not jail:
                        continue
                    detail = app.admin.run_command(
                        ["fail2ban-client", "status", jail],
                        timeout=10,
                        text=True,
                    )
                    current = re.search(
                        r"Currently banned:\s*(\d+)",
                        str(detail.stdout or ""),
                    )
                    count = current.group(1) if current else "0"
                    jails_info.append(
                        f"• <b>{html.escape(jail)}</b>: "
                        f"<code>{count} banned</code>",
                    )
        except Exception:
            pass

    jails_block = (
        "\n".join(jails_info)
        if jails_info
        else "<i>Нет активных джейлов</i>"
    )
    return (
        "<b>🚫 Fail2ban Status</b>\n\n"
        f"<b>Статус:</b> {running_icon}\n"
        f"<b>Всего заблокировано IP:</b> {total_banned}\n\n"
        f"<b>Джейлы:</b>\n{jails_block}"
    )

def _parse_fail2ban_jail(detail: str) -> dict:
    result = {
        "currently_failed": 0,
        "total_failed": 0,
        "currently_banned": 0,
        "total_banned": 0,
        "ips": [],
    }
    mapping = {
        "Currently failed": "currently_failed",
        "Total failed": "total_failed",
        "Currently banned": "currently_banned",
        "Total banned": "total_banned",
    }
    for line in str(detail).splitlines():
        clean = line.strip().lstrip("|-` ")
        for label, key in mapping.items():
            if label in clean:
                match = re.search(r":\s*(\d+)", clean)
                if match:
                    result[key] = int(match.group(1))
        if "Banned IP list" in clean and ":" in clean:
            result["ips"] = clean.split(":", 1)[1].strip().split()
    return result

def _legacy_fail2ban_dashboard_text(app: ApplicationService) -> str:
    status = app.protocols.status("fail2ban")
    if not status.running:
        return "<b>🚫 Fail2ban</b>\n\n<b>Сервис:</b> 🔴 остановлен"
    overall = app.admin.run_command(
        ["fail2ban-client", "status"],
        timeout=10,
        text=True,
    )
    match = re.search(r"Jail list:\s*(.*)", str(overall.stdout or ""))
    jails = (
        [item.strip() for item in match.group(1).split(",") if item.strip()]
        if match
        else []
    )
    options = _mapping_projection(
        app.plugin_query(
            "fail2ban",
            "jail_options",
            state=app.admin.load_state(),
        ),
    )
    blocks = []
    total_current = total_ever = total_failed = 0
    for jail in jails:
        detail = app.admin.run_command(
            ["fail2ban-client", "status", jail],
            timeout=10,
            text=True,
        )
        info = _parse_fail2ban_jail(str(detail.stdout or ""))
        total_current += info["currently_banned"]
        total_ever += info["total_banned"]
        total_failed += info["total_failed"]
        config = options.get(jail, {})
        ips = (
            ", ".join(
                f"<code>{html.escape(address)}</code>"
                for address in info["ips"][:5]
            )
            or "—"
        )
        blocks.append(
            f"<b>{html.escape(jail)}</b>\n"
            f"  Сейчас: {info['currently_banned']} банов / "
            f"{info['currently_failed']} ошибок\n"
            f"  Всего: {info['total_banned']} банов / "
            f"{info['total_failed']} ошибок\n"
            f"  Политика: {config.get('maxretry', '—')} попыток за "
            f"{_format_period(config.get('findtime'))}, "
            f"бан {_format_period(config.get('bantime'))}\n"
            f"  IP: {ips}",
        )
    return (
        "<b>🚫 Fail2ban — защита авторизации</b>\n\n"
        "<b>Сервис:</b> 🟢 работает\n"
        f"<b>Jail:</b> {len(jails)}\n"
        f"<b>Сейчас заблокировано:</b> {total_current}\n"
        f"<b>Всего банов:</b> {total_ever}\n"
        f"<b>Всего ошибок:</b> {total_failed}\n\n"
        + ("\n\n".join(blocks) if blocks else "<i>Активных jail нет</i>")
    )

def _recent_fail2ban_bans(
    app: ApplicationService,
    limit: int = 5,
) -> list[dict[str, str]]:
    """Parse plugin-owned Fail2ban log records through a read projection."""
    try:
        lines = app.plugin_query(
            "fail2ban",
            "recent_logs",
            limit=5000,
        )
        if not isinstance(lines, list):
            return []
        return _parse_fail2ban_ban_lines(
            [str(line) for line in lines],
            limit,
        )
    except Exception:
        return []

def get_fail2ban_dashboard_text(
    app: ApplicationService,
    *,
    recent_bans,
    lookup_intel,
) -> str:
    """Render the compact Fail2ban dashboard."""
    status = app.protocols.status("fail2ban")
    if not status.running:
        return "<b>🚫 Fail2ban</b>\n\n🔴 остановлен"
    overall = app.admin.run_command(
        ["fail2ban-client", "status"],
        timeout=10,
        text=True,
    )
    match = re.search(r"Jail list:\s*(.*)", str(overall.stdout or ""))
    jails = (
        [item.strip() for item in match.group(1).split(",") if item.strip()]
        if match
        else []
    )
    options = _mapping_projection(
        app.plugin_query(
            "fail2ban",
            "jail_options",
            state=app.admin.load_state(),
        ),
    )
    jail_rows = []
    total_current = 0
    for jail in jails:
        detail = app.admin.run_command(
            ["fail2ban-client", "status", jail],
            timeout=10,
            text=True,
        )
        info = _parse_fail2ban_jail(str(detail.stdout or ""))
        current = info["currently_banned"]
        total_current += current
        config = options.get(jail, {})
        jail_rows.append(
            f"• <code>{html.escape(jail)}</code> · {current} IP · "
            f"{html.escape(str(config.get('maxretry', '—')))}/"
            f"{_format_period(config.get('findtime'))} "
            f"→ {_format_period(config.get('bantime'))}",
        )

    recent = recent_bans(app, 5)
    intel = lookup_intel([item["ip"] for item in recent])
    recent_rows = []
    for item in recent:
        details = intel.get(item["ip"], {})
        flag = html.escape(str(details.get("flag", "🌐")))
        jail = item["jail"]
        duration = _format_period(
            options.get(jail, {}).get("bantime"),
        )
        owner = _network_label(details)
        suffix = f" · {html.escape(owner)}" if owner else ""
        recent_rows.append(
            f"• {flag} <code>{html.escape(item['ip'])}</code> · "
            f"{html.escape(_format_security_timestamp(item['when']))}\n"
            f"  <code>{html.escape(jail)}</code> · "
            f"бан {duration}{suffix}",
        )

    return (
        "<b>🚫 Fail2ban</b>\n\n"
        f"🟢 работает · <b>{total_current}</b> активных банов\n"
        f"<b>Jail:</b> {len(jails)}\n\n"
        "<b>Политики:</b>\n"
        + ("\n".join(jail_rows) if jail_rows else "<i>Активных jail нет</i>")
        + "\n\n<b>Последние блокировки:</b>\n"
        + (
            "\n\n".join(recent_rows)
            if recent_rows
            else "<i>Событий Ban в журнале нет</i>"
        )
    )
