"""Validated security actions exposed through the application boundary."""
from __future__ import annotations

import html
import ipaddress
from collections.abc import Mapping

from hydra.services.application import ApplicationService

def _mapping_projection(value: object) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}

def unban_ip_everywhere(ip: str, app: ApplicationService) -> str:
    """Remove an address from AntiDPI, Honeypot and Fail2ban."""
    results = []
    try:
        target_ip = ipaddress.ip_address(
            str(ip).strip().strip("[]"),
        ).compressed
    except ValueError:
        return "<b>❌ Некорректный IP-адрес.</b>"
    safe_ip = html.escape(target_ip)

    try:
        antidpi_ok = bool(
            app.plugin_action("antidpi", "unban", raw=target_ip),
        )
        results.append(
            "• AntiDPI: "
            + (
                "✅ Разблокирован"
                if antidpi_ok
                else "ℹ️ Не найден в бане"
            ),
        )
    except Exception as exc:
        results.append(f"• AntiDPI: ❌ Ошибка ({html.escape(str(exc))})")

    try:
        honeypot_ok = bool(
            app.plugin_action("honeypot", "unban", raw=target_ip),
        )
        results.append(
            "• Honeypot: "
            + (
                "✅ Разблокирован"
                if honeypot_ok
                else "ℹ️ Не найден в бане"
            ),
        )
    except Exception as exc:
        results.append(f"• Honeypot: ❌ Ошибка ({html.escape(str(exc))})")

    try:
        result = app.admin.run_command(
            ["fail2ban-client", "unban", target_ip],
            timeout=10,
            text=True,
        )
        if result.returncode == 0:
            results.append(
                "• Fail2ban: ✅ Разблокирован "
                f"({html.escape(result.stdout.strip())})",
            )
        else:
            results.append("• Fail2ban: ℹ️ Не найден в джейлах")
    except Exception as exc:
        results.append(f"• Fail2ban: ❌ Ошибка ({html.escape(str(exc))})")

    return (
        f"<b>🔓 Результат разблокировки IP "
        f"<code>{safe_ip}</code>:</b>\n\n"
        + "\n".join(results)
    )

def ban_ip_antidpi(ip: str, app: ApplicationService) -> dict:
    """Apply a validated manual AntiDPI ban."""
    result = app.plugin_action(
        "antidpi",
        "manual_ban",
        raw=ip,
        source="telegram-admin",
    )
    return _mapping_projection(result)

