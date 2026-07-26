"""System dashboard renderer for the Telegram administration adapter."""
from __future__ import annotations

import html

from hydra.services.application import ApplicationService

def get_system_info_text(app: ApplicationService) -> str:
    """Collect system resources and registered plugin statuses."""
    hostname = "N/A"
    try:
        state = app.admin.load_state()
        overview = app.admin.system_overview(state)
        hostname = html.escape(overview.hostname or "N/A")
        server_ip = html.escape(
            state.network.server_ip or overview.public_ip or "N/A",
        )
    except Exception:
        overview = None
        server_ip = "N/A"

    load_str = "N/A"
    ram_str = "N/A"
    disk_str = "N/A"
    uptime_str = "N/A"
    if overview is not None:
        if overview.load_averages:
            load_str = ", ".join(
                f"{value:.2f}" for value in overview.load_averages
            )
        if overview.memory_total > 0:
            ram_percent = (
                overview.memory_percent
                if overview.memory_percent is not None
                else overview.memory_used / overview.memory_total * 100
            )
            ram_str = (
                f"{overview.memory_used / 1024**3:.2f} GB / "
                f"{overview.memory_total / 1024**3:.2f} GB "
                f"({ram_percent:.0f}%)"
            )
        if overview.disk_total > 0:
            disk_percent = (
                overview.disk_percent
                if overview.disk_percent is not None
                else overview.disk_used / overview.disk_total * 100
            )
            disk_str = (
                f"{overview.disk_used / 1024**3:.1f} GB / "
                f"{overview.disk_total / 1024**3:.1f} GB "
                f"({disk_percent:.0f}%)"
            )
        if overview.uptime_seconds is not None:
            seconds = max(0, int(overview.uptime_seconds))
            days = seconds // 86400
            hours = seconds % 86400 // 3600
            minutes = seconds % 3600 // 60
            uptime_str = f"{days}d {hours}h {minutes}m"

    services_lines = []
    try:
        for name, status in app.protocols.statuses().items():
            icon = (
                "🟢"
                if status.get("running")
                else ("⚠️" if status.get("installed") else "🔴")
            )
            port = f" (port {status['port']})" if status.get("port") else ""
            services_lines.append(
                f"• {icon} <b>{html.escape(str(name))}</b>{html.escape(port)}",
            )
    except Exception as exc:
        services_lines.append(
            f"Ошибка получения статуса: {html.escape(str(exc))}",
        )

    services_block = (
        "\n".join(services_lines)
        if services_lines
        else "Нет активных плагинов"
    )
    return (
        "<b>🖥️ HYDRA System Information</b>\n\n"
        f"<b>Сервер:</b> <code>{hostname}</code> ({server_ip})\n"
        f"<b>Аптайм:</b> <code>{uptime_str}</code>\n"
        f"<b>Load Average:</b> <code>{load_str}</code>\n"
        f"<b>RAM:</b> <code>{ram_str}</code>\n"
        f"<b>Диск:</b> <code>{disk_str}</code>\n\n"
        f"<b>⚡ Статус сервисов:</b>\n{services_block}"
    )
