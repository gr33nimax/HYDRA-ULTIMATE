"""AntiDPI dashboard renderers."""
from __future__ import annotations

import html
import time

from hydra.services.application import ApplicationService
from hydra.services.telegram.dashboard_common import (
    _format_period,
    _mapping_projection,
)


def _summarize_counter(counter: dict) -> str:
    safe = []
    for name, value in counter.items():
        try:
            safe.append((str(name), int(value)))
        except (TypeError, ValueError):
            continue
    safe.sort(key=lambda item: item[1], reverse=True)
    return (
        ", ".join(
            f"{html.escape(name)}: {value}"
            for name, value in safe[:5]
        )
        or "нет данных"
    )

def get_antidpi_status_text(app: ApplicationService) -> str:
    """Render the detailed legacy AntiDPI status view."""
    status = app.protocols.status("antidpi")
    running_icon = (
        "🟢 Активен"
        if status.running
        else ("⚠️ Установлен" if status.installed else "🔴 Отключен")
    )

    banned_ips: list[str] = []
    events_count = 0
    source_counts: dict = {}
    signal_counts: dict = {}
    notification_stats: dict = {}
    suppressed_notices = 0
    try:
        data = _mapping_projection(
            app.plugin_query("antidpi", "management_snapshot"),
        )
        banned = _mapping_projection(data.get("banned"))
        if data:
            events_count = data.get("events", 0)
            source_counts = (
                data.get("source_counts", {})
                if isinstance(data.get("source_counts"), dict)
                else {}
            )
            signal_counts = (
                data.get("signal_counts", {})
                if isinstance(data.get("signal_counts"), dict)
                else {}
            )
            notification_stats = (
                data.get("notification_stats", {})
                if isinstance(data.get("notification_stats"), dict)
                else {}
            )
            suppressed_notices = int(
                data.get("suppressed_ban_notifications", 0) or 0,
            )
            ordered_bans = sorted(
                banned.items(),
                key=lambda item: float(item[1].get("at", 0) or 0),
                reverse=True,
            )
            for address, metadata in ordered_bans:
                try:
                    score = float(metadata.get("score", 0))
                except (TypeError, ValueError):
                    score = 0.0
                raw_signals = metadata.get("signals", [])
                signals = (
                    ", ".join(str(value) for value in raw_signals)
                    if isinstance(raw_signals, list)
                    else str(raw_signals or "")
                )
                banned_ips.append(
                    f"• <code>{html.escape(str(address))}</code> "
                    f"(score: {score:.1f}, {html.escape(signals)})",
                )
    except Exception:
        pass

    sources_block = _summarize_counter(source_counts)
    signals_block = _summarize_counter(signal_counts)
    delivered = int(notification_stats.get("delivered", 0) or 0)
    failed = int(notification_stats.get("failed", 0) or 0)
    banned_block = (
        "\n".join(banned_ips[:10])
        if banned_ips
        else "<i>Нет заблокированных IP</i>"
    )
    if len(banned_ips) > 10:
        banned_block += f"\n<i>...и ещё {len(banned_ips) - 10} IP</i>"

    return (
        "<b>🛡️ AntiDPI Status</b>\n\n"
        f"<b>Статус:</b> {running_icon}\n"
        f"<b>Всего событий:</b> {events_count}\n"
        f"<b>Заблокировано IP:</b> {len(banned_ips)}\n"
        f"<b>Источники:</b> {sources_block}\n"
        f"<b>Сигналы:</b> {signals_block}\n"
        f"<b>Уведомления:</b> доставлено {delivered}, ошибок {failed}, "
        f"сгруппировано {suppressed_notices}\n\n"
        f"<b>Заблокированные IP:</b>\n{banned_block}"
    )

_SIGNAL_LABELS = {
    "malformed_tls": "повреждённый TLS ClientHello",
    "handshake_failure": "ошибка handshake",
    "unknown_sni": "неизвестный SNI",
    "active_decoy_probe": "активная проверка decoy",
    "auth_failure": "ошибка аутентификации",
    "port_scan": "сканирование портов",
    "connection_burst": "частые подключения",
    "port_sweep": "перебор разных портов",
    "protocol_mismatch": "несоответствие протокола",
    "invalid_first_packet": "некорректный первый пакет",
}

def get_antidpi_dashboard_text(app: ApplicationService) -> str:
    """Render the operational AntiDPI dashboard."""
    status = app.protocols.status("antidpi")
    data = _mapping_projection(
        app.plugin_query("antidpi", "management_snapshot"),
    )
    banned = _mapping_projection(data.get("banned"))
    now = time.time()
    ordered = sorted(
        banned.items(),
        key=lambda item: float(item[1].get("at", 0) or 0),
        reverse=True,
    )
    rows = []
    for address, metadata in ordered[:8]:
        signals = metadata.get("signals", [])
        if not isinstance(signals, list):
            signals = [str(signals)] if signals else []
        reasons = (
            ", ".join(
                _SIGNAL_LABELS.get(str(item), str(item))
                for item in signals[:3]
            )
            or "аномальное поведение"
        )
        duration = int(metadata.get("duration", 0) or 0)
        remaining = duration - max(
            0,
            now - float(metadata.get("at", 0) or 0),
        )
        expiry = (
            "бессрочно"
            if metadata.get("permanent") is True
            else f"осталось {_format_period(remaining)}"
        )
        source = str(metadata.get("source", "legacy/unknown"))
        protocol = str(metadata.get("protocol", "unknown"))
        score = float(metadata.get("score", 0) or 0)
        offense = int(metadata.get("offense_count", 1) or 1)
        rows.append(
            f"• <code>{html.escape(address)}</code> — "
            f"<b>{score:.1f}</b> баллов, {expiry}\n"
            f"  {html.escape(reasons)} · "
            f"{html.escape(protocol)}/{html.escape(source)} · "
            f"нарушение #{offense}",
        )
    if len(ordered) > 8:
        rows.append(
            f"<i>…и ещё {len(ordered) - 8} активных блокировок</i>",
        )
    stats = (
        data.get("notification_stats", {})
        if isinstance(data.get("notification_stats"), dict)
        else {}
    )
    last_source = html.escape(str(data.get("last_event_source", "—")))
    return (
        "<b>🛡 AntiDPI — защита всей VPS</b>\n\n"
        f"<b>Сервис:</b> "
        f"{'🟢 работает' if status.running else '🔴 остановлен'}\n"
        f"<b>Активных блокировок:</b> {len(ordered)}\n"
        f"<b>Обработано событий:</b> {int(data.get('events', 0) or 0)}\n"
        f"<b>Последний источник:</b> <code>{last_source}</code>\n"
        f"<b>Telegram:</b> "
        f"доставлено {int(stats.get('delivered', 0) or 0)}, "
        f"ошибок {int(stats.get('failed', 0) or 0)}\n\n"
        "<b>Последние активные баны:</b>\n"
        + ("\n\n".join(rows) if rows else "<i>Активных банов нет</i>")
    )
