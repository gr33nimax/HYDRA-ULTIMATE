"""Human-readable AntiDPI vocabulary owned by the plugin that produces it.

Adapters must never disagree about what a signal means or how long a ban still
lasts, and the service layer is not allowed to import plugin internals.  The
plugin therefore owns the vocabulary and ships rendered labels inside its
management projection; generic number and date formatting lives in
:mod:`hydra.utils.format_ru`.
"""
from __future__ import annotations

from collections.abc import Iterable

from hydra.plugins.antidpi.model import BAN_THRESHOLD, ban_duration
from hydra.utils.format_ru import format_duration

SIGNAL_LABELS: dict[str, str] = {
    "malformed_tls": "повреждённый TLS ClientHello",
    "non_tls_on_tls": "не-TLS трафик на TLS-порту",
    "unknown_sni": "неизвестный SNI",
    "handshake_failure": "ошибка handshake",
    "protocol_mismatch": "несоответствие протокола",
    "quic_retry_burst": "серия QUIC Retry",
    "connection_burst": "частые подключения",
    "invalid_first_packet": "некорректный первый пакет",
    "active_decoy_probe": "активная проверка decoy",
    "auth_failure": "ошибка аутентификации",
    "port_scan": "сканирование портов",
    "port_sweep": "перебор разных портов",
    "udp_probe": "UDP-зонд",
    "low_volume_session": "сессия без полезного трафика",
    "manual_ban": "блокировка администратором",
}

SOURCE_LABELS: dict[str, str] = {
    "journal": "журнал протокола",
    "auth_log": "журнал аутентификации",
    "kernel-firewall": "телеметрия ядра",
    "kernel-mieru": "телеметрия ядра (Mieru)",
    "kernel-udp-probe": "телеметрия ядра (UDP)",
    "caddy-decoy": "decoy-сайт",
    "caddy-naive": "Naive",
    "caddy-naive-decoy": "decoy-сайт Naive",
    "caddy-trusttunnel": "TrustTunnel",
    "caddy-trusttunnel-decoy": "decoy-сайт TrustTunnel",
    "caddy-vless": "VLESS XHTTP",
    "caddy-vless-decoy": "decoy-сайт VLESS",
    "caddy-source-relay": "source-relay Caddy",
    "manual": "администратор",
    "legacy/unknown": "источник не сохранён",
    "unknown": "источник неизвестен",
}

FAMILY_LABELS: dict[str, str] = {
    "tls_integrity": "целостность TLS",
    "tls_negotiation": "согласование TLS",
    "protocol": "поведение протокола",
    "auth": "аутентификация",
    "scanning": "сканирование",
    "decoy": "приманка",
    "manual": "решение администратора",
}

BLOCK_REASON_LABELS: dict[str, str] = {
    "single_family": "улики одного типа — нужен второй независимый признак",
    "below_threshold": "улик пока недостаточно",
    "unverified_source": "источник не подтверждён — только оповещение",
}

HEALTH_LABELS: dict[str, str] = {
    "service": "служба детектора",
    "ipsets": "ipset-наборы блокировок",
    "firewall": "правила DROP в INPUT",
    "scan_telemetry": "телеметрия сканирования",
    "udp_probe_telemetry_removed": "устаревшие UDP-правила удалены",
    "mieru_probe_telemetry": "телеметрия Mieru",
}


def signal_label(value: object) -> str:
    """Translate one signal key, keeping unknown keys visible as-is."""
    key = str(value or "").strip()
    return SIGNAL_LABELS.get(key, key or "—")


def signal_summary(values: object, *, limit: int = 3) -> str:
    """Render up to ``limit`` translated signals plus an overflow marker."""
    items = signal_list(values)
    if not items:
        return "аномальное поведение"
    visible = [signal_label(item) for item in items[:max(1, int(limit))]]
    hidden = len(items) - len(visible)
    if hidden > 0:
        visible.append(f"+{hidden}")
    return ", ".join(visible)


def source_label(value: object) -> str:
    """Translate an evidence source, falling back to its raw identifier."""
    key = str(value or "").strip()
    return SOURCE_LABELS.get(key, key or "—")


def health_label(value: object) -> str:
    """Translate one healthcheck key from the firewall adapter."""
    key = str(value or "").strip()
    return HEALTH_LABELS.get(key, key or "—")


def family_label(value: object) -> str:
    """Translate one evidence family."""
    key = str(value or "").strip()
    return FAMILY_LABELS.get(key, key or "—")


def family_summary(values: object) -> str:
    """Render the evidence families behind an address."""
    items = signal_list(values)
    if not items:
        return "—"
    return ", ".join(family_label(item) for item in items)


def block_reason_label(value: object) -> str:
    """Explain in one phrase why an address is not banned yet."""
    key = str(value or "").strip()
    return BLOCK_REASON_LABELS.get(key, "")


def signal_list(values: object) -> list[str]:
    """Normalize persisted signals that may be a list or a legacy string."""
    if isinstance(values, str):
        return [item.strip() for item in values.split(",") if item.strip()]
    if isinstance(values, Iterable) and not isinstance(values, (bytes, dict)):
        return [str(item) for item in values if str(item).strip()]
    return []


def ban_view(address: object, metadata: object, *, now: float) -> dict:
    """Project one ban record into the fields every adapter renders."""
    record = metadata if isinstance(metadata, dict) else {}
    duration = ban_duration(record)
    permanent = record.get("permanent") is True
    started_at = _number(record.get("at"))
    remaining = (
        0.0
        if permanent
        else max(0.0, duration - (float(now) - started_at))
    )
    expired = not permanent and remaining <= 0
    if permanent:
        icon, ttl, left = "🔴", "бессрочно", "бессрочно"
    elif expired:
        icon, ttl, left = "🟡", format_duration(duration), "истёк"
    else:
        icon = "🔴" if remaining > 300 else "🟠"
        ttl, left = format_duration(duration), format_duration(remaining)
    return {
        "ip": str(address),
        "at": started_at,
        "duration": duration,
        "permanent": permanent,
        "expired": expired,
        "remaining": remaining,
        "icon": icon,
        "ttl": ttl,
        "remaining_label": left,
        "score": _number(record.get("score")),
        "threshold": float(BAN_THRESHOLD),
        "offense": _positive_int(record.get("offense_count"), default=1),
        "signals": signal_list(record.get("signals")),
        "reason": signal_summary(record.get("signals")),
        "source": source_label(record.get("source", "legacy/unknown")),
        "protocol": str(record.get("protocol", "unknown"))[:40],
        "kind": str(record.get("kind", ""))[:80],
    }


def counter_rows(counter: object, translate, *, limit: int = 6) -> list[dict]:
    """Rank one persisted counter and attach its translated labels."""
    values = counter if isinstance(counter, dict) else {}
    rows = []
    for name, value in values.items():
        try:
            rows.append({"key": str(name), "count": int(value)})
        except (TypeError, ValueError):
            continue
    rows.sort(key=lambda row: row["count"], reverse=True)
    top = max((row["count"] for row in rows), default=0)
    return [
        {**row, "label": translate(row["key"]), "maximum": top}
        for row in rows[:max(0, int(limit))]
    ]


def _number(value: object) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _positive_int(value: object, *, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


__all__ = [
    "BLOCK_REASON_LABELS",
    "FAMILY_LABELS",
    "HEALTH_LABELS",
    "SIGNAL_LABELS",
    "SOURCE_LABELS",
    "ban_view",
    "block_reason_label",
    "counter_rows",
    "family_label",
    "family_summary",
    "health_label",
    "signal_label",
    "signal_list",
    "signal_summary",
    "source_label",
]
