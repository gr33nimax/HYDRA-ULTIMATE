"""
Имена systemd-служб HYDRA — единый реестр для диагностики и меню.

Исторические имена xray-* / vless-sub сохранены до отдельной миграции unit-файлов.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Literal

ServiceStatus = Literal["active", "inactive", "failed", "missing"]


@dataclass(frozen=True)
class HydraService:
    key: str
    unit: str
    label_ru: str


# Основной стек HYDRA (проверяется в quick status / full diagnostic).
CORE_SERVICES: tuple[HydraService, ...] = (
    HydraService("naive", "caddy-naive", "NaiveProxy (Caddy)"),
    HydraService("mieru", "mita", "Mieru (mita)"),
    HydraService("sub", "vless-sub", "Сервер подписок"),
    HydraService("dnscrypt", "dnscrypt-proxy", "DNSCrypt"),
)

# Фоновые / опциональные.
OPTIONAL_SERVICES: tuple[HydraService, ...] = (
    HydraService("sync_agent", "hydra-sync-agent.timer", "Sync-агент (TTL/лимиты)"),
    HydraService("tg_bot", "xray-tg-bot", "Telegram user bot"),
    HydraService("tg_admin", "xray-tg-admin", "Telegram admin bot"),
)

ALL_SERVICES: tuple[HydraService, ...] = CORE_SERVICES + OPTIONAL_SERVICES

_UNITS_BY_KEY: dict[str, str] = {s.key: s.unit for s in ALL_SERVICES}


def unit_name(key: str) -> str:
    """Ключ → имя unit (например sub → vless-sub)."""
    if key not in _UNITS_BY_KEY:
        raise KeyError(f"Неизвестная служба HYDRA: {key!r}")
    return _UNITS_BY_KEY[key]


def core_unit_names() -> list[str]:
    return [s.unit for s in CORE_SERVICES]


def diagnostic_unit_names() -> list[str]:
    """Службы для меню «Статус и сеть» (раздел 4)."""
    return core_unit_names()


def is_active(unit: str) -> bool:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            check=False,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def probe_status(unit: str) -> ServiceStatus:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            check=False,
        )
        st = r.stdout.strip()
        if st == "active":
            return "active"
        if st == "inactive":
            return "inactive"
        if st == "failed":
            return "failed"
        return "missing"
    except Exception:
        return "missing"
