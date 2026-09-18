"""Контракт протокола «VLESS через внешний CDN»: имена, путь, значения по умолчанию.

Путь, имена и порт попадают сразу в три места — web-маршрут, inbound ядра и
клиентский профиль, — поэтому они проверяются здесь один раз и больше нигде не
собираются по частям.

Модуль намеренно лежит в слое контрактов: его читают и плагин, и сервис установки,
а импорт конкретного плагина сервисом (или наоборот) архитектурный тест запрещает.
"""

from __future__ import annotations

import re

from hydra.contracts import JsonValue

PROTOCOL_NAME = "vless_cdn"
DEFAULT_XHTTP_PATH = "/api/media/session"
MIN_PATH_SEGMENTS = 3
RESERVED_PATH_PREFIX = "/assets"

_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

# Значения immutable: они попадают в состояние как есть и не должны делиться
# между экземплярами.
CONFIG_DEFAULTS: tuple[tuple[str, JsonValue], ...] = (
    ("cdn_domain", ""),
    ("origin_host", ""),
    ("xhttp_path", DEFAULT_XHTTP_PATH),
    ("core_port", 0),
    ("encryption_mode", "native"),
    ("encryption_private_key", ""),
    ("encryption_public_key", ""),
    ("region_country_code", ""),
    ("region_country_name", ""),
    ("region_capital", ""),
    ("region_latitude", 0.0),
    ("region_longitude", 0.0),
    ("region_timezone", ""),
    ("region_extra_timezones", ""),
    ("region_image_id", ""),
    ("image_source", ""),
    ("image_attribution", ""),
)


def as_int(value: object) -> int:
    """Привести сохранённое значение к int, не доверяя его типу."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def normalize_path(value: object) -> str:
    """Return the canonical XHTTP path shared by the route, the core and the client."""
    path = str(value or "").strip()
    if not path:
        raise ValueError("XHTTP путь не задан")
    if not path.startswith("/"):
        raise ValueError("XHTTP путь должен начинаться с «/»")
    if any(character.isspace() for character in path):
        raise ValueError("XHTTP путь не должен содержать пробелов")

    normalized = path.rstrip("/") or "/"
    if normalized == RESERVED_PATH_PREFIX or normalized.startswith(f"{RESERVED_PATH_PREFIX}/"):
        raise ValueError(f"XHTTP путь не может занимать зарезервированный {RESERVED_PATH_PREFIX}")

    segments = [segment for segment in normalized.split("/") if segment]
    if len(segments) < MIN_PATH_SEGMENTS:
        raise ValueError(
            f"XHTTP путь должен содержать не менее {MIN_PATH_SEGMENTS} сегментов",
        )
    return normalized


def normalize_hostname(value: object, *, field: str) -> str:
    """Return a lowercase hostname suitable for SNI and for an ACME HTTP-01 challenge."""
    host = str(value or "").strip().rstrip(".")
    if not host:
        raise ValueError(f"{field} не задан")
    if "://" in host or "/" in host or any(character.isspace() for character in host):
        raise ValueError(f"{field} должен быть именем хоста без схемы и пути")
    if len(host) > 253:
        raise ValueError(f"{field} слишком длинный")

    labels = host.split(".")
    if len(labels) < 2 or any(not _LABEL.match(label) for label in labels):
        raise ValueError(
            f"{field} должен быть доменным именем, например origin.example.com",
        )
    return host.lower()
