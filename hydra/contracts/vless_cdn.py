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

# Ключ и порт маршрута в SNI-документе. Ключ обязан совпадать с тем, который читает
# планировщик; он продублирован здесь, потому что слой контрактов не может импортировать
# core — это нарушило бы порядок слоёв, который проверяет архитектурный тест.
DECOY_ROUTE_KEY = "_tls_http_decoy_route"
DECOY_HTTP_PORT = 10806
DECOY_ROOT = "/var/www/decoy-cdn"
DECOY_THEME = "status"

# Маршрут читает имена и порт из тех же полей состояния, что и остальной код, и объявляет
# HTTP/2 на участке CDN → origin. Константа типизирована, чтобы её можно было положить
# в состояние без приведения типов.
DECOY_ROUTE: dict[str, JsonValue] = {
    "kind": "http_path_proxy",
    "internal_port_config": "core_port",
    "domain_config": "origin_host",
    "decoy_http_port": DECOY_HTTP_PORT,
    "decoy_root": DECOY_ROOT,
    "decoy_theme": DECOY_THEME,
    "path_config": "xhttp_path",
    "origin_http2": True,
}

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
    ("region_city", ""),
    ("region_flag", ""),
    ("region_capital", ""),
    ("region_latitude", 0.0),
    ("region_longitude", 0.0),
    ("region_timezone", ""),
    ("region_extra_timezones", ""),
    ("region_image_id", ""),
    ("image_source", ""),
    ("image_attribution", ""),
    ("image_updated_at", 0.0),
    (DECOY_ROUTE_KEY, DECOY_ROUTE),
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


ENCRYPTION_SCHEME = "mlkem768x25519plus"
ENCRYPTION_MODES = ("native", "xorpub", "random")
DEFAULT_ENCRYPTION_MODE = "native"
CLIENT_ENCRYPTION_HANDSHAKE = "1rtt"

# Окно тикетов и ротации ключа в секундах: ядро берёт случайное значение между
# границами (`seconds = RandBetween(from, to)` в server.go); ноль с обеих сторон
# означает, что 0-RTT запрещён. Это окно в минутах, а не срок действия ключа.
ENCRYPTION_TICKET_SECONDS = (300, 600)
KEY_SIZE = 32


def _b64url(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_encryption_keypair() -> tuple[str, str]:
    """Сгенерировать пару X25519: (приватный ключ, публичный ключ) в base64url.

    Ядро принимает как X25519 (32 байта), так и ключ ML-KEM-768; для нашей схемы
    достаточно X25519, а имя схемы остаётся общим.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519

    private = x25519.X25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64url(private_bytes), _b64url(public_bytes)


def server_encryption_value(
    private_key: str,
    *,
    mode: str = DEFAULT_ENCRYPTION_MODE,
    seconds: tuple[int, int] = ENCRYPTION_TICKET_SECONDS,
) -> str:
    """Строка `decryption` для inbound: схема, режим, окно тикетов, приватный ключ."""
    if mode not in ENCRYPTION_MODES:
        raise ValueError(f"режим шифрования не поддерживается: {mode}")
    key = str(private_key).strip()
    if not key:
        raise ValueError("приватный ключ не задан")
    try:
        start, end = int(seconds[0]), int(seconds[1])
    except (TypeError, ValueError) as exc:
        raise ValueError("окно тикетов должно быть числом") from exc
    if start <= 0 or end < start:
        raise ValueError("окно тикетов должно быть положительным и упорядоченным")
    return f"{ENCRYPTION_SCHEME}.{mode}.{start}-{end}s.{key}"


def client_encryption_value(
    public_key: str,
    *,
    mode: str = DEFAULT_ENCRYPTION_MODE,
) -> str:
    """Строка `encryption` для клиента: схема, режим, рукопожатие, публичный ключ."""
    if mode not in ENCRYPTION_MODES:
        raise ValueError(f"режим шифрования не поддерживается: {mode}")
    key = str(public_key).strip()
    if not key:
        raise ValueError("публичный ключ не задан")
    return f"{ENCRYPTION_SCHEME}.{mode}.{CLIENT_ENCRYPTION_HANDSHAKE}.{key}"


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
