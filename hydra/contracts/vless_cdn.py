"""Контракт протокола «VLESS через внешний CDN»: имена, путь, значения по умолчанию.

Путь, имена и порт попадают сразу в три места — web-маршрут, inbound ядра и
клиентский профиль, — поэтому они проверяются здесь один раз и больше нигде не
собираются по частям.

Модуль намеренно лежит в слое контрактов: его читают и плагин, и сервис установки,
а импорт конкретного плагина сервисом (или наоборот) архитектурный тест запрещает.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from collections.abc import Callable

from hydra.contracts import JsonValue
from hydra.contracts.hostnames import normalize_hostname as _shared_normalize_hostname

PROTOCOL_NAME = "vless_cdn"

# Имя, которое видит клиент: меню панели, подписка и подпись share-ссылки берут его
# отсюда, иначе в клиенте два VLESS-профиля выглядят одинаково.
CLIENT_LABEL = "VLESS Яндекс CDN"
DEFAULT_XHTTP_PATH = "/api/media/session"
MIN_PATH_SEGMENTS = 3
RESERVED_PATH_PREFIX = "/assets"

# Семейство медиа-путей. Под ним живёт и клиент сайта-заглушки (плейлист и сегменты),
# и боевой путь VLESS: так боевой путь — одна из многих медиа-сессий, а не одинокая
# полоса трафика на мёртвом префиксе. См. .kiro/specs/vless-cdn-decoy.
MEDIA_PATH_PREFIX = "/api/media"
MEDIA_PLAYLIST_PATH = f"{MEDIA_PATH_PREFIX}/playlist.m3u8"
MEDIA_SEGMENT_PATH_PREFIX = f"{MEDIA_PATH_PREFIX}/seg/"

# Проводные метки, которые шлёт и плеер заглушки, и сам транспорт VLESS. Значения — те же,
# что в hydra/plugins/vless_cdn/profile.py, и держатся здесь, чтобы клиент, сайт и туннель
# не разъехались (R4).
MEDIA_SESSION_HEADER = "X-Upload-Token"
MEDIA_SEQ_PARAM = "chunk_id"
MEDIA_PADDING_HEADER = "X-Client-Version"

# Формы источника камеры, которые принимает ретранслятор, по схеме/хосту URL.
MEDIA_SOURCE_HLS = "hls"
MEDIA_SOURCE_RTSP = "rtsp"
MEDIA_SOURCE_MJPEG = "mjpeg"
MEDIA_SOURCE_YOUTUBE = "youtube"
MEDIA_SOURCE_SCHEMES = ("http", "https", "rtsp")
YOUTUBE_HOSTS = frozenset(
    {"youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be"},
)

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
    "assets_prefix": RESERVED_PATH_PREFIX,
    "origin_http2": True,
    # Расшифрованный поток ядро принимает по cleartext HTTP/2: TLS на этом плече
    # завершён выше, а Caddy без явного h2c говорит по HTTP/1.1 и туннель не встаёт.
    "upstream_tls": False,
    # Клиент и ядро должны видеть одно публичное имя: origin-имя — деталь CDN.
    "public_host_config": "cdn_domain",
    # HLS-источник для /api/media/*: сайт ретранслирует его reverse_proxy'ем, а не кодирует
    # локально. Пусто — медиа-эндпоинт пустой (без fallback, как и решено).
    "media_source_config": "cam_source_url",
}

# Значения immutable: они попадают в состояние как есть и не должны делиться
# между экземплярами.
CONFIG_DEFAULTS: tuple[tuple[str, JsonValue], ...] = (
    ("cdn_domain", ""),
    ("origin_host", ""),
    ("xhttp_path", DEFAULT_XHTTP_PATH),
    ("core_port", 0),
    # Живая камера оператора: пусто — чистая синтетика (фолбэк без внешнего источника).
    # Форма URL (hls/rtsp/mjpeg/youtube) проверяется контрактом, SSRF — перед стримом.
    ("cam_source_url", ""),
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
    ("region_status", "unavailable"),
    ("region_error", ""),
    ("region_checked_at", 0.0),
    ("region_image_id", ""),
    ("image_source", ""),
    ("image_attribution", ""),
    ("image_updated_at", 0.0),
    ("image_last_attempt_at", 0.0),
    ("image_refresh_error", ""),
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
    # Боевой путь обязан лежать внутри медиа-семейства: иначе он выбивается из
    # органического медиа-трафика сайта и становится лёгкой зацепкой.
    if not normalized.startswith(f"{MEDIA_PATH_PREFIX}/"):
        raise ValueError(
            f"XHTTP путь должен лежать внутри {MEDIA_PATH_PREFIX}/, "
            "чтобы не отличаться от медиа-трафика сайта-заглушки",
        )

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
    """Compatibility re-export of the shared hostname validation contract."""
    return _shared_normalize_hostname(value, field=field)


def classify_media_source(value: object) -> str:
    """Форма источника камеры по URL: `hls`, `rtsp`, `mjpeg` или `youtube`.

    Форма однозначна и выводится из схемы/хоста, чтобы ретранслятор, сайт и контракт не
    решали это каждый по-своему. Нераспознанный или запрещённый URL — ошибка, а не
    догадка: пусть вызывающий сам решает, уходить ли на синтетику.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("URL источника пуст")
    parts = urllib.parse.urlsplit(raw)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in MEDIA_SOURCE_SCHEMES:
        raise ValueError(f"схема источника не поддерживается: {scheme or '(нет)'}")
    if not host:
        raise ValueError("URL источника без хоста")
    if host in YOUTUBE_HOSTS:
        # YouTube отдаёт только страницу-смотрильню; поток достаёт yt-dlp отдельно.
        return MEDIA_SOURCE_YOUTUBE
    if scheme == "rtsp":
        return MEDIA_SOURCE_RTSP
    if parts.path.lower().endswith(".m3u8"):
        return MEDIA_SOURCE_HLS
    # Остальной http(s) — обычный MJPEG/HTTP-поток вебкамеры.
    return MEDIA_SOURCE_MJPEG


def resolve_host(host: str) -> list[str]:
    """Все адреса, в которые разрешается имя; пусто, если не разрешается."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


def assert_public_media_source(
    value: object,
    *,
    resolve: Callable[[str], list[str]] = resolve_host,
) -> str:
    """Отклонить URL источника, указывающий внутрь хоста или в приватную сеть (SSRF).

    URL — операторский аргумент, поэтому проверяется до любого соединения: схема и форма
    допустимы, а хост либо литеральный адрес, либо имя, каждый адрес которого публичный.
    Разрешение имени только расширяемо: тесты подменяют `resolve`, не ходя в DNS.
    """
    raw = str(value or "").strip()
    kind = classify_media_source(raw)
    if kind == MEDIA_SOURCE_YOUTUBE:
        # Известные публичные хосты: резолвить их здесь незачем и вредно.
        return raw
    host = urllib.parse.urlsplit(raw).hostname or ""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        addresses = resolve(host)
        if not addresses:
            raise ValueError("URL источника не разрешается в адрес") from None
    else:
        addresses = [str(literal)]
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("URL источника разрешается не в адрес") from exc
        if not parsed.is_global:
            raise ValueError(
                "URL источника указывает во внутреннюю или служебную сеть",
            )
    return raw


def parse_hls_relay_source(
    value: object,
    *,
    resolve: Callable[[str], list[str]] = resolve_host,
) -> dict[str, object] | None:
    """Разобрать HLS-URL под reverse_proxy: хост, папка и имя плейлиста, или None.

    Ретранслируется только http(s) HLS с относительными сегментами: Caddy проксирует
    папку целиком, ничего не переписывая внутри плейлиста. RTSP/MJPEG/YouTube так не
    проксируются (нет готового HLS с относительными путями) — для них возвращаем None,
    и медиа-эндпоинт остаётся пустым. SSRF проверяется здесь же: URL операторский.
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if classify_media_source(raw) != MEDIA_SOURCE_HLS:
            return None
        assert_public_media_source(raw, resolve=resolve)
    except ValueError:
        return None
    parts = urllib.parse.urlsplit(raw)
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    if not host:
        return None
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path
    directory, _, basename = path.rpartition("/")
    if not basename:
        return None
    return {
        "host": host,
        "port": port,  # urlsplit.port уже int—or—None; дефолт тоже int
        "tls": scheme == "https",
        "dir": directory,  # без завершающего «/», может быть пустым для корня
        "playlist": basename,
    }


def normalize_media_source(
    value: object,
    *,
    resolve: Callable[[str], list[str]] = resolve_host,
) -> str:
    """Привести URL источника камеры к одному виду или отклонить его.

    Пусто — это «источника нет», то есть чистая синтетика: допустимое состояние, а не
    ошибка. Непустое значение проверяется на форму (`classify_media_source`) и на SSRF
    (`assert_public_media_source`), чтобы оператор не мог сохранить ссылку внутрь хоста.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    assert_public_media_source(raw, resolve=resolve)
    return raw
