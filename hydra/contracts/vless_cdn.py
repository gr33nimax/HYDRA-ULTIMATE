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

# Что показывает страница-заглушка. Видео — живой поток через ffmpeg, и он требует
# `cam_source_url`. Фото — региональная картинка без медиатрафика вовсе: страница живая,
# но объём VLESS она больше не объясняет — это осознанный размен, а не «то же дешевле».
MEDIA_MODE_VIDEO = "video"
MEDIA_MODE_PHOTO = "photo"
MEDIA_MODES = (MEDIA_MODE_VIDEO, MEDIA_MODE_PHOTO)
DEFAULT_MEDIA_MODE = MEDIA_MODE_VIDEO
MEDIA_MODE_LABELS: dict[str, str] = {MEDIA_MODE_VIDEO: "Видео", MEDIA_MODE_PHOTO: "Фото"}

# Настройки живого потока. `stream_hls_time` — только минимум: резать можно лишь по
# кейфреймам, поэтому у источника с интервалом в 3 с выйдет 3 с, сколько ни проси.
# Окно в 10 сегментов — это десятки секунд запаса вместо одной секунды у прежнего
# ретранслятора, и именно оно делает поток терпимым к задержке через CDN.
STREAM_HLS_TIME_DEFAULT = 2
STREAM_LIST_SIZE_DEFAULT = 10
# Простой, после которого сторож гасит ffmpeg. Ноль — не гасить никогда.
STREAM_IDLE_TIMEOUT_DEFAULT = 120
# Сторож медиа: Caddy проксирует ему только плейлист, сегменты остаются статикой.
GATE_HOST = "127.0.0.1"
GATE_PORT = 1985

# Проводные метки, которые шлёт и плеер заглушки, и сам транспорт VLESS. Значения — те же,
# что в hydra/plugins/vless_cdn/profile.py, и держатся здесь, чтобы клиент, сайт и туннель
# не разъехались (R4).
MEDIA_SESSION_HEADER = "X-Upload-Token"
MEDIA_SEQ_PARAM = "chunk_id"
MEDIA_PADDING_HEADER = "X-Client-Version"

# Формы источника, которые поток умеет отдать в браузер. MJPEG сюда не входит: ни HLS,
# ни MSE его не несут, то есть такой источник сохранился бы и молча не играл.
MEDIA_SOURCE_HLS = "hls"
MEDIA_SOURCE_RTSP = "rtsp"
MEDIA_SOURCE_SCHEMES = ("http", "https", "rtsp")
# YouTube — не форма, а явный отказ: страница-смотрильня требует отдельного резолвера,
# которого у нас нет, и такой URL умирает на разборе контейнера. Список держим, чтобы
# отказ был внятным, а не «не удалось подключиться».
YOUTUBE_HOSTS = frozenset(
    {"youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be"},
)

# Префикс, оставшийся от прежней ретрансляции через go2rtc: он уходил в его конфиг как
# есть. Наш код его больше не пишет, но читать обязан — иначе развёрнутая машина после
# обновления перестанет понимать собственный сохранённый источник.
MEDIA_SOURCE_PREFIX = "ffmpeg:"

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
}

# Значения immutable: они попадают в состояние как есть и не должны делиться
# между экземплярами.
CONFIG_DEFAULTS: tuple[tuple[str, JsonValue], ...] = (
    ("cdn_domain", ""),
    ("origin_host", ""),
    ("xhttp_path", DEFAULT_XHTTP_PATH),
    ("core_port", 0),
    # Живая камера оператора: пусто — медиа нет вовсе (плеер будет пустой, синтетики нет
    # с коммита «drop ffmpeg»). Форма URL (hls/rtsp/mjpeg) проверяется контрактом,
    # SSRF — до любого соединения.
    ("cam_source_url", ""),
    # Что показывает страница: живое видео или фото региона. Видео требует источника,
    # фото живёт без него и медиатрафика не гоняет. Дефолт — видео: он не меняет поведение
    # уже настроенных инсталляций.
    ("media_mode", DEFAULT_MEDIA_MODE),
    ("stream_hls_time", STREAM_HLS_TIME_DEFAULT),
    ("stream_hls_list_size", STREAM_LIST_SIZE_DEFAULT),
    ("stream_idle_timeout", STREAM_IDLE_TIMEOUT_DEFAULT),
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


def as_int_or(value: object, default: int) -> int:
    """Целое из состояния с дефолтом. Ноль — законное значение, поэтому «пусто» и «ноль»
    надо различать: для `stream_idle_timeout` ноль значит «не гасить никогда»."""
    if value is None or value == "":
        return default
    return as_int(value)


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


def strip_source_prefix(value: object) -> str:
    """Снять префикс прежней ретрансляции (`ffmpeg:`), если он есть: проверяем форму
    внутреннего URL. Наш код его больше не пишет, но обязан прочитать сохранённый."""
    raw = str(value or "").strip()
    if raw.lower().startswith(MEDIA_SOURCE_PREFIX):
        return raw[len(MEDIA_SOURCE_PREFIX) :].strip()
    return raw


def classify_media_source(value: object) -> str:
    """Форма источника по URL: `hls` или `rtsp`.

    Форма однозначна и выводится из схемы/хоста, чтобы поток и контракт не решали это
    каждый по-своему. Нераспознанный или запрещённый URL — ошибка, а не догадка.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("URL источника пуст")
    parts = urllib.parse.urlsplit(strip_source_prefix(raw))
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in MEDIA_SOURCE_SCHEMES:
        raise ValueError(f"схема источника не поддерживается: {scheme or '(нет)'}")
    if not host:
        raise ValueError("URL источника без хоста")
    if host in YOUTUBE_HOSTS:
        raise ValueError("YouTube поток не умеет: нужен прямой поток (HLS-плейлист или RTSP)")
    if scheme == "rtsp":
        return MEDIA_SOURCE_RTSP
    if parts.path.lower().endswith(".m3u8"):
        return MEDIA_SOURCE_HLS
    # MJPEG и прочий http-поток отклоняем: в браузере его нечем проиграть, а сохранить и
    # потом молча показать пустой плеер — худший из вариантов.
    raise ValueError("нужен HLS-плейлист (.m3u8) или RTSP: браузер не играет MJPEG")


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
    # Форма проверяется здесь же: нераспознанное или запрещённое (YouTube) — отказ до сети.
    classify_media_source(raw)
    host = urllib.parse.urlsplit(strip_source_prefix(raw)).hostname or ""
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


def normalize_media_source(
    value: object,
    *,
    resolve: Callable[[str], list[str]] = resolve_host,
) -> str:
    """Привести URL источника камеры к одному виду или отклонить его.

    Пусто — это «источника нет»: допустимое состояние (тогда в видео-режиме плеер будет
    пустой, а страница — фото), а не ошибка. Непустое значение проверяется на форму
    (`classify_media_source`) и на SSRF (`assert_public_media_source`), чтобы оператор не
    мог сохранить ссылку внутрь хоста.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    assert_public_media_source(raw, resolve=resolve)
    return raw


def normalize_media_mode(value: object) -> str:
    """Режим медиа. Неизвестное значение — дефолт, а не исключение.

    Так читаются состояния, записанные до появления поля: старые инсталляции не должны
    падать из-за отсутствующего ключа, а явно испорченное значение не должно ломать
    страницу — в обоих случаях поведение остаётся прежним (видео).
    """
    raw = str(value or "").strip().lower()
    return raw if raw in MEDIA_MODES else DEFAULT_MEDIA_MODE
