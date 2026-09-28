"""Pure HTTP decoy-server sections for the Caddy SNI document."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from hydra.contracts.vless_cdn import (
    GATE_HOST,
    GATE_PORT,
    MEDIA_PATH_PREFIX,
    MEDIA_PLAYLIST_PATH,
    MEDIA_SEGMENT_PATH_PREFIX,
)

Backend = dict[str, Any]

# MIME медиа-семейства: без него Caddy отдал бы плейлист и сегменты как octet-stream,
# и плеер бы их не принял. Range-запросы file_server умеет сам.
PLAYLIST_CONTENT_TYPE = "application/vnd.apple.mpegurl"
SEGMENT_CONTENT_TYPE = "video/mp2t"
PLAYLIST_CACHE_CONTROL = "no-cache"
SEGMENT_CACHE_CONTROL = "public, max-age=60"


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from rendered plugin config, or ``default``.

    A listener port arrives from plugin configuration, so a malformed value
    must not abort the whole Caddy document render.
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return int(value.strip())
        except (TypeError, ValueError):
            return default
    return default


def _redirect_server() -> dict[str, Any]:
    return {
        "listen": [":80"],
        "automatic_https": {
            "disable": True,
            "disable_redirects": True,
        },
        "routes": [
            {
                "handle": [
                    {
                        "handler": "static_response",
                        "status_code": 308,
                        "headers": {
                            "Location": [
                                "https://{http.request.host}{http.request.uri}",
                            ],
                        },
                    },
                ],
            },
        ],
    }


def _static_decoy_server(
    backend: Backend,
    *,
    listen_port: int,
    root: str,
    logger: str,
    listener_wrappers: Callable[[], list[dict[str, Any]]],
) -> dict[str, Any]:
    return {
        "listen": [f"127.0.0.1:{listen_port}"],
        "listener_wrappers": listener_wrappers(),
        "automatic_https": {
            "disable": True,
            "disable_redirects": True,
        },
        "routes": [
            {
                "handle": [
                    {"handler": "file_server", "root": root},
                ],
            },
        ],
        "logs": {"logger_names": {backend["domain"]: logger}},
    }


def _trusttunnel_server(
    backend: Backend,
    settings: Any,
    *,
    relay_enabled: bool,
    listener_wrappers: Callable[[], list[dict[str, Any]]],
) -> dict[str, Any]:
    relay = relay_enabled and "trusttunnel" in settings.relay_ports
    upstream_port = settings.relay_ports["trusttunnel"] if relay else settings.internal_ports["trusttunnel"]
    transport: dict[str, Any] = {
        "protocol": "http",
        "versions": ["2"],
        "response_header_timeout": "5s",
        "tls": {"insecure_skip_verify": True},
    }
    if relay:
        transport["proxy_protocol"] = "v2"
        transport["keep_alive"] = {"enabled": False}
    decoy_handler = {
        "handler": "file_server",
        "root": "/var/www/decoy-c",
    }
    return {
        "listen": [
            f"127.0.0.1:{settings.decoy_ports['trusttunnel']}",
        ],
        "listener_wrappers": listener_wrappers(),
        "automatic_https": {
            "disable": True,
            "disable_redirects": True,
        },
        "routes": [
            {
                "match": [{"method": ["CONNECT"]}],
                "handle": [
                    {
                        "handler": "reverse_proxy",
                        "upstreams": [
                            {"dial": f"127.0.0.1:{upstream_port}"},
                        ],
                        "transport": transport,
                        "headers": {
                            "request": {
                                "set": {
                                    "Proxy-Authorization": [
                                        "{http.request.header.Proxy-Authorization}",
                                    ],
                                    "Authorization": [
                                        "{http.request.header.Authorization}",
                                    ],
                                    "Host": ["{http.request.hostport}"],
                                },
                            },
                        },
                        "handle_response": [
                            {
                                "match": {
                                    "status_code": [502, 503, 504],
                                },
                                "routes": [
                                    {
                                        "handle": [
                                            decoy_handler.copy(),
                                        ],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
            {"handle": [decoy_handler.copy()]},
        ],
        "errors": {
            "routes": [{"handle": [decoy_handler.copy()]}],
        },
        "logs": {
            "logger_names": {
                backend["domain"]: "trusttunnel",
            },
        },
    }


def _static_handlers(
    content_type: str,
    cache_control: str,
    decoy_handler: dict[str, Any],
) -> list[dict[str, Any]]:
    """Обработчики статики с явным Content-Type: file_server взял бы его по расширению,
    а для HLS-типов его может не оказаться в таблице MIME. Range отдаёт сам file_server."""
    headers = {
        "Content-Type": [content_type],
        "Cache-Control": [cache_control],
    }
    return [{"handler": "headers", "response": {"set": headers}}, decoy_handler.copy()]


def _static_route(
    match_path: str,
    content_type: str,
    cache_control: str,
    decoy_handler: dict[str, Any],
) -> dict[str, Any]:
    return {
        "match": [{"path": [match_path]}],
        "handle": _static_handlers(content_type, cache_control, decoy_handler),
    }


def _media_playlist_route(decoy_handler: dict[str, Any]) -> dict[str, Any]:
    """Плейлист идёт через сторожа: он поднимает поток по требованию и гасит по простою.

    Сегменты рядом остаются статикой — это мегабайты неизменяемых файлов, гонять их через
    python незачем. Сторожу достаётся только плейлист: он крошечный и запрашивается
    постоянно, то есть служит естественным пульсом зрителя.

    Сторож лежит (5xx) → отдаём тот же плейлист статикой: медиа-путь не должен зиять
    голой ошибкой даже тогда, когда сторож не поднялся.
    """
    return {
        "match": [{"path": [MEDIA_PLAYLIST_PATH]}],
        "handle": [
            {
                "handler": "reverse_proxy",
                "upstreams": [{"dial": f"{GATE_HOST}:{GATE_PORT}"}],
                # Сторож на холодном старте ждёт первый сегмент: ffmpeg поднимается, тянет
                # источник и режет по кейфрейму — это секунды, и таймаут должен их пережить.
                "transport": {"protocol": "http", "response_header_timeout": "40s"},
                "handle_response": [
                    {
                        "match": {"status_code": [502, 503, 504]},
                        "routes": [
                            {
                                "handle": _static_handlers(
                                    PLAYLIST_CONTENT_TYPE,
                                    PLAYLIST_CACHE_CONTROL,
                                    decoy_handler,
                                ),
                            },
                        ],
                    },
                ],
            },
        ],
    }


def _decoy_routes(
    path: str,
    assets_prefix: str,
    proxy: dict[str, Any],
    decoy_handler: dict[str, Any],
    *,
    media_prefix: str = "",
) -> list[dict[str, Any]]:
    """Таблица маршрутов: туннель, затем медиа сайта, затем статика, затем сайт.

    Порядок — часть контракта. Туннель идёт первым по своему точному пути и поэтому
    не может быть перехвачен медиа-маршрутом `/api/media/*` (Caddy берёт первое совпадение).
    Сайт идёт последним и ничего не перехватывает.
    """
    routes: list[dict[str, Any]] = [
        {
            "match": [{"path": [path, f"{path}/*"]}],
            "handle": [proxy],
        },
    ]
    if media_prefix:
        # Плейлист — через сторожа (он поднимает поток по требованию), сегменты — статикой
        # из корня сайта: /api/media/seg/... → {decoy_root}/api/media/seg/...
        routes.append(_media_playlist_route(decoy_handler))
        routes.append(
            _static_route(
                f"{MEDIA_SEGMENT_PATH_PREFIX.rstrip('/')}/*",
                SEGMENT_CONTENT_TYPE,
                SEGMENT_CACHE_CONTROL,
                decoy_handler,
            ),
        )
    if assets_prefix:
        routes.append(
            {
                "match": [{"path": [f"{assets_prefix}/*"]}],
                "handle": [
                    {
                        "handler": "headers",
                        "response": {
                            "set": {
                                "Cache-Control": ["public, max-age=86400"],
                            },
                        },
                    },
                    decoy_handler.copy(),
                ],
            },
        )
    routes.append({"handle": [decoy_handler.copy()]})
    return routes


def _path_proxy_decoy_server(
    backend: Backend,
    settings: Any,
    *,
    listener_wrappers: Callable[[], list[dict[str, Any]]],
) -> dict[str, Any]:
    path = str(backend["proxy_path"]).rstrip("/")
    # Префикс статики объявляет сам протокол: если он его не заявил, таблица маршрутов
    # остаётся прежней — два маршрута, как у остальных протоколов.
    assets_prefix = str(backend.get("assets_prefix") or "").rstrip("/")
    # Медиа-семейство обслуживаем статикой только там, где в нём же живёт туннель:
    # путь заявлен внутри /api/media/* — значит, плейлист и сегменты сайта — соседи
    # боевого пути, а не отдельный префикс. У чужих http-протоколов путь снаружи,
    # и их таблица маршрутов не меняется.
    media_prefix = MEDIA_PATH_PREFIX if path.startswith(f"{MEDIA_PATH_PREFIX}/") else ""
    exact_source = str(backend["name"]) in settings.relay_ports
    upstream_port = settings.relay_ports[str(backend["name"])] if exact_source else _as_int(backend["port"])
    upstream_tls = bool(backend.get("upstream_tls", True))
    transport: dict[str, Any] = {
        "protocol": "http",
        # Явный h2c: без TLS Caddy иначе ждёт HTTP/1.1, и расшифрованный поток CDN
        # до ядра не доходит. TLS на этом плече — только там, где его заявил маршрут.
        "versions": ["2"] if upstream_tls else ["2", "h2c"],
        "response_header_timeout": "30s",
    }
    if upstream_tls:
        transport["tls"] = {"server_name": str(backend["domain"])}
    if exact_source:
        # A PROXY header describes one downstream TCP peer.  Prevent HTTP/2
        # connection reuse from mixing several clients behind one header.
        transport["proxy_protocol"] = "v2"
        transport["keep_alive"] = {"enabled": False}
    decoy_handler = {
        "handler": "file_server",
        "root": str(backend["decoy_root"]),
    }
    proxy = {
        "handler": "reverse_proxy",
        "upstreams": [
            {"dial": f"127.0.0.1:{upstream_port}"},
        ],
        "flush_interval": -1,
        "transport": transport,
        "headers": {
            "request": {
                "set": {
                    # Публичное имя, а не origin: клиент тоже ходит на публичное имя,
                    # и ядро должно видеть то же самое.
                    "Host": [str(backend.get("public_host") or backend["domain"])],
                },
            },
            # Туннель не должен кешироваться нигде по пути.
            "response": {
                "set": {
                    "Cache-Control": ["no-store, no-transform"],
                },
            },
        },
        "handle_response": [
            {
                "match": {"status_code": [502, 503, 504]},
                "routes": [
                    {"handle": [decoy_handler.copy()]},
                ],
            },
        ],
    }
    server: dict[str, Any] = {
        "listen": [f"127.0.0.1:{_as_int(backend['decoy_port'])}"],
        "listener_wrappers": listener_wrappers(),
        "automatic_https": {
            "disable": True,
            "disable_redirects": True,
        },
        "routes": _decoy_routes(
            path,
            assets_prefix,
            proxy,
            decoy_handler,
            media_prefix=media_prefix,
        ),
        "errors": {
            "routes": [{"handle": [decoy_handler.copy()]}],
        },
        "logs": {
            "logger_names": {
                str(backend["domain"]): ("vless-cdn-decoy" if backend["name"] == "vless_cdn" else "decoy"),
            },
        },
    }
    if backend.get("origin_http2"):
        # Расшифрованный поток от CDN может быть HTTP/2; без h2c здесь внутренний
        # сервер понял бы только HTTP/1.1, и туннель бы не поднялся.
        server["protocols"] = ["h1", "h2c"]
    return server


def http_servers(
    backends: list[Backend],
    settings: Any,
    *,
    relay_enabled: bool,
    listener_wrappers: Callable[[], list[dict[str, Any]]],
) -> dict[str, Any]:
    """Render redirect and protocol decoy servers."""
    servers = {"https_redirect": _redirect_server()}
    by_name = {str(item["name"]): item for item in backends}
    if anytls := by_name.get("anytls"):
        servers["anytls_decoy"] = _static_decoy_server(
            anytls,
            listen_port=settings.decoy_ports["anytls"],
            root="/var/www/decoy-b",
            logger="decoy",
            listener_wrappers=listener_wrappers,
        )
    if trusttunnel := by_name.get("trusttunnel"):
        servers["trusttunnel_decoy"] = _trusttunnel_server(
            trusttunnel,
            settings,
            relay_enabled=relay_enabled,
            listener_wrappers=listener_wrappers,
        )
    if hysteria2 := by_name.get("hysteria2"):
        servers["hysteria2_decoy"] = _static_decoy_server(
            hysteria2,
            listen_port=settings.decoy_ports["hysteria2"],
            root="/var/www/decoy-hysteria2",
            logger="decoy",
            listener_wrappers=listener_wrappers,
        )
    for backend in backends:
        if backend.get("route_kind") != "http_path_proxy":
            continue
        servers[f"{backend['name']}_decoy"] = _path_proxy_decoy_server(
            backend,
            settings,
            listener_wrappers=listener_wrappers,
        )
    return servers


__all__ = ["http_servers"]
