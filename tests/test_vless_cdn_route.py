"""TSK-003: маршрут origin в SNI-документе — h2c на L4 и PROXY v2 внутри."""

from __future__ import annotations

from typing import Any, cast

from hydra.contracts import JsonValue
from hydra.contracts.vless_cdn import (
    DECOY_HTTP_PORT,
    DECOY_ROOT,
    DECOY_ROUTE_KEY,
    DEFAULT_XHTTP_PATH,
    MEDIA_PATH_PREFIX,
    MEDIA_PLAYLIST_PATH,
    MEDIA_SEGMENT_PATH_PREFIX,
    PROTOCOL_NAME,
)
from hydra.core.sni_router import _collect_backends, _generate_config
from hydra.core.state import AppState, PluginState
from hydra.plugins.vless_cdn.plugin import VlessCdnPlugin

ORIGIN = "origin.example.com"
CDN = "cdn.example.com"
CORE_PORT = 20449
VLESS_DECOY_PORT = 10804


def _state(*, origin_http2: bool = True, with_vless: bool = False, cam_source_url: str = "") -> AppState:
    route = VlessCdnPlugin.route_config()
    route["origin_http2"] = origin_http2
    state = AppState()
    state.protocols[PROTOCOL_NAME] = PluginState(
        enabled=True,
        installed=True,
        config={
            "cdn_domain": CDN,
            "origin_host": ORIGIN,
            "xhttp_path": DEFAULT_XHTTP_PATH,
            "core_port": CORE_PORT,
            "cert_file": f"/etc/letsencrypt/live/{ORIGIN}/fullchain.pem",
            "key_file": f"/etc/letsencrypt/live/{ORIGIN}/privkey.pem",
            "cam_source_url": cam_source_url,
            DECOY_ROUTE_KEY: route,
        },
    )
    if with_vless:
        from hydra.plugins.vless_xhttp.plugin import ROUTE_CONFIG_KEY, VlessXhttpPlugin

        state.protocols["vless"] = PluginState(
            enabled=True,
            installed=True,
            config={
                "domain": "xhttp.example.com",
                "decoy_theme": "shop",
                "xhttp_path": "/xhttp",
                "cert_file": "/etc/letsencrypt/live/xhttp.example.com/fullchain.pem",
                "key_file": "/etc/letsencrypt/live/xhttp.example.com/privkey.pem",
                # Чужая декларация аннотирована шире реального содержимого.
                ROUTE_CONFIG_KEY: cast(JsonValue, VlessXhttpPlugin.route_config()),
            },
        )
    return state


def _backends(**kwargs) -> dict[str, dict]:
    return {backend["name"]: backend for backend in _collect_backends(_state(**kwargs))}


def _document(**kwargs) -> dict[str, Any]:
    state = _state(**kwargs)
    return _generate_config(_collect_backends(state), state)


def _find(node: Any, predicate) -> dict | None:
    """Найти узел документа по признаку, не полагаясь на его вложенность."""
    if isinstance(node, dict):
        if predicate(node):
            return node
        for value in node.values():
            found = _find(value, predicate)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find(item, predicate)
            if found is not None:
                return found
    return None


def _require(node: dict | None, description: str) -> dict:
    assert node is not None, f"{description} отсутствует в документе"
    return node


def _tls_route(document: dict, domain: str) -> dict | None:
    return _find(
        document,
        lambda node: node.get("match") == [{"tls": {"sni": [domain]}}],
    )


def _inner_server(document: dict, port: int) -> dict | None:
    return _find(document, lambda node: node.get("listen") == [f"127.0.0.1:{port}"])


def test_route_reads_its_identity_from_the_protocol_config():
    backend = _backends()[PROTOCOL_NAME]

    assert backend["domain"] == ORIGIN
    assert backend["port"] == CORE_PORT
    assert backend["decoy_port"] == DECOY_HTTP_PORT
    assert backend["decoy_root"] == DECOY_ROOT
    assert backend["proxy_path"] == DEFAULT_XHTTP_PATH
    assert backend["route_kind"] == "http_path_proxy"
    assert backend["origin_http2"] is True
    assert backend["upstream_tls"] is False, "ядро слушает без TLS"
    assert backend["public_host"] == CDN, "наверх уходит публичное имя"


def test_l4_terminates_tls_and_offers_http2_to_the_cdn():
    route = _require(_tls_route(_document(), ORIGIN), "маршрут origin")

    handlers = route["handle"]
    termination = handlers[0]
    assert termination["handler"] == "tls"
    assert termination["connection_policies"] == [{"alpn": ["h2", "http/1.1"]}]

    forward = handlers[1]
    assert forward["handler"] == "proxy"
    assert forward["proxy_protocol"] == "v2"
    assert forward["upstreams"] == [{"dial": [f"127.0.0.1:{DECOY_HTTP_PORT}"]}]


def test_inner_server_routes_the_tunnel_then_the_media_then_the_assets_then_the_site():
    server = _require(_inner_server(_document(), DECOY_HTTP_PORT), "внутренний сервер")

    assert server["protocols"] == ["h1", "h2c"]
    assert server["listener_wrappers"], "PROXY v2 wrapper must stay in place"
    assert server["automatic_https"] == {"disable": True, "disable_redirects": True}
    assert server["logs"]["logger_names"] == {ORIGIN: "vless-cdn-decoy"}

    tunnel, playlist, segments, assets, fallback = server["routes"]

    assert tunnel["match"] == [
        {"path": [DEFAULT_XHTTP_PATH, f"{DEFAULT_XHTTP_PATH}/*"]},
    ], "путь туннеля разбирается первым"
    proxy = tunnel["handle"][0]
    assert proxy["handler"] == "reverse_proxy"
    assert proxy["flush_interval"] == -1, "поток не должен буферизоваться"
    assert proxy["upstreams"] == [{"dial": f"127.0.0.1:{CORE_PORT}"}]
    transport = proxy["transport"]
    assert transport["versions"] == ["2", "h2c"], "до ядра путь идёт по cleartext HTTP/2"
    assert "tls" not in transport, "ядро принимает расшифрованный поток: TLS на этом плече лишний"
    assert proxy["headers"]["request"]["set"]["Host"] == [CDN], "клиент и ядро видят одно публичное имя"
    assert proxy["headers"]["response"]["set"]["Cache-Control"] == [
        "no-store, no-transform",
    ], "туннель нельзя кешировать"

    # Медиа плеера — тем же file_server'ом, но с явным Content-Type: боевой путь
    # живёт в том же семействе /api/media/*, поэтому он «один из многих».
    assert playlist["match"] == [{"path": [MEDIA_PLAYLIST_PATH]}]
    assert playlist["handle"][0]["response"]["set"]["Content-Type"] == ["application/vnd.apple.mpegurl"]
    assert playlist["handle"][1]["handler"] == "file_server"

    assert segments["match"] == [{"path": [f"{MEDIA_SEGMENT_PATH_PREFIX.rstrip('/')}/*"]}]
    assert segments["handle"][0]["response"]["set"]["Content-Type"] == ["video/mp2t"]
    assert segments["handle"][1]["handler"] == "file_server"

    assert assets["match"] == [{"path": ["/assets/*"]}], "статика — своим маршрутом"
    cache = assets["handle"][0]
    assert cache["handler"] == "headers"
    assert cache["response"]["set"]["Cache-Control"] == ["public, max-age=86400"]
    assert assets["handle"][1]["handler"] == "file_server"

    assert "match" not in fallback, "сайт обслуживает всё остальное и ничего не перехватывает"
    assert fallback["handle"][0]["handler"] == "file_server"
    assert fallback["handle"][0]["root"] == DECOY_ROOT


def test_the_tunnel_path_stays_inside_the_media_family_the_site_uses():
    """Боевой путь обязан делить префикс с медиа сайта, иначе он выбивается из трафика."""
    backend = _backends()[PROTOCOL_NAME]

    assert backend["proxy_path"].startswith(f"{MEDIA_PATH_PREFIX}/")


def test_a_source_makes_media_a_reverse_proxy_relay_to_go2rtc():
    """С источником /api/media/* ретранслируется на локальный go2rtc, без ffmpeg и без статики."""
    source = "rtsp://8.8.8.8/live"  # go2rtc тянет любой вход, в т.ч. rtsp
    backend = _backends(cam_source_url=source)[PROTOCOL_NAME]
    assert backend["media_source"] == {
        "host": "127.0.0.1",
        "port": 1984,
        "tls": False,
        "dir": "/api",
        "playlist": "stream.m3u8?src=decoy",
    }

    server = _require(
        _inner_server(_document(cam_source_url=source), DECOY_HTTP_PORT),
        "внутренний сервер",
    )
    tunnel, media, assets, fallback = server["routes"]
    assert tunnel["match"][0]["path"][0] == DEFAULT_XHTTP_PATH, "туннель всё ещё первый"
    assert media["match"] == [{"path": [f"{MEDIA_PATH_PREFIX}/*"]}]
    rewrite, relay = media["handle"]
    # go2rtc пишет относительные ссылки → одна замена ^/api/media/ → /api/ покрывает всё.
    assert rewrite["handler"] == "rewrite"
    assert rewrite["path_regexp"] == [{"find": f"^{MEDIA_PATH_PREFIX}/", "replace": "/api/"}]
    assert relay["handler"] == "reverse_proxy"
    assert relay["upstreams"] == [{"dial": "127.0.0.1:1984"}]
    assert "tls" not in relay["transport"], "локальный go2rtc — плайн HTTP, без TLS"
    # upstream упал → отдаём статику сайта, а не голую 5xx.
    assert relay["handle_response"][0]["match"]["status_code"] == [502, 503, 504]
    assert relay["handle_response"][0]["routes"][0]["handle"][0]["handler"] == "file_server"
    assert "match" not in fallback
    assert assets["match"] == [{"path": ["/assets/*"]}]


def test_a_route_without_a_media_prefix_keeps_two_routes():
    """Чужой http-протокол без медиа-семейства получает прежнюю таблицу маршрутов."""
    vless_server = _require(
        _inner_server(_document(with_vless=True), VLESS_DECOY_PORT),
        "внутренний сервер чужого протокола",
    )

    tunnel, fallback = vless_server["routes"]
    assert "match" in tunnel
    assert "match" not in fallback
    for route in vless_server["routes"]:
        for match in route.get("match", []):
            if "path" in match:
                assert not match["path"][0].startswith(MEDIA_PATH_PREFIX)


def test_the_site_can_never_answer_on_the_tunnel_path():
    """Сайт обязан оставаться последним и без своего пути, иначе он перехватит туннель."""
    server = _require(_inner_server(_document(), DECOY_HTTP_PORT), "внутренний сервер")
    tunnel = server["routes"][0]

    assert tunnel["match"][0]["path"] == [
        DEFAULT_XHTTP_PATH,
        f"{DEFAULT_XHTTP_PATH}/*",
    ]
    assert "match" not in server["routes"][-1], "у сайта нет собственного пути — он обслуживает остаток"


def test_the_static_prefix_and_the_tunnel_path_do_not_overlap():
    """Туннель внутри /assets отдавался бы как статика — это запрещено контрактом."""
    prefix = str(VlessCdnPlugin.route_config()["assets_prefix"]).rstrip("/")
    path = _backends()[PROTOCOL_NAME]["proxy_path"]

    assert path != prefix
    assert not path.startswith(f"{prefix}/"), "туннель не может жить внутри статики"


def test_a_route_without_the_flag_keeps_behaving_as_before():
    document = _document(origin_http2=False)

    termination = _require(_tls_route(document, ORIGIN), "маршрут origin")["handle"][0]
    assert "connection_policies" not in termination

    server = _require(_inner_server(document, DECOY_HTTP_PORT), "внутренний сервер")
    assert "protocols" not in server


def test_a_route_stored_by_an_older_version_is_refreshed_on_load(tmp_path, monkeypatch):
    """Дефолты умеют только добавлять ключи: прежняя копия маршрута иначе остаётся навсегда."""
    from hydra.core import state as state_module

    monkeypatch.setattr(state_module, "STATE_FILE", tmp_path / "state.json")
    state = _state()
    stored = state.protocols[PROTOCOL_NAME].config[DECOY_ROUTE_KEY]
    assert isinstance(stored, dict)
    stale = dict(stored)
    stale.pop("upstream_tls", None)
    stale.pop("public_host_config", None)
    state.protocols[PROTOCOL_NAME].config[DECOY_ROUTE_KEY] = cast(JsonValue, stale)
    state_module.save_state(state)

    loaded = state_module.load_state()
    route = loaded.protocols[PROTOCOL_NAME].config[DECOY_ROUTE_KEY]
    assert isinstance(route, dict)

    assert route["upstream_tls"] is False, "ядро слушает без TLS — это должно доехать до планировщика"
    assert route["public_host_config"] == "cdn_domain"

    backend = _backends()[PROTOCOL_NAME]
    assert backend["upstream_tls"] is False
    assert backend["public_host"] == CDN


def test_other_protocols_are_untouched_by_our_route():
    backends = _backends(with_vless=True)
    document = _document(with_vless=True)

    assert "origin_http2" not in backends["vless"]
    assert "upstream_tls" not in backends["vless"], "чужой маршрут не переведён на cleartext"
    assert "public_host" not in backends["vless"], "чужое имя не переписывается"

    vless_server = _require(
        _inner_server(document, VLESS_DECOY_PORT),
        "внутренний сервер чужого протокола",
    )
    assert "protocols" not in vless_server

    vless_tls = _require(
        _tls_route(document, "xhttp.example.com"),
        "маршрут чужого протокола",
    )
    assert "connection_policies" not in vless_tls["handle"][0]

    vless_tunnel = _require(
        _find(vless_server, lambda node: node.get("handler") == "reverse_proxy"),
        "туннель чужого протокола",
    )
    assert vless_tunnel["transport"]["versions"] == ["2"], "у чужого протокола версии не меняются"
    assert vless_tunnel["transport"]["tls"]["server_name"] == "xhttp.example.com", (
        "inbound чужого протокола с сертификатом: TLS на этом плече остаётся"
    )
    assert vless_tunnel["headers"]["request"]["set"]["Host"] == ["xhttp.example.com"]
