"""TSK-003: маршрут origin в SNI-документе — h2c на L4 и PROXY v2 внутри."""

from __future__ import annotations

from typing import Any, cast

from hydra.contracts import JsonValue
from hydra.contracts.vless_cdn import (
    DECOY_HTTP_PORT,
    DECOY_ROOT,
    DECOY_ROUTE_KEY,
    DEFAULT_XHTTP_PATH,
    PROTOCOL_NAME,
)
from hydra.core.sni_router import _collect_backends, _generate_config
from hydra.core.state import AppState, PluginState
from hydra.plugins.vless_cdn.plugin import VlessCdnPlugin

ORIGIN = "origin.example.com"
CDN = "cdn.example.com"
CORE_PORT = 20449
VLESS_DECOY_PORT = 10804


def _state(*, origin_http2: bool = True, with_vless: bool = False) -> AppState:
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


def test_inner_server_routes_the_tunnel_then_the_assets_then_the_site():
    server = _require(_inner_server(_document(), DECOY_HTTP_PORT), "внутренний сервер")

    assert server["protocols"] == ["h1", "h2c"]
    assert server["listener_wrappers"], "PROXY v2 wrapper must stay in place"
    assert server["automatic_https"] == {"disable": True, "disable_redirects": True}

    tunnel, assets, fallback = server["routes"]

    assert tunnel["match"] == [
        {"path": [DEFAULT_XHTTP_PATH, f"{DEFAULT_XHTTP_PATH}/*"]},
    ], "путь туннеля разбирается первым"
    proxy = tunnel["handle"][0]
    assert proxy["handler"] == "reverse_proxy"
    assert proxy["flush_interval"] == -1, "поток не должен буферизоваться"
    assert proxy["upstreams"] == [{"dial": f"127.0.0.1:{CORE_PORT}"}]
    assert proxy["transport"]["versions"] == ["2"], "до ядра путь идёт по h2c"
    assert proxy["headers"]["request"]["set"]["Host"] == [ORIGIN]
    assert proxy["headers"]["response"]["set"]["Cache-Control"] == [
        "no-store, no-transform",
    ], "туннель нельзя кешировать"

    assert assets["match"] == [{"path": ["/assets/*"]}], "статика — своим маршрутом"
    cache = assets["handle"][0]
    assert cache["handler"] == "headers"
    assert cache["response"]["set"]["Cache-Control"] == ["public, max-age=86400"]
    assert assets["handle"][1]["handler"] == "file_server"

    assert "match" not in fallback, "сайт обслуживает всё остальное и ничего не перехватывает"
    assert fallback["handle"][0]["handler"] == "file_server"
    assert fallback["handle"][0]["root"] == DECOY_ROOT


def test_the_site_can_never_answer_on_the_tunnel_path():
    """Сайт обязан оставаться последним и без своего пути, иначе он перехватит туннель."""
    server = _require(_inner_server(_document(), DECOY_HTTP_PORT), "внутренний сервер")
    tunnel, _assets, fallback = server["routes"]

    assert tunnel["match"][0]["path"] == [
        DEFAULT_XHTTP_PATH,
        f"{DEFAULT_XHTTP_PATH}/*",
    ]
    assert "match" not in fallback, "у сайта нет собственного пути — он обслуживает остаток"


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


def test_other_protocols_are_untouched_by_our_route():
    backends = _backends(with_vless=True)
    document = _document(with_vless=True)

    assert "origin_http2" not in backends["vless"]

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
