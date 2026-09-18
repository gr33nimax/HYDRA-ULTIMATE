"""Профиль XHTTP для VLESS через CDN: одни значения на обеих сторонах.

Значения — из таблицы D3 дизайна (соответствие «параметр брифа → реальное поле ядра»).
Сервер и клиент собираются одним кодом, поэтому разъехаться не могут: отличаются только
поля, которые относятся к одной стороне.

Чего здесь намеренно нет: `h_keep_alive_period` (в этом ядре поле читается в секундах и
зажимается в 5 с – 5 мин, значение из референса скопировать нельзя), `sc_stream_up_server_secs`
(относится к `stream-up`, а мы в `packet-up`) и `congestion_controller`/`cwnd` (только HTTP/3).
"""
from __future__ import annotations

from typing import Any

MODE = "packet-up"
UPLINK_METHOD = "GET"

X_PADDING_BYTES = "100-1000"
X_PADDING_KEY = "hash"
X_PADDING_HEADER = "X-Client-Version"
X_PADDING_PLACEMENT = "queryInHeader"
X_PADDING_METHOD = "tokenish"

SESSION_PLACEMENT = "header"
SESSION_KEY = "X-Upload-Token"
SESSION_ID_TABLE = "Base62"
SESSION_ID_LENGTH = "16-32"

SEQ_PLACEMENT = "query"
SEQ_KEY = "chunk_id"

UPLINK_DATA_PLACEMENT = "body"

SC_MAX_EACH_POST_BYTES = "131072-1048576"
SC_MAX_BUFFERED_POSTS = 30
SC_MIN_POSTS_INTERVAL_MS = "50-150"
SERVER_MAX_HEADER_BYTES = 8192
NO_SSE_HEADER = False
NO_GRPC_HEADER = False

XMUX: dict[str, Any] = {
    "max_concurrency": "16-32",
    "max_connections": 0,
    "c_max_reuse_times": 1000,
    "h_max_request_times": "600-900",
    "h_max_reusable_secs": 100,
}


def _shared_fields(path: str, host: str) -> dict[str, Any]:
    """Поля, которые читают обе стороны: иначе кадры не разберутся."""
    return {
        "type": "xhttp",
        "mode": MODE,
        "host": host,
        "path": path,
        "x_padding_bytes": X_PADDING_BYTES,
        "x_padding_obfs_mode": True,
        "x_padding_key": X_PADDING_KEY,
        "x_padding_header": X_PADDING_HEADER,
        "x_padding_placement": X_PADDING_PLACEMENT,
        "x_padding_method": X_PADDING_METHOD,
        "session_placement": SESSION_PLACEMENT,
        "session_key": SESSION_KEY,
        "session_id_table": SESSION_ID_TABLE,
        "session_id_length": SESSION_ID_LENGTH,
        "seq_placement": SEQ_PLACEMENT,
        "seq_key": SEQ_KEY,
        "uplink_data_placement": UPLINK_DATA_PLACEMENT,
        "sc_max_each_post_bytes": SC_MAX_EACH_POST_BYTES,
        "no_grpc_header": NO_GRPC_HEADER,
    }


def xhttp_transport(path: str, host: str, *, client: bool) -> dict[str, Any]:
    """Собрать транспорт XHTTP для сервера или для клиента."""
    transport = _shared_fields(path, host)
    if client:
        # Клиент выбирает метод выгрузки и держит мультиплексирование соединений.
        transport["uplink_http_method"] = UPLINK_METHOD
        transport["xmux"] = dict(XMUX)
        return transport

    # Сторона сервера: приём выгрузки и её буферизация.
    transport["no_sse_header"] = NO_SSE_HEADER
    transport["sc_max_buffered_posts"] = SC_MAX_BUFFERED_POSTS
    transport["sc_min_posts_interval_ms"] = SC_MIN_POSTS_INTERVAL_MS
    transport["server_max_header_bytes"] = SERVER_MAX_HEADER_BYTES
    return transport


__all__ = ["MODE", "UPLINK_METHOD", "XMUX", "xhttp_transport"]
