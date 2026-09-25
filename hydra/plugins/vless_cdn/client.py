"""Клиентские артефакты протокола: профиль sing-box и share-ссылка.

Клиент подключается к публичному CDN-домену, а не к нашему серверу: адрес origin
не должен появляться ни в профиле, ни в ссылке. Параметры транспорта берутся из того же
модуля, что и серверные, поэтому разъехаться не могут.
"""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping
from typing import Any

from hydra.contracts import JsonObject
from hydra.contracts.vless_cdn import (
    CLIENT_LABEL,
    DEFAULT_ENCRYPTION_MODE,
    DEFAULT_XHTTP_PATH,
    client_encryption_value,
    normalize_hostname,
    normalize_path,
)
from hydra.core.state_models import User
from hydra.plugins.vless_cdn.profile import MODE, link_extra, xhttp_transport

PUBLIC_PORT = 443

# Честная граница артефакта: профиль sing-box самодостаточен, а share-ссылка несёт
# XHTTP-настройки в блоке `extra`, который понимают клиенты Xray-семейства. Клиент,
# игнорирующий `extra`, соберёт другую разметку кадров и не подключится.
SHARE_LINK_NOTE = (
    "share-ссылка содержит настройки XHTTP в блоке extra; клиент, который его не читает, подключиться не сможет"
)


def tls_block(cdn_domain: str) -> dict[str, Any]:
    """TLS для клиента: имя и ALPN публичного домена, отпечаток не навязываем."""
    return {
        "enabled": True,
        "server_name": cdn_domain,
        "alpn": ["h2"],
    }


def _settings(config: Mapping[str, object]) -> tuple[str, str, str, str]:
    """(cdn-домен, путь, режим шифрования, публичный ключ) или ValueError."""
    cdn = normalize_hostname(config.get("cdn_domain", ""), field="CDN-домен")
    path = normalize_path(config.get("xhttp_path", DEFAULT_XHTTP_PATH))
    mode = str(config.get("encryption_mode") or DEFAULT_ENCRYPTION_MODE)
    public_key = str(config.get("encryption_public_key", "")).strip()
    if not public_key:
        raise ValueError("публичный ключ шифрования не выпущен")
    return cdn, path, mode, public_key


def outbound(user: User, config: Mapping[str, object]) -> JsonObject:
    """Исходящее подключение одного пользователя к публичному CDN-домену."""
    cdn, path, mode, public_key = _settings(config)
    outbound_config: JsonObject = {
        "type": "vless",
        "tag": f"vless-cdn-{user.email}",
        "server": cdn,
        "server_port": PUBLIC_PORT,
        "uuid": user.uuid,
        "encryption": client_encryption_value(public_key, mode=mode),
        "tls": tls_block(cdn),
        "transport": xhttp_transport(path, cdn, client=True),
    }
    return outbound_config


def profile(user: User, config: Mapping[str, object]) -> str:
    """Готовый конфиг клиента на sing-box."""
    connection = outbound(user, config)
    return json.dumps(
        {
            "log": {"level": "info"},
            "outbounds": [connection, {"type": "direct", "tag": "direct"}],
            "route": {"final": connection["tag"]},
        },
        indent=2,
    )


def share_link(user: User, config: Mapping[str, object]) -> str:
    """Ссылка `vless://` на публичный домен с настройками XHTTP в блоке `extra`."""
    cdn, path, _mode, public_key = _settings(config)
    parameters: dict[str, str] = {
        "encryption": client_encryption_value(public_key),
        "security": "tls",
        "sni": cdn,
        "alpn": "h2",
        "type": "xhttp",
        "host": cdn,
        "path": path,
        "mode": MODE,
        "extra": json.dumps(link_extra(), separators=(",", ":"), sort_keys=True),
    }
    query = urllib.parse.urlencode(list(parameters.items()))
    uuid = urllib.parse.quote(user.uuid, safe="")
    tag = urllib.parse.quote(f"{user.email} {CLIENT_LABEL}", safe="")
    return f"vless://{uuid}@{cdn}:{PUBLIC_PORT}?{query}#{tag}"


def client_view(user: User, config: Mapping[str, object]) -> dict[str, Any]:
    """То, что показывается оператору: куда подключается клиент и чем это ограничено."""
    cdn, path, mode, _public_key = _settings(config)
    return {
        "server": cdn,
        "port": PUBLIC_PORT,
        "path": path,
        "mode": MODE,
        "encryption_mode": mode,
        "share_note": SHARE_LINK_NOTE,
    }


__all__ = [
    "PUBLIC_PORT",
    "SHARE_LINK_NOTE",
    "client_view",
    "outbound",
    "profile",
    "share_link",
    "tls_block",
]
