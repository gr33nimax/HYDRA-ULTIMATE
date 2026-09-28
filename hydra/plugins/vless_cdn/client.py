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
from hydra.contracts.utls import UTLS_FINGERPRINTS
from hydra.contracts.vless_cdn import (
    CLIENT_LABEL,
    DEFAULT_ENCRYPTION_MODE,
    DEFAULT_UTLS_FINGERPRINT,
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


def _fingerprint(config: Mapping[str, object]) -> str:
    """Отпечаток ClientHello из конфига; пусто — `none`, то есть клиент решает сам.

    Читаем терпимо: испорченное значение в состоянии не должно ломать профиль —
    неизвестный отпечаток ядро отвергнет, поэтому оно считается дефолтом. Пишем,
    наоборот, строго: команда отклонит всё, чего нет в списке.
    """
    fingerprint = str(config.get("utls_fingerprint", DEFAULT_UTLS_FINGERPRINT)).strip().lower()
    if fingerprint not in UTLS_FINGERPRINTS:
        fingerprint = DEFAULT_UTLS_FINGERPRINT
    return "" if fingerprint == "none" else fingerprint


def tls_block(cdn_domain: str, fingerprint: str) -> dict[str, Any]:
    """TLS для клиента: публичное имя, h2 и выбранный отпечаток ClientHello.

    Пустой отпечаток — не ошибка: тогда блока `utls` нет вовсе и ClientHello собирает
    сам клиент. Это заметнее для DPI, чем chrome, поэтому выбор вынесен оператору,
    а не спрятан в коде.
    """
    block: dict[str, Any] = {
        "enabled": True,
        "server_name": cdn_domain,
        "alpn": ["h2"],
    }
    if fingerprint:
        block["utls"] = {"enabled": True, "fingerprint": fingerprint}
    return block


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
        "tls": tls_block(cdn, _fingerprint(config)),
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
        # Ссылку парсят клиенты (NekoBox, Throne), которые берут path буквально
        # и не добавляют trailing slash сами. Ядро же валидирует путь со
        # слешем, поэтому без него запрос отвергается. Клиенты, которые
        # нормализуют path сами (sing-box), со слешем тоже работают.
        "path": f"{path}/",
        "mode": MODE,
        "extra": json.dumps(link_extra(), separators=(",", ":"), sort_keys=True),
    }
    # Отпечаток добавляется только когда он выбран: при `none` параметра в ссылке нет,
    # и выбор ClientHello остаётся клиенту.
    fingerprint = _fingerprint(config)
    if fingerprint:
        parameters["fp"] = fingerprint
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
        "utls_fingerprint": _fingerprint(config) or "none",
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
