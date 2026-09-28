"""Сборка inbound'ов VLESS XHTTP: один слушатель, два способа доказать имя.

Вынесено из модуля плагина, который стоял на пределе ревьюируемого размера. Порт
слушателя нужен в двух местах — сборке конфигурации и панели статуса, — и считаться
они обязаны одной формулой: статус показывал 443 там, где слушал 20448.
"""
from __future__ import annotations

from hydra.plugins.context import PluginStateAccess
from hydra.plugins.vless_xhttp.client import PUBLIC_PORT
from hydra.plugins.vless_xhttp.health import INBOUND_TAG
from hydra.plugins.vless_xhttp.security import is_reality, normalize_domain, server_tls
from hydra.plugins.vless_xhttp.tuning import transport as build_transport
from hydra.utils.tls import resolve_tls_material

INTERNAL_PORT = 20448


def applied_port(config: dict, state: PluginStateAccess | None) -> int:
    """Порт, который реально слушает inbound в выбранном режиме.

    Сертификатный вход всегда стоит за frontend'ом (loopback и внутренний порт),
    Reality — либо сам на 443, либо тоже за мультиплексором. Условие то же, что и у
    сборки inbound: панель показывала 443 там, где слушал 20448.
    """
    if not is_reality(config):
        return INTERNAL_PORT
    from hydra.core.sni_router import needs_mux

    return INTERNAL_PORT if state is not None and needs_mux(state) else PUBLIC_PORT


def certificate_inbound(config: dict, users: list[dict]) -> dict[str, object] | None:
    """Вход на нашем сертификате: TLS завершает frontend, слушаем loopback.

    Без сертификата и ключа входа не появляется вовсе: полупроверенный слушатель хуже
    отсутствующего, потому что выглядит рабочим.
    """
    raw_domain = str(config.get("domain", "")).strip()
    if not raw_domain:
        return None
    domain = normalize_domain(raw_domain)
    cert, key = resolve_tls_material(domain, config)
    if not cert or not key:
        return None
    return {
        "type": "vless",
        "tag": INBOUND_TAG,
        "listen": "127.0.0.1",
        "listen_port": INTERNAL_PORT,
        "users": users,
        "tls": {
            "enabled": True,
            "server_name": domain,
            "alpn": ["h2"],
            "certificate_path": cert,
            "key_path": key,
        },
        "transport": build_transport(config, client=False),
    }


def reality_inbound(
    state: PluginStateAccess,
    config: dict,
    users: list[dict],
) -> dict[str, object] | None:
    """Reality: чужое рукопожатие и наш ключ. Без мультиплексора слушаем сами 443."""
    from hydra.core.sni_router import needs_mux

    try:
        tls = server_tls(config)
    except ValueError:
        return None
    behind_mux = needs_mux(state)
    return {
        "type": "vless",
        "tag": INBOUND_TAG,
        "listen": "127.0.0.1" if behind_mux else "::",
        "listen_port": applied_port(config, state),
        "users": users,
        "tls": tls,
        "transport": build_transport(config, client=False),
    }


__all__ = [
    "INTERNAL_PORT",
    "applied_port",
    "certificate_inbound",
    "reality_inbound",
]
