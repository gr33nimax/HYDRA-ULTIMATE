"""
vless_installer/modules/sub_generator_pc.py
───────────────────────────────────────────────────────────────────────────────
Генерация подписочных конфигов для ПК (NekoBox PC / NyameBox).

Отличия от универсального sub_generator.py:
  • naive:// ссылки содержат fp=chrome и padding=true для предотвращения
    ошибок валидации ядра sing-box на ПК.
  • mieru:// ссылки генерируются в формате NekoBox PC (mierus:// с указанием
    порта в хосте и параметром transport вместо protocol).
  • sn://awg генерируется так же, поскольку он поддерживается ПК.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import urllib.parse
from typing import Optional

from vless_installer.modules.sub_generator import (
    _get_server_ip,
    _load_state,
    _load_naiveproxy_state,
    _load_mieru_state,
    get_awg_client_config,
    generate_awg_sn_link,
    generate_vless_links,
    generate_hysteria2_link
)


def generate_naive_link(state: dict, email: str) -> Optional[str]:
    """Генерация naive+https:// URI, оптимизированного для ПК (NekoBox)."""
    naive = _load_naiveproxy_state()
    if not naive.get("installed"):
        return None

    host = naive.get("domain", "") or state.get("domain", "") or _get_server_ip()
    port = naive.get("port", 8443)

    for u in naive.get("users", []):
        if u.get("username", "") == email:
            user = urllib.parse.quote(u["username"])
            pwd = urllib.parse.quote(u["password"])
            # fp=chrome и padding=true обязательны для корректной валидации ядра на ПК
            return f"naive+https://{user}:{pwd}@{host}:{port}?fp=chrome&padding=true#{email}%20Naive"

    return None


def generate_mieru_link(state: dict, email: str) -> list[str]:
    """Генерация mierus:// ссылки, оптимизированной для ПК (NekoBox)."""
    mieru = _load_mieru_state()
    if not mieru.get("installed"):
        return []

    host = state.get("domain", "") or _get_server_ip()
    port_start = mieru.get("port_start", 8964)
    protocol = mieru.get("protocol", "TCP")

    links = []
    for u in mieru.get("users", []):
        if u.get("username") == email:
            uname = u["username"]
            pwd = u["password"]
            # Nekobox PC mierus:// формат: mierus://user:pass@host:PORT?transport=PROTO&mtu=1400
            nekobox_mierus_link = f"mierus://{urllib.parse.quote(uname)}:{urllib.parse.quote(pwd)}@{host}:{port_start}?transport={protocol.upper()}&mtu=1400#{email}%20Mieru"
            links.append(nekobox_mierus_link)
            break

    return links


def generate_base64_sub(state: dict, uuid_str: str, email: str) -> str:
    """Генерация Base64-подписки для ПК: все ссылки через \n, затем base64."""
    links: list[str] = []

    # VLESS
    links.extend(generate_vless_links(state, uuid_str, email))

    # NaiveProxy (PC)
    naive_link = generate_naive_link(state, email)
    if naive_link:
        links.append(naive_link)

    # Hysteria2
    h2_link = generate_hysteria2_link(state, email)
    if h2_link:
        links.append(h2_link)

    # Mieru (PC)
    mieru_links = generate_mieru_link(state, email)
    links.extend(mieru_links)

    # AmneziaWG (sn://awg)
    awg_username = email.split('@')[0] if '@' in email else email
    awg_conf = get_awg_client_config(awg_username)
    if awg_conf:
        awg_link = generate_awg_sn_link(awg_conf, profile_name=f'{awg_username} AWG')
        links.append(awg_link)

    raw = "\n".join(links) + "\n"
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")
