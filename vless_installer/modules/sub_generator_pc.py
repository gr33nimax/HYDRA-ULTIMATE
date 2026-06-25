"""
vless_installer/modules/sub_generator_pc.py
───────────────────────────────────────────────────────────────────────────────
Генерация подписочных конфигов для ПК (NekoBox PC / NyameBox).

Отличия от универсального sub_generator.py:
  • naive+https:// ссылка без лишних параметров:
    naive+https://user:pass@host:port/#email
  • amneziawg ссылка в формате wg:// с параметрами обфускации и ключами:
    wg://host:port?private_key=...&local_address=...&enable_amnezia=true...
  • Только naive и amneziawg протоколы включены в подписку.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import urllib.parse
from typing import Optional

from vless_installer.modules.sub_generator import (
    _get_server_ip,
    _load_naiveproxy_state,
    get_awg_client_config,
    _parse_awg_conf,
    _get_awg_val
)


def generate_naive_link(state: dict, email: str) -> Optional[str]:
    """Генерация naive+https:// URI, оптимизированного для ПК (NekoBox)."""
    naive = _load_naiveproxy_state()
    if not naive.get("installed"):
        return None

    host = naive.get("domain", "") or state.get("domain", "") or _get_server_ip()
    port = naive.get("port", 443)

    for u in naive.get("users", []):
        if u.get("username", "") == email:
            user = urllib.parse.quote(u["username"])
            pwd = urllib.parse.quote(u["password"])
            tag = urllib.parse.quote(email)
            # Формат: naive+https://test:DKXaTsgde8QVwjEd@node.gr33nimax.mr2faced.ru:443/#test
            return f"naive+https://{user}:{pwd}@{host}:{port}/#{tag}"

    return None


def generate_awg_link(state: dict, email: str) -> Optional[str]:
    """Генерация wg:// URI для AmneziaWG на ПК (NekoBox)."""
    import re
    awg_username = re.sub(r'[^a-zA-Z0-9_-]', '', email)
    awg_conf = get_awg_client_config(awg_username)
    if not awg_conf:
        return None

    cfg = _parse_awg_conf(awg_conf)
    iface = cfg.get('interface', {})
    peer  = cfg.get('peer', {})

    # Endpoint: 'host:port'
    endpoint = _get_awg_val(peer, 'Endpoint', '127.0.0.1:51820')
    if ':' not in endpoint:
        endpoint = f"{endpoint}:51820"

    client_addr    = _get_awg_val(iface, 'Address', '')
    private_key    = _get_awg_val(iface, 'PrivateKey', '')
    server_pubkey  = _get_awg_val(peer, 'PublicKey', '')
    preshared_key  = _get_awg_val(peer, 'PresharedKey', '')

    # Параметры обфускации AmneziaWG
    jc   = _get_awg_val(iface, 'Jc',   '4')
    jmin = _get_awg_val(iface, 'Jmin', '40')
    jmax = _get_awg_val(iface, 'Jmax', '70')
    s1   = _get_awg_val(iface, 'S1',   '0')
    s2   = _get_awg_val(iface, 'S2',   '0')
    s3   = _get_awg_val(iface, 'S3',   '0')
    s4   = _get_awg_val(iface, 'S4',   '0')
    
    h1   = _get_awg_val(iface, 'H1', '0')
    h2   = _get_awg_val(iface, 'H2', '0')
    h3   = _get_awg_val(iface, 'H3', '0')
    h4   = _get_awg_val(iface, 'H4', '0')

    persistent_keepalive = _get_awg_val(peer, 'PersistentKeepalive', '25')

    # Кодирование ключей (сохраняем + и / как в Nekobox/Go)
    q_private_key = urllib.parse.quote(private_key, safe='+/')
    q_public_key = urllib.parse.quote(server_pubkey, safe='+/')
    q_preshared_key = urllib.parse.quote(preshared_key, safe='+/') if preshared_key else ''

    # Формируем query параметры строго в нужном порядке или как словарь
    params = [
        f"private_key={q_private_key}",
        f"local_address={client_addr}",
        "enable_amnezia=true",
        f"jc={jc}",
        f"jmin={jmin}",
        f"jmax={jmax}",
        f"s1={s1}",
        f"s2={s2}",
        f"s3={s3}",
        f"s4={s4}",
        f"h1={h1}",
        f"h2={h2}",
        f"h3={h3}",
        f"h4={h4}",
        f"public_key={q_public_key}"
    ]

    if q_preshared_key:
        params.append(f"pre_shared_key={q_preshared_key}")

    params.append(f"persistent_keepalive_interval={persistent_keepalive}")

    query_string = "&".join(params)
    tag = urllib.parse.quote(f"{email} AWG")

    return f"wg://{endpoint}?{query_string}#{tag}"


def generate_base64_sub(state: dict, uuid_str: str, email: str) -> str:
    """Генерация Base64-подписки для ПК: Naive и AmneziaWG."""
    links: list[str] = []

    # NaiveProxy (PC)
    naive_link = generate_naive_link(state, email)
    if naive_link:
        links.append(naive_link)

    # AmneziaWG (PC)
    awg_link = generate_awg_link(state, email)
    if awg_link:
        links.append(awg_link)

    raw = "\n".join(links) + "\n" if links else ""
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")
