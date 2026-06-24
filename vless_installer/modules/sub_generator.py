"""
vless_installer/modules/sub_generator.py
───────────────────────────────────────────────────────────────────────────────
Генерация подписочных конфигов для пользователей.

Форматы:
  • Base64 — универсальный (v2rayNG, Shadowrocket, Hiddify)
  • Clash Meta YAML — для Mihomo / Clash Verge / Nyanpasu
  • Sing-box JSON — для sing-box / NekoBox (NaiveProxy и Mieru как outbounds)

Точка входа из sub_server.py:
    from vless_installer.modules.sub_generator import (
        generate_base64_sub, generate_clash_yaml, generate_singbox_json,
        generate_userinfo_header
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import json
import socket
import struct
import subprocess
import zlib
import urllib.parse
from pathlib import Path
from typing import Optional

STATE_FILE = Path("/var/lib/xray-installer/state.json")
XRAY_CONFIG = Path("/var/lib/xray-installer/config.json")


# ── Вспомогательные ──────────────────────────────────────────────────────────

def _get_server_ip() -> str:
    """Получить публичный IPv4-адрес сервера."""
    for cmd in (
        ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
        ["curl", "-s", "-4", "--max-time", "5", "https://ifconfig.me"],
        ["hostname", "-I"],
    ):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            ip = r.stdout.strip().split()[0] if r.stdout.strip() else ""
            if ip and not ip.startswith("127.") and not ip.startswith("::"):
                return ip
        except Exception:
            continue
    return "0.0.0.0"


def _load_state() -> dict:
    """Загрузить state.json."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _load_xray_config() -> dict:
    return {}


def _load_naiveproxy_state() -> dict:
    """Загрузить naiveproxy.json."""
    p = Path("/var/lib/xray-installer/naiveproxy.json")
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _load_mieru_state() -> dict:
    """Загрузить mieru.json."""
    p = Path("/var/lib/xray-installer/mieru.json")
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _find_user_uuid(email: str) -> Optional[str]:
    return None


# ── Генерация VLESS-ссылок ───────────────────────────────────────────────────

def generate_vless_links(state: dict, uuid_str: str, email: str) -> list[str]:
    return []


# ── AmneziaWG: чтение конфига из Docker и генерация sn://awg ─────────────────

def _awg_serialize_string(s: str) -> bytes:
    """Сериализация строки в формат NekoBox: последний байт с установленным старшим битом."""
    if not s:
        return b'\x80'
    b = s.encode('utf-8')
    return b[:-1] + bytes([b[-1] | 0x80])


def _parse_awg_conf(conf_text: str) -> dict:
    """Парсинг .conf файла AmneziaWG в словарь."""
    result = {'interface': {}, 'peer': {}}
    section = None
    for line in conf_text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line == '[Interface]':
            section = 'interface'
        elif line == '[Peer]':
            section = 'peer'
        elif '=' in line and section:
            k, _, v = line.partition('=')
            result[section][k.strip()] = v.strip()
    return result


def _detect_awg_container() -> str:
    """Определяет имя Docker-контейнера AmneziaWG."""
    try:
        r = subprocess.run(
            ['docker', 'ps', '-a', '--format', '{{.Names}}'],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            names = [n.strip() for n in r.stdout.splitlines() if n.strip()]
            for n in ('amnezia-awg2', 'amnezia-awg', 'amnezia-wg'):
                if n in names:
                    return n
    except Exception:
        pass
    return 'amnezia-awg2'


def get_awg_client_config(username: str) -> Optional[str]:
    """
    Читает клиентский .conf файл из контейнера AmneziaWG.
    Возвращает текст конфига или None если не найден.
    """
    container = _detect_awg_container()
    conf_path = f'/opt/amnezia/awg/client_{username}.conf'
    try:
        r = subprocess.run(
            ['docker', 'exec', container, 'cat', conf_path],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return None


def generate_awg_sn_link(conf_text: str, profile_name: str = 'AmneziaWG') -> str:
    """
    Генерирует sn://awg?<data> ссылку для NekoBox/SFA из текста .conf файла AmneziaWG.

    Формат бинарной структуры (little-endian, zlib+base64url):
      [u32: 2]                  тип = AmneziaWG
      [str: server]             хост сервера (endpoint без порта)
      [u32: port]               UDP-порт
      [str: client_addr]        IP клиента (e.g. 10.8.1.3/32)
      [str: private_key]        приватный ключ клиента
      [str: server_public_key]  публичный ключ сервера (из [Peer])
      [str: preshared_key]      PSK (пустая строка если нет)
      [str: client_public_key]  публичный ключ клиента (пустой — не вычислить без awg)
      [u32: Jc][u32: Jmin][u32: Jmax][u32: S1][u32: S2]
      [str: H1][str: H2]
      [u32: S3][u32: S4]
      [str: H3][str: H4]
      [bytes: b'\x81\x81\x81\x81']  4 boolean-флага = true
      [u32: 1]                  PersistentKeepalive enabled
      [str: profile_name]       имя профиля
      [bytes: b'\x81\x81']      trailing booleans
    """
    cfg = _parse_awg_conf(conf_text)
    iface = cfg['interface']
    peer  = cfg['peer']

    # Endpoint: 'host:port'
    endpoint = peer.get('Endpoint', '127.0.0.1:51820')
    if ':' in endpoint:
        server_host, server_port_s = endpoint.rsplit(':', 1)
        server_port = int(server_port_s)
    else:
        server_host = endpoint
        server_port = 51820

    client_addr    = iface.get('Address', '10.8.0.2/32')
    private_key    = iface.get('PrivateKey', '')
    server_pubkey  = peer.get('PublicKey', '')
    preshared_key  = peer.get('PresharedKey', '')

    # Параметры обфускации AmneziaWG
    jc   = int(iface.get('Jc',   4))
    jmin = int(iface.get('Jmin', 40))
    jmax = int(iface.get('Jmax', 70))
    s1   = int(iface.get('S1',   0))
    s2   = int(iface.get('S2',   0))
    s3   = int(iface.get('S3',   0))
    s4   = int(iface.get('S4',   0))
    h1   = iface.get('H1', '0')
    h2   = iface.get('H2', '0')
    h3   = iface.get('H3', '0')
    h4   = iface.get('H4', '0')

    def _u32(v: int) -> bytes:
        return struct.pack('<I', v)

    data = (
        _u32(2)                              +  # тип AmneziaWG
        _awg_serialize_string(server_host)   +
        _u32(server_port)                    +
        _awg_serialize_string(client_addr)   +
        _awg_serialize_string(private_key)   +
        _awg_serialize_string(server_pubkey) +
        _awg_serialize_string(preshared_key) +
        _awg_serialize_string('')            +  # client pubkey (недоступен без awg)
        _u32(jc)                             +
        _u32(jmin)                           +
        _u32(jmax)                           +
        _u32(s1)                             +
        _u32(s2)                             +
        _awg_serialize_string(h1)            +
        _awg_serialize_string(h2)            +
        _u32(s3)                             +
        _u32(s4)                             +
        _awg_serialize_string(h3)            +
        _awg_serialize_string(h4)            +
        b'\x81\x81\x81\x81'                +  # boolean flags
        _u32(1)                              +  # PersistentKeepalive enabled
        _awg_serialize_string(profile_name)  +
        b'\x81\x81'                           # trailing flags
    )

    compressed = zlib.compress(data, level=7)
    encoded = base64.urlsafe_b64encode(compressed).rstrip(b'=').decode('ascii')
    return f'sn://awg?{encoded}'



# ── Генерация NaiveProxy ─────────────────────────────────────────────────────

def generate_naive_link(state: dict, email: str) -> Optional[str]:
    """Генерация naive+https:// URI если NaiveProxy установлен."""
    naive = _load_naiveproxy_state()
    if not naive.get("installed"):
        return None

    host = naive.get("domain", "") or state.get("domain", "") or _get_server_ip()
    port = naive.get("port", 8443)

    # Ищем пользователя строго по email
    for u in naive.get("users", []):
        if u.get("username", "") == email:
            user = urllib.parse.quote(u["username"])
            pwd = urllib.parse.quote(u["password"])
            return f"naive+https://{user}:{pwd}@{host}:{port}#{email}%20Naive"

    return None


# ── Генерация Hysteria2 ──────────────────────────────────────────────────────

def generate_hysteria2_link(state: dict, email: str) -> Optional[str]:
    """Генерация hy2:// URI если Hysteria2 установлен."""
    h2 = state.get("hysteria2", {})
    if not h2.get("installed"):
        return None

    host = state.get("domain", "") or _get_server_ip()
    port = h2.get("port", 443)
    password = h2.get("password", "")

    if password:
        return f"hy2://{password}@{host}:{port}#{email}%20Hysteria2"
    return None


# ── Генерация Mieru ──────────────────────────────────────────────────────────

def generate_mieru_nekobox_link(host: str, port: int, protocol: str, username: str, password: str, tag: str) -> str:
    import zlib
    import base64
    import struct

    def serialize_string(s: str) -> bytes:
        b = s.encode('utf-8')
        return b[:-1] + bytes([b[-1] | 0x80])

    header = b'\x00\x00\x00\x00'
    s_host = serialize_string(host)
    s_port = struct.pack('<I', port)
    s_proto = serialize_string(protocol.upper())
    s_user = serialize_string(username)
    s_pass = serialize_string(password)
    s_val = struct.pack('<I', 1)
    s_tag = serialize_string(tag)
    booleans = b'\x81\x81'

    data = header + s_host + s_port + s_proto + s_user + s_pass + s_val + s_tag + booleans
    compressed = zlib.compress(data, 7)
    encoded = base64.urlsafe_b64encode(compressed).decode('utf-8').rstrip('=')
    return f"sn://mieru?{encoded}"


def generate_mieru_link(state: dict, email: str) -> list[str]:
    """Генерация mieru линков для Nekobox и Karing."""
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
            # Nekobox sn://mieru формат
            neko_link = generate_mieru_nekobox_link(host, port_start, protocol, uname, pwd, f"{email}_Mieru")
            links.append(neko_link)
            # Karing формат
            karing_link = f"mierus://{urllib.parse.quote(uname)}:{urllib.parse.quote(pwd)}@{host}?port={port_start}&protocol={protocol.upper()}&profile=default&mtu=1400&multiplexing=MULTIPLEXING_HIGH#{email}%20Mieru%20Karing"
            links.append(karing_link)
            break

    return links


# ═════════════════════════════════════════════════════════════════════════════
#  ФОРМАТ 1: Base64
# ═════════════════════════════════════════════════════════════════════════════

def generate_base64_sub(state: dict, uuid_str: str, email: str) -> str:
    """Генерация Base64-подписки: все ссылки через \n, затем base64."""
    links: list[str] = []

    # VLESS
    links.extend(generate_vless_links(state, uuid_str, email))

    # NaiveProxy
    naive_link = generate_naive_link(state, email)
    if naive_link:
        links.append(naive_link)

    # Hysteria2
    h2_link = generate_hysteria2_link(state, email)
    if h2_link:
        links.append(h2_link)

    # Mieru
    mieru_links = generate_mieru_link(state, email)
    links.extend(mieru_links)

    # AmneziaWG — ищем конфиг по имени пользователя (email без домена)
    awg_username = email.split('@')[0] if '@' in email else email
    awg_conf = get_awg_client_config(awg_username)
    if awg_conf:
        awg_link = generate_awg_sn_link(awg_conf, profile_name=f'{awg_username} AWG')
        links.append(awg_link)

    raw = "\n".join(links) + "\n"
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")


# ═════════════════════════════════════════════════════════════════════════════
#  ФОРМАТ 2: Clash Meta YAML
# ═════════════════════════════════════════════════════════════════════════════

def _yaml_str(s: str) -> str:
    """Безопасное экранирование строки для YAML без зависимости от PyYAML."""
    if any(c in s for c in (':', '{', '}', '[', ']', ',', '&', '*', '?', '|',
                             '-', '<', '>', '=', '!', '%', '@', '#', '\n')):
        return f'"{s}"'
    return s


def generate_clash_yaml(state: dict, uuid_str: str, email: str) -> str:
    """Генерация Clash Meta YAML конфига."""
    proxies: list[str] = []
    proxy_names: list[str] = []

    server_ip = state.get("domain", "") or _get_server_ip()
    port = state.get("server_port", 443)
    fp = state.get("fingerprint", "chrome")
    protocol_mode = state.get("protocol_mode", "reality")

    # VLESS Reality and xHTTP removed

    # NaiveProxy
    naive = _load_naiveproxy_state()
    if naive.get("installed"):
        for u in naive.get("users", []):
            if u.get("username") == email:
                name = f"{email} Naive"
                proxy_names.append(name)
                host = naive.get("domain", "") or state.get("domain", "") or _get_server_ip()
                proxies.append(f"""  - name: {_yaml_str(name)}
    type: http
    server: {host}
    port: {naive.get('port', 8443)}
    username: {_yaml_str(u['username'])}
    password: {_yaml_str(u['password'])}
    tls: true
    skip-cert-verify: false""")
                break

    # Hysteria2
    h2 = state.get("hysteria2", {})
    if h2.get("installed") and h2.get("password"):
        name = f"{email} Hysteria2"
        proxy_names.append(name)
        host = state.get("domain", "") or _get_server_ip()
        proxies.append(f"""  - name: {_yaml_str(name)}
    type: hysteria2
    server: {host}
    port: {h2.get('port', 443)}
    password: {_yaml_str(h2['password'])}
    alpn:
      - h3""")

    # Сборка YAML
    names_str = ", ".join(f'"{n}"' for n in proxy_names)

    yaml = f"""# Clash Meta config — auto-generated
# User: {email}

mixed-port: 7890
allow-lan: false
mode: rule
log-level: info

proxies:
{chr(10).join(proxies)}

proxy-groups:
  - name: "Proxy"
    type: select
    proxies: [{names_str}]
  - name: "Auto"
    type: url-test
    proxies: [{names_str}]
    url: http://www.gstatic.com/generate_204
    interval: 300

rules:
  - GEOIP,private,DIRECT,no-resolve
  - MATCH,Proxy
"""
    return yaml


# ═════════════════════════════════════════════════════════════════════════════
#  ФОРМАТ 3: Sing-box JSON
# ═════════════════════════════════════════════════════════════════════════════

def generate_singbox_json(state: dict, uuid_str: str, email: str) -> str:
    """Генерация sing-box JSON конфига.
    NaiveProxy и Mieru включаются как outbound'ы для импорта в NekoBox."""
    outbounds: list[dict] = []
    tags: list[str] = []

    server_ip = state.get("domain", "") or _get_server_ip()
    port = state.get("server_port", 443)
    fp = state.get("fingerprint", "chrome")
    protocol_mode = state.get("protocol_mode", "reality")

    # VLESS Reality and xHTTP removed

    # NaiveProxy → sing-box naive outbound
    naive = _load_naiveproxy_state()
    if naive.get("installed"):
        for u in naive.get("users", []):
            if u.get("username") == email:
                tag = f"{email}-naive"
                tags.append(tag)
                host = naive.get("domain", "") or state.get("domain", "") or _get_server_ip()
                outbounds.append({
                    "type": "naive",
                    "tag": tag,
                    "server": host,
                    "server_port": naive.get("port", 8443),
                    "username": u["username"],
                    "password": u["password"],
                    "tls": {
                        "enabled": True,
                        "server_name": host,
                    },
                })
                break



    # Hysteria2
    h2 = state.get("hysteria2", {})
    if h2.get("installed") and h2.get("password"):
        tag = f"{email}-hysteria2"
        tags.append(tag)
        host = state.get("domain", "") or _get_server_ip()
        outbounds.append({
            "type": "hysteria2",
            "tag": tag,
            "server": host,
            "server_port": h2.get("port", 443),
            "password": h2["password"],
            "tls": {
                "enabled": True,
                "server_name": host,
                "alpn": ["h3"],
            },
        })

    # Selector + urltest outbounds
    outbounds.append({
        "type": "selector",
        "tag": "proxy",
        "outbounds": tags + ["auto", "direct"],
        "default": tags[0] if tags else "direct",
    })
    outbounds.append({
        "type": "urltest",
        "tag": "auto",
        "outbounds": tags,
        "url": "http://www.gstatic.com/generate_204",
        "interval": "5m",
    })
    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})
    outbounds.append({"type": "dns", "tag": "dns-out"})

    config = {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {"tag": "google", "address": "https://8.8.8.8/dns-query", "detour": "proxy"},
                {"tag": "local", "address": "local", "detour": "direct"},
            ],
            "rules": [
                {"outbound": ["any"], "server": "local"},
            ],
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "inet4_address": "172.19.0.1/30",
                "auto_route": True,
                "strict_route": True,
                "sniff": True,
            },
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"geoip": ["private"], "outbound": "direct"},
            ],
            "final": "proxy",
        },
    }

    return json.dumps(config, indent=2, ensure_ascii=False)


# ═════════════════════════════════════════════════════════════════════════════
#  Subscription-Userinfo заголовок
# ═════════════════════════════════════════════════════════════════════════════

def generate_userinfo_header(state: dict, email: str) -> str:
    """Генерация заголовка Subscription-Userinfo.
    Формат: upload=0; download=N; total=T; expire=E
    """
    # Базовые значения (расширяемо через state.json)
    upload = 0
    download = 0
    total = 0  # 0 = безлимит
    expire = 0  # 0 = бессрочно

    # Попытка получить реальные данные из state
    traffic = state.get("user_traffic", {}).get(email, {})
    if traffic:
        upload = traffic.get("upload", 0)
        download = traffic.get("download", 0)
        total = traffic.get("total", 0)
        expire = traffic.get("expire", 0)

    return f"upload={upload}; download={download}; total={total}; expire={expire}"
