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
import subprocess
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
    """Загрузить xray config.json."""
    if XRAY_CONFIG.exists():
        try:
            return json.loads(XRAY_CONFIG.read_text(encoding="utf-8"))
        except Exception:
            pass
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
    """Найти UUID пользователя по email в xray config."""
    cfg = _load_xray_config()
    for inb in cfg.get("inbounds", []):
        for cl in inb.get("settings", {}).get("clients", []):
            if cl.get("email", "") == email:
                return cl.get("id", "")
    return None


# ── Генерация VLESS-ссылок ───────────────────────────────────────────────────

def generate_vless_links(state: dict, uuid_str: str, email: str) -> list[str]:
    """Генерация VLESS URI на основе текущей конфигурации."""
    if not uuid_str:
        return []
    links = []
    server_ip = state.get("domain", "") or _get_server_ip()
    port = state.get("server_port", 443)
    fp = state.get("fingerprint", "chrome")
    label = urllib.parse.quote(email)

    protocol_mode = state.get("protocol_mode", "reality")

    # REALITY ссылка
    if protocol_mode in ("reality", "both", ""):
        pbk = state.get("public_key", "")
        sid = state.get("short_id", "")
        sni = state.get("reality_dest", "www.microsoft.com")
        if ":" in sni:
            sni = sni.split(":")[0]
        link = (
            f"vless://{uuid_str}@{server_ip}:{port}"
            f"?type=tcp&security=reality&pbk={pbk}"
            f"&fp={fp}&sni={sni}&sid={sid}"
            f"&flow=xtls-rprx-vision#{label}%20REALITY"
        )
        links.append(link)

    # xHTTP + TLS ссылка
    if protocol_mode in ("xhttp", "both"):
        domain = state.get("domain", "")
        xhttp_path = state.get("xhttp_path", "/")
        xhttp_mode = state.get("xhttp_mode", "streamup")
        if domain:
            path_enc = urllib.parse.quote(xhttp_path, safe="/")
            link = (
                f"vless://{uuid_str}@{domain}:{port}"
                f"?type=xhttp&security=tls&sni={domain}"
                f"&path={path_enc}&mode={xhttp_mode}"
                f"&fp={fp}#{label}%20xHTTP"
            )
            links.append(link)

    return links


# ── Генерация NaiveProxy ─────────────────────────────────────────────────────

def generate_naive_link(state: dict, email: str) -> Optional[str]:
    """Генерация naive+https:// URI если NaiveProxy установлен."""
    naive = _load_naiveproxy_state()
    if not naive.get("installed") or not naive.get("users"):
        return None

    host = naive.get("domain", "") or state.get("domain", "") or _get_server_ip()
    port = naive.get("port", 8443)

    # Ищем пользователя, с возможностью fallback на первого
    user_data = next((u for u in naive["users"] if u.get("username", "") == email), naive["users"][0])
    user = urllib.parse.quote(user_data["username"])
    pwd = urllib.parse.quote(user_data["password"])
    return f"naive+https://{user}:{pwd}@{host}:{port}#{email}%20Naive"


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
    if not mieru.get("installed") or not mieru.get("users"):
        return []

    host = state.get("domain", "") or _get_server_ip()
    port_start = mieru.get("port_start", 8964)
    protocol = mieru.get("protocol", "TCP")

    # Ищем пользователя, с возможностью fallback на первого
    user_data = next((u for u in mieru["users"] if u.get("username") == email), mieru["users"][0])
    uname = user_data["username"]
    pwd = user_data["password"]

    links = []
    # Nekobox sn://mieru формат
    neko_link = generate_mieru_nekobox_link(host, port_start, protocol, uname, pwd, f"{email}_Mieru")
    links.append(neko_link)
    # Karing формат
    karing_link = f"mierus://{urllib.parse.quote(uname)}:{urllib.parse.quote(pwd)}@{host}?port={port_start}&protocol={protocol.upper()}&profile=default&mtu=1400&multiplexing=MULTIPLEXING_HIGH#{email}%20Mieru%20Karing"
    links.append(karing_link)

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

    # VLESS REALITY
    if uuid_str and protocol_mode in ("reality", "both", ""):
        name = f"{email} REALITY"
        proxy_names.append(name)
        pbk = state.get("public_key", "")
        sid = state.get("short_id", "")
        sni = state.get("reality_dest", "www.microsoft.com")
        if ":" in sni:
            sni = sni.split(":")[0]
        proxies.append(f"""  - name: {_yaml_str(name)}
    type: vless
    server: {server_ip}
    port: {port}
    uuid: {uuid_str}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    client-fingerprint: {fp}
    servername: {sni}
    reality-opts:
      public-key: {pbk}
      short-id: {sid}""")

    # VLESS xHTTP
    if uuid_str and protocol_mode in ("xhttp", "both"):
        domain = state.get("domain", "")
        if domain:
            name = f"{email} xHTTP"
            proxy_names.append(name)
            xhttp_path = state.get("xhttp_path", "/")
            proxies.append(f"""  - name: {_yaml_str(name)}
    type: vless
    server: {domain}
    port: {port}
    uuid: {uuid_str}
    network: xhttp
    udp: true
    tls: true
    client-fingerprint: {fp}
    servername: {domain}
    xhttp-opts:
      path: {xhttp_path}""")

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

    # VLESS REALITY
    if uuid_str and protocol_mode in ("reality", "both", ""):
        tag = f"{email}-reality"
        tags.append(tag)
        pbk = state.get("public_key", "")
        sid = state.get("short_id", "")
        sni = state.get("reality_dest", "www.microsoft.com")
        if ":" in sni:
            sni = sni.split(":")[0]
        outbounds.append({
            "type": "vless",
            "tag": tag,
            "server": server_ip,
            "server_port": port,
            "uuid": uuid_str,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": sni,
                "utls": {"enabled": True, "fingerprint": fp},
                "reality": {
                    "enabled": True,
                    "public_key": pbk,
                    "short_id": sid,
                },
            },
        })

    # VLESS xHTTP
    if uuid_str and protocol_mode in ("xhttp", "both"):
        domain = state.get("domain", "")
        if domain:
            tag = f"{email}-xhttp"
            tags.append(tag)
            xhttp_path = state.get("xhttp_path", "/")
            outbounds.append({
                "type": "vless",
                "tag": tag,
                "server": domain,
                "server_port": port,
                "uuid": uuid_str,
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": fp},
                },
                "transport": {
                    "type": "httpupgrade",
                    "path": xhttp_path,
                },
            })

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
