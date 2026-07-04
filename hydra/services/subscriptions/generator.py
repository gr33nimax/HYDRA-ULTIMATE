"""
hydra/services/subscriptions/generator.py — Генератор подписок v2.

Форматы:
  • Base64 (для v2rayNG, Shadowrocket, Hiddify)
  • Sing-Box JSON (для NekoBox, Karing)
  • NekoBox sn:// ссылки для NaiveProxy, AnyTLS, TrustTunnel, Mieru, AmneziaWG

Динамически собирает ссылки/конфиги со всех включённых TRANSPORT-плагинов
через их v2-методы client_link() и generate_client_config().
"""
from __future__ import annotations

import base64
import json
import re
import socket
import struct
import zlib
import urllib.parse
from pathlib import Path
from typing import Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

from hydra.core.state import AppState, User
from hydra.plugins.base import PluginCategory
from hydra.plugins.registry import enabled, get

# ── SagerNet / NekoBox Сериализация ───────────────────────────────────────────

def _awg_serialize_string(s: str) -> bytes:
    """Сериализация строки в формат NekoBox: последний байт с установленным старшим битом."""
    if not s:
        return b'\x80'
    b = s.encode('utf-8')
    return b[:-1] + bytes([b[-1] | 0x80])


def _awg_serialize_len(length: int) -> bytes:
    val = length + 1
    out = bytearray()
    first = True
    while True:
        towrite = val & 0x3f
        val >>= 6
        if val > 0:
            byte_val = 0x40 | towrite
        else:
            byte_val = towrite
        
        if first:
            byte_val |= 0x80
            first = False
            
        out.append(byte_val)
        if val == 0:
            break
    return bytes(out)


def _awg_serialize_string_len(s: str) -> bytes:
    return _awg_serialize_len(len(s)) + s.encode('utf-8')


def serialize_naive(server: str, port: int, network: str, username: str, password: str, sni: str, fingerprint: str, name: str) -> str:
    data = struct.pack('<I', 3)  # Type 3
    data += _awg_serialize_string(server)
    data += struct.pack('<I', port)
    data += _awg_serialize_string(network)
    data += _awg_serialize_string(username)
    data += _awg_serialize_string(password)
    data += b'\x81\x81'  # tls=True, insecure=True
    data += _awg_serialize_string(sni)
    data += b'\x00' if not fingerprint else _awg_serialize_string(fingerprint)
    data += b'\x00'  # alpn count = 0
    data += b'\x00\x00\x00'  # mux=False, padding=False, strict_padding=False
    data += struct.pack('<I', 1)
    data += _awg_serialize_string(name)
    data += b'\x81\x81'
    compressed = zlib.compress(data, 7)
    return 'sn://naive?' + base64.urlsafe_b64encode(compressed).decode('ascii').rstrip('=')


def serialize_anytls(server: str, port: int, password: str, sni: str, fingerprint: str, name: str) -> str:
    data = struct.pack('<I', 1)  # Type 1
    data += _awg_serialize_string(server)
    data += struct.pack('<I', port)
    data += _awg_serialize_string_len(password)
    data += _awg_serialize_string(sni)
    data += b'\x81\x81'  # tls=True, insecure=True
    data += _awg_serialize_string(fingerprint)
    data += b'\x00'  # alpn count = 0
    data += b'\x81\x81\x81'  # mux=True, padding=True, strict_padding=True
    data += struct.pack('<I', 1)
    data += _awg_serialize_string(name)
    data += b'\x81\x81'
    compressed = zlib.compress(data, 7)
    return 'sn://anytls?' + base64.urlsafe_b64encode(compressed).decode('ascii').rstrip('=')


def serialize_trusttunnel(server: str, port: int, username: str, password: str, sni: str, name: str) -> str:
    data = struct.pack('<I', 4)  # Type 4
    data += _awg_serialize_string(server)
    data += struct.pack('<I', port)
    data += _awg_serialize_string(username)
    data += _awg_serialize_string_len(password)
    data += b'\x00\x00\x00\x00\x00'  # empty connection properties
    data += _awg_serialize_string("bbr")
    data += _awg_serialize_string(sni)
    data += b'\x81\x81\x81'  # tls=True, insecure=True, udp=True
    data += _awg_serialize_string("firefox")
    data += b'\x00\x00'
    data += _awg_serialize_string("0s")
    data += b'\x00\x00'
    data += b'\x81\x81\x81\x81\x81\x81\x81'
    data += struct.pack('<I', 1)
    data += _awg_serialize_string(name)
    data += b'\x81\x81'
    compressed = zlib.compress(data, 7)
    return 'sn://trusttunnel?' + base64.urlsafe_b64encode(compressed).decode('ascii').rstrip('=')


def _get_awg_val(d: dict, key: str, default: str = '') -> str:
    k_lower = key.lower()
    for k, v in d.items():
        if k.lower() == k_lower:
            return v
    return default


def _parse_awg_conf(conf_text: str) -> dict:
    result = {'interface': {}, 'peer': {}}
    section = None
    for line in conf_text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.lower() == '[interface]':
            section = 'interface'
        elif line.lower() == '[peer]':
            section = 'peer'
        elif '=' in line and section:
            k, _, v = line.partition('=')
            result[section][k.strip()] = v.strip()
    return result


def generate_awg_sn_link(conf_text: str, profile_name: str = 'AmneziaWG') -> Optional[str]:
    try:
        cfg = _parse_awg_conf(conf_text)
        iface = cfg['interface']
        peer  = cfg['peer']

        endpoint = _get_awg_val(peer, 'Endpoint', '127.0.0.1:51820')
        if ':' in endpoint:
            server_host, server_port_s = endpoint.rsplit(':', 1)
            server_port = int(server_port_s)
        else:
            server_host = endpoint
            server_port = 51820

        client_addr = _get_awg_val(iface, 'Address', '10.8.0.2/32')
        private_key = _get_awg_val(iface, 'PrivateKey', '')
        server_pubkey = _get_awg_val(peer, 'PublicKey', '')
        preshared_key = _get_awg_val(peer, 'PresharedKey', '')

        def _parse_int(val_s: str, default: int) -> int:
            val_s = val_s.strip()
            if not val_s:
                return default
            try:
                return int(val_s)
            except ValueError:
                return default

        jc   = _parse_int(_get_awg_val(iface, 'Jc',   '4'), 4)
        jmin = _parse_int(_get_awg_val(iface, 'Jmin', '40'), 40)
        jmax = _parse_int(_get_awg_val(iface, 'Jmax', '70'), 70)
        s1   = _parse_int(_get_awg_val(iface, 'S1',   '0'), 0)
        s2   = _parse_int(_get_awg_val(iface, 'S2',   '0'), 0)
        s3   = _parse_int(_get_awg_val(iface, 'S3',   '0'), 0)
        s4   = _parse_int(_get_awg_val(iface, 'S4',   '0'), 0)
        
        h1   = _get_awg_val(iface, 'H1', '0')
        h2   = _get_awg_val(iface, 'H2', '0')
        h3   = _get_awg_val(iface, 'H3', '0')
        h4   = _get_awg_val(iface, 'H4', '0')
        i1   = _get_awg_val(iface, 'I1', '')

        persistent_keepalive = _parse_int(_get_awg_val(peer, 'PersistentKeepalive', '25'), 25)
        mtu = _parse_int(_get_awg_val(iface, 'MTU', '1280'), 1280)

        def _u32(v: int) -> bytes:
            return struct.pack('<I', v)

        data = (
            _u32(2)                                   +  # Type 2 (AWG)
            _awg_serialize_string(server_host)         +
            _u32(server_port)                          +
            _awg_serialize_string(client_addr)         +
            _awg_serialize_string_len(private_key)     +
            _awg_serialize_string_len(server_pubkey)   +
            _awg_serialize_string_len(preshared_key)   +
            _u32(persistent_keepalive)                 +
            _u32(mtu)                                  +
            _awg_serialize_string_len('')              +  # client pubkey
            _u32(jc)                                   +
            _u32(jmin)                                 +
            _u32(jmax)                                 +
            _u32(s1)                                   +
            _u32(s2)                                   +
            _awg_serialize_string(h1)                  +
            _awg_serialize_string(h2)                  +
            _u32(s3)                                   +
            _u32(s4)                                   +
            _awg_serialize_string(h3)                  +
            _awg_serialize_string(h4)                  +
            _awg_serialize_string_len(i1)              +
            b'\x81\x81\x81\x81'                       +  # boolean flags
            _u32(1)                                    +  # PersistentKeepalive enabled
            _awg_serialize_string(profile_name)        +
            b'\x81\x81'
        )

        compressed = zlib.compress(data, level=7)
        return 'sn://awg?' + base64.urlsafe_b64encode(compressed).rstrip(b'=').decode('ascii')
    except Exception:
        return None


def generate_mieru_nekobox_link(host: str, port: int, protocol: str, username: str, password: str, tag: str) -> str:
    header = b'\x00\x00\x00\x00' # Type 0 (Mieru)
    s_host = _awg_serialize_string(host)
    s_port = struct.pack('<I', port)
    s_proto = _awg_serialize_string(protocol.upper())
    s_user = _awg_serialize_string(username)
    s_pass = _awg_serialize_string_len(password)
    s_val = struct.pack('<I', 1)
    s_tag = _awg_serialize_string(tag)
    booleans = b'\x81\x81'

    data = header + s_host + s_port + s_proto + s_user + s_pass + s_val + s_tag + booleans
    compressed = zlib.compress(data, 7)
    return "sn://mieru?" + base64.urlsafe_b64encode(compressed).decode('utf-8').rstrip('=')

# ── Разбор URL в sn:// ────────────────────────────────────────────────────────

def clean_link_to_sn(link: str, user: User) -> Optional[str]:
    try:
        parsed = urllib.parse.urlparse(link)
        scheme = parsed.scheme
        fragment = urllib.parse.unquote(parsed.fragment) if parsed.fragment else user.email
        
        # 1. Naive (NekoBox supports naive+quic:// and naive+https:// natively)
        if scheme in ("naive", "naive+quic", "naive+https"):
            return None
            
        # 2. AnyTLS (NekoBox supports anytls:// natively)
        elif scheme == "anytls":
            return None
            
        # 3. TrustTunnel (NekoBox does NOT support tt:// natively, needs sn://trusttunnel)
        elif scheme in ("tt", "trusttunnel"):
            netloc = parsed.netloc
            if "@" not in netloc:
                return None
            creds, host_port = netloc.split("@", 1)
            username, password = urllib.parse.unquote(creds).split(":", 1) if ":" in creds else (urllib.parse.unquote(creds), "")
            host, port_s = host_port.split(":", 1) if ":" in host_port else (host_port, "443")
            port = int(port_s)
            
            query = urllib.parse.parse_qs(parsed.query)
            sni = query.get("sni", [host])[0]
            
            return serialize_trusttunnel(host, port, username, password, sni, fragment)
            
        # 4. Mieru (NekoBox requires sn://mieru via its plugin)
        # Ручной парсинг из-за возможного наличия '/' в незакодированном base64-пароле
        elif scheme == "mierus":
            without_frag, _, frag_str = link.partition("#")
            without_scheme = without_frag[len("mierus://"):]
            without_query, _, query_str = without_scheme.partition("?")
            creds, _, host = without_query.rpartition("@")
            username, _, password = creds.partition(":")
            
            username = urllib.parse.unquote(username)
            password = urllib.parse.unquote(password)
            
            if ":" in host:
                host, _ = host.split(":", 1)
                
            query = urllib.parse.parse_qs(query_str)
            port = int(query.get("port", [8964])[0])
            protocol = query.get("protocol", ["TCP"])[0]
            
            fragment = urllib.parse.unquote(frag_str) if frag_str else user.email
            
            return generate_mieru_nekobox_link(host, port, protocol, username, password, fragment)
            
    except Exception:
        pass
    return None

# ── Генерация подписок ───────────────────────────────────────────────────────

def generate_links(user: User, state: AppState) -> list[str]:
    """Собирает ссылки со всех включённых TRANSPORT-плагинов."""
    links: list[str] = []
    for p in enabled(state, PluginCategory.TRANSPORT):
        try:
            link = p.client_link(user, state)
            if link:
                links.append(link)
        except Exception:
            pass
    return links


def generate_base64_sub(user: User, state: AppState) -> str:
    """Base64-кодированные ссылки (включая sn:// форматы для NekoBox)."""
    links = generate_links(user, state)
    extended_links: list[str] = []
    
    # Сначала преобразуем стандартные ссылки, добавляя красивый суффикс протокола в тэг
    formatted_links = []
    for link in links:
        try:
            parsed = urllib.parse.urlparse(link)
            scheme = parsed.scheme.lower()
            
            proto_suffix = ""
            if scheme in ("naive", "naive+quic", "naive+https"):
                proto_suffix = "NaiveProxy"
            elif scheme == "anytls":
                proto_suffix = "AnyTLS"
            elif scheme in ("tt", "trusttunnel"):
                proto_suffix = "TrustTunnel"
            elif scheme == "mierus":
                proto_suffix = "Mieru"
                
            if proto_suffix:
                # Обновляем фрагмент (тэг) ссылки
                tag = f"{user.email} {proto_suffix}"
                parsed = parsed._replace(fragment=urllib.parse.quote(tag))
                link = urllib.parse.urlunparse(parsed)
        except Exception:
            pass
        formatted_links.append(link)
        
    # Добавляем стандартные ссылки
    extended_links.extend(formatted_links)
    
    # Конвертируем стандартные в sn:// где применимо
    for link in formatted_links:
        sn_link = clean_link_to_sn(link, user)
        if sn_link:
            extended_links.append(sn_link)
            
    # Особый случай для AmneziaWG: нужен контент .conf файла для генерации sn://awg
    awg_plugin = get("amneziawg")
    if awg_plugin and awg_plugin.status().enabled:
        try:
            conf_text = awg_plugin.generate_client_config(user, state)
            if conf_text:
                awg_sn = generate_awg_sn_link(conf_text, f"{user.email} AWG")
                if awg_sn:
                    extended_links.append(awg_sn)
        except Exception:
            pass
            
    payload = "\n".join(extended_links) + "\n"
    return base64.b64encode(payload.encode("utf-8")).decode("utf-8")


def generate_userinfo_header(user: User, state: AppState) -> str:
    """Генерация заголовка Subscription-Userinfo с трафиком и окончанием подписки."""
    upload = 0
    download = user.traffic_used_bytes
    total = int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0
    expire = 0
    if user.expiry_date:
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(user.expiry_date)
            expire = int(dt.timestamp())
        except Exception:
            pass
    return f"upload={upload}; download={download}; total={total}; expire={expire}"


def get_subscription_url(user: User, state: AppState) -> str:
    """Возвращает ссылку на подписку (учитывая sub_domain для скрытия порта)."""
    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        return f"https://{sub_domain}/sub/{user.uuid}"
    
    from hydra.utils.net import public_ip
    host = state.network.domain or state.network.server_ip or public_ip()
    return f"https://{host}:9443/sub/{user.uuid}"

# ── SSL и Сертификаты ─────────────────────────────────────────────────────────

def find_any_cert(state: AppState) -> tuple[Optional[str], Optional[str]]:
    """Поиск существующего TLS-сертификата в системе."""
    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        # Если задан выделенный домен для подписок, ищем сертификат СТРОГО для него
        paths = [
            (f"/etc/letsencrypt/live/{sub_domain}/fullchain.pem", f"/etc/letsencrypt/live/{sub_domain}/privkey.pem"),
            (f"/etc/xray/{sub_domain}.crt", f"/etc/xray/{sub_domain}.key"),
        ]
        for cert, key in paths:
            if Path(cert).exists() and Path(key).exists():
                return cert, key
        return None, None

    # Иначе ищем сертификат основного домена или другие
    domains = []
    if state.network.domain:
        domains.append(state.network.domain)
        
    for name, ps in state.protocols.items():
        if ps.config and "domain" in ps.config:
            d = ps.config["domain"]
            if d and d not in domains:
                domains.append(d)
                
    for domain in domains:
        paths = [
            (f"/etc/letsencrypt/live/{domain}/fullchain.pem", f"/etc/letsencrypt/live/{domain}/privkey.pem"),
            (f"/etc/xray/{domain}.crt", f"/etc/xray/{domain}.key"),
        ]
        for cert, key in paths:
            if Path(cert).exists() and Path(key).exists():
                return cert, key
                
    fallback = ("/etc/xray/xray.crt", "/etc/xray/xray.key")
    if Path(fallback[0]).exists() and Path(fallback[1]).exists():
        return fallback
        
    return None, None


def is_user_valid(user: User, state: AppState) -> bool:
    """Проверяет лимиты трафика и времени пользователя в реальном времени."""
    if user.blocked:
        return False
        
    # Проверка даты окончания
    if user.expiry_date:
        try:
            from datetime import datetime, timezone
            expiry = datetime.fromisoformat(user.expiry_date)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry < datetime.now(timezone.utc):
                return False
        except Exception:
            pass
            
    # Проверка лимита трафика
    if user.traffic_limit_gb:
        limit_bytes = int(user.traffic_limit_gb * 1073741824)
        if user.traffic_used_bytes >= limit_bytes:
            return False
            
    return True


# ── HTTP Server ───────────────────────────────────────────────────────────────

class SubscriptionHandler(BaseHTTPRequestHandler):
    state: AppState = None

    def log_message(self, format, *args):
        pass

    def finish(self) -> None:
        try:
            if hasattr(self.request, "unwrap"):
                self.request.settimeout(1.0)
                self.request.unwrap()
        except Exception:
            pass
        try:
            super().finish()
        except Exception:
            pass

    def _send_error(self, code: int, message: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(message.encode("utf-8"))

    def do_GET(self):
        path = self.path
        if "?" in path:
            path = path.split("?")[0]
        path = path.strip("/")
        parts = path.split("/")
        
        token = None
        if len(parts) >= 2 and parts[0] == "sub":
            token = parts[1]
        else:
            # Fallback для query-параметра ?token=...
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            token = params.get("token", [None])[0]
            
        if not self.state:
            self._send_error(500, "Server not configured")
            return
            
        if not token:
            self._send_error(404, "Not found")
            return
            
        user = None
        for u in self.state.users:
            if u.uuid == token:
                # Динамически проверяем лимиты и статус
                if is_user_valid(u, self.state):
                    user = u
                break
                
        if not user:
            self._send_error(403, "Invalid, expired or blocked token")
            return
            
        content = generate_base64_sub(user, self.state)
        userinfo = generate_userinfo_header(user, self.state)
        
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="hydra-{user.email}-sub.txt"')
        self.send_header("Subscription-Userinfo", userinfo)
        self.send_header("Profile-Update-Interval", "6")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))


def run_standalone(host: str = "0.0.0.0", port: int = 9443):
    """Синхронный запуск сервера с TLS."""
    from hydra.core.state import load_state
    state = load_state()
    SubscriptionHandler.state = state
    
    try:
        server = HTTPServer((host, port), SubscriptionHandler)
    except OSError as e:
        print(f"Failed to bind subscription server to {host}:{port}: {e}")
        return
        
    cert_file, key_file = find_any_cert(state)
    if not cert_file or not key_file:
        print("ERROR: SSL certificates not found! Subscription server requires HTTPS/TLS.")
        return
        
    try:
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(f"SSL/HTTPS enabled using cert: {cert_file}")
    except Exception as e:
        print(f"Failed to wrap socket with SSL: {e}")
        return
        
    print(f"Starting subscription server on https://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Server stopped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HYDRA Subscription Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    args = parser.parse_args()
    
    run_standalone(args.host, args.port)
