"""NekoBox/SagerNet link serialization helpers."""
from __future__ import annotations

import base64
import struct
import urllib.parse
import zlib

from hydra.core.state_models import User


def _serialize_string(value: str) -> bytes:
    if not value:
        return b"\x80"
    encoded = value.encode()
    return encoded[:-1] + bytes([encoded[-1] | 0x80])


def _serialize_len(length: int) -> bytes:
    value = length + 1
    result = bytearray()
    first = True
    while True:
        part = value & 0x3F
        value >>= 6
        byte_value = (0x40 | part) if value > 0 else part
        if first:
            byte_value |= 0x80
            first = False
        result.append(byte_value)
        if value == 0:
            return bytes(result)


def _serialize_string_len(value: str) -> bytes:
    return _serialize_len(len(value)) + value.encode()


def serialize_nekobox_config(config: str, name: str) -> str:
    """Serialize a full sing-box config as NekoBox's ConfigBean link."""
    data = struct.pack("<I", 0)
    data += _serialize_string("127.0.0.1")
    data += struct.pack("<I", 1080)
    data += struct.pack("<I", 0)
    data += _serialize_string_len(config)
    data += struct.pack("<I", 1)
    data += _serialize_string(name)
    data += b"\x81\x81"
    encoded = base64.urlsafe_b64encode(zlib.compress(data, 9))
    return f"sn://config?{encoded.decode('ascii').rstrip('=')}"


def serialize_naive(
    server: str,
    port: int,
    network: str,
    username: str,
    password: str,
    sni: str,
    fingerprint: str,
    name: str,
) -> str:
    data = struct.pack("<I", 3)
    data += _serialize_string(server)
    data += struct.pack("<I", port)
    data += _serialize_string(network)
    data += _serialize_string(username)
    data += _serialize_string(password)
    data += b"\x81\x81"
    data += _serialize_string(sni)
    data += b"\x00" if not fingerprint else _serialize_string(fingerprint)
    data += b"\x00"
    data += b"\x00\x00\x00"
    data += struct.pack("<I", 1)
    data += _serialize_string(name)
    data += b"\x81\x81"
    encoded = base64.urlsafe_b64encode(zlib.compress(data, 7))
    return "sn://naive?" + encoded.decode("ascii").rstrip("=")


def serialize_anytls(
    server: str,
    port: int,
    password: str,
    sni: str,
    fingerprint: str,
    name: str,
) -> str:
    data = struct.pack("<I", 1)
    data += _serialize_string(server)
    data += struct.pack("<I", port)
    data += _serialize_string_len(password)
    data += _serialize_string(sni)
    data += b"\x81\x81"
    data += _serialize_string(fingerprint)
    data += b"\x00"
    data += b"\x81\x81\x81"
    data += struct.pack("<I", 1)
    data += _serialize_string(name)
    data += b"\x81\x81"
    encoded = base64.urlsafe_b64encode(zlib.compress(data, 7))
    return "sn://anytls?" + encoded.decode("ascii").rstrip("=")


def serialize_trusttunnel(
    server: str,
    port: int,
    username: str,
    password: str,
    sni: str,
    name: str,
) -> str:
    data = struct.pack("<I", 4)
    data += _serialize_string(server)
    data += struct.pack("<I", port)
    data += _serialize_string(username)
    data += _serialize_string_len(password)
    data += b"\x00\x00\x00\x00\x00"
    data += _serialize_string("bbr")
    data += _serialize_string(sni)
    data += b"\x81\x81\x81"
    data += _serialize_string("firefox")
    data += b"\x00\x00"
    data += _serialize_string("0s")
    data += b"\x00\x00"
    data += b"\x81\x81\x81\x81\x81\x81\x81"
    data += struct.pack("<I", 1)
    data += _serialize_string(name)
    data += b"\x81\x81"
    encoded = base64.urlsafe_b64encode(zlib.compress(data, 7))
    return "sn://trusttunnel?" + encoded.decode("ascii").rstrip("=")


def _awg_value(values: dict, key: str, default: str = "") -> str:
    expected = key.lower()
    for current, value in values.items():
        if current.lower() == expected:
            return value
    return default


def _parse_awg_config(config: str) -> dict:
    result = {"interface": {}, "peer": {}}
    section = None
    for raw_line in config.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower() == "[interface]":
            section = "interface"
        elif line.lower() == "[peer]":
            section = "peer"
        elif "=" in line and section:
            key, _, value = line.partition("=")
            result[section][key.strip()] = value.strip()
    return result


def _integer(value: str, default: int) -> int:
    try:
        return int(value.strip()) if value.strip() else default
    except ValueError:
        return default


def generate_awg_sn_link(
    conf_text: str,
    profile_name: str = "AmneziaWG",
) -> str | None:
    try:
        config = _parse_awg_config(conf_text)
        interface = config["interface"]
        peer = config["peer"]

        endpoint = _awg_value(peer, "Endpoint", "127.0.0.1:51820")
        if ":" in endpoint:
            server_host, server_port_text = endpoint.rsplit(":", 1)
            server_port = int(server_port_text)
        else:
            server_host, server_port = endpoint, 51820

        client_address = _awg_value(interface, "Address", "10.8.0.2/32")
        private_key = _awg_value(interface, "PrivateKey")
        server_public_key = _awg_value(peer, "PublicKey")
        preshared_key = _awg_value(peer, "PresharedKey")
        keepalive = _integer(
            _awg_value(peer, "PersistentKeepalive", "25"),
            25,
        )
        mtu = _integer(_awg_value(interface, "MTU", "1280"), 1280)
        u32 = lambda value: struct.pack("<I", value)

        data = (
            u32(2)
            + _serialize_string(server_host)
            + u32(server_port)
            + _serialize_string(client_address)
            + _serialize_string_len(private_key)
            + _serialize_string_len(server_public_key)
            + _serialize_string_len(preshared_key)
            + u32(keepalive)
            + u32(mtu)
            + _serialize_string_len("")
            + u32(_integer(_awg_value(interface, "Jc", "4"), 4))
            + u32(_integer(_awg_value(interface, "Jmin", "40"), 40))
            + u32(_integer(_awg_value(interface, "Jmax", "70"), 70))
            + u32(_integer(_awg_value(interface, "S1", "0"), 0))
            + u32(_integer(_awg_value(interface, "S2", "0"), 0))
            + _serialize_string_len(_awg_value(interface, "H1", "0"))
            + _serialize_string_len(_awg_value(interface, "H2", "0"))
            + u32(_integer(_awg_value(interface, "S3", "0"), 0))
            + u32(_integer(_awg_value(interface, "S4", "0"), 0))
            + _serialize_string_len(_awg_value(interface, "H3", "0"))
            + _serialize_string_len(_awg_value(interface, "H4", "0"))
            + _serialize_string_len(_awg_value(interface, "I1"))
            + b"\x81\x81\x81\x81"
            + u32(1 if keepalive > 0 else 0)
            + _serialize_string_len(profile_name)
            + b"\x81\x81"
        )
        encoded = base64.urlsafe_b64encode(zlib.compress(data, level=7))
        return "sn://awg?" + encoded.rstrip(b"=").decode("ascii")
    except Exception:
        return None


def generate_mieru_nekobox_link(
    host: str,
    port: int,
    protocol: str,
    username: str,
    password: str,
    tag: str,
) -> str:
    data = (
        b"\x00\x00\x00\x00"
        + _serialize_string(host)
        + struct.pack("<I", port)
        + _serialize_string(protocol.upper())
        + _serialize_string(username)
        + _serialize_string_len(password)
        + struct.pack("<I", 1)
        + _serialize_string(tag)
        + b"\x81\x81"
    )
    encoded = base64.urlsafe_b64encode(zlib.compress(data, 7))
    return "sn://mieru?" + encoded.decode().rstrip("=")


def clean_link_to_sn(link: str, user: User) -> str | None:
    """Convert supported share links to NekoBox-native ``sn://`` links."""
    try:
        parsed = urllib.parse.urlparse(link)
        scheme = parsed.scheme
        fragment = (
            urllib.parse.unquote(parsed.fragment)
            if parsed.fragment
            else user.email
        )
        if scheme in {
            "naive",
            "naive+quic",
            "naive+https",
            "anytls",
            "shadowtls",
        }:
            return None

        if scheme in ("tt", "trusttunnel"):
            if "@" not in parsed.netloc:
                return None
            credentials, host_port = parsed.netloc.split("@", 1)
            decoded = urllib.parse.unquote(credentials)
            username, password = (
                decoded.split(":", 1) if ":" in decoded else (decoded, "")
            )
            host, port_text = (
                host_port.split(":", 1)
                if ":" in host_port
                else (host_port, "443")
            )
            query = urllib.parse.parse_qs(parsed.query)
            if query.get("alpn", ["h2"])[0] == "h3":
                return None
            return serialize_trusttunnel(
                host,
                int(port_text),
                username,
                password,
                query.get("sni", [host])[0],
                fragment,
            )

        if scheme == "mierus":
            without_fragment, _, fragment_text = link.partition("#")
            without_scheme = without_fragment[len("mierus://") :]
            without_query, _, query_text = without_scheme.partition("?")
            credentials, _, host = without_query.rpartition("@")
            username, _, password = credentials.partition(":")
            if ":" in host:
                host, _ = host.split(":", 1)
            query = urllib.parse.parse_qs(query_text)
            return generate_mieru_nekobox_link(
                host,
                int(query.get("port", [8964])[0]),
                query.get("protocol", ["TCP"])[0],
                urllib.parse.unquote(username),
                urllib.parse.unquote(password),
                (
                    urllib.parse.unquote(fragment_text)
                    if fragment_text
                    else user.email
                ),
            )
    except Exception:
        return None
    return None
