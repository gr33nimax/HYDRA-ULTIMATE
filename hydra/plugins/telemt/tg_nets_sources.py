"""External Telegram network source adapters."""
from __future__ import annotations

import json
import re
import socket
import urllib.request
from collections.abc import Callable

from .tg_nets_model import HTTP_TIMEOUT, TG_MNT, USER_AGENT, valid_cidr

HttpGet = Callable[..., bytes | None]


def http_get(url: str, timeout: int = HTTP_TIMEOUT) -> bytes | None:
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except Exception:
        return None


def ripe_stat(
    asns: list[int],
    *,
    get: HttpGet = http_get,
) -> tuple[list[str], int, str]:
    networks: list[str] = []
    available = 0
    for asn in asns:
        raw = get(
            "https://stat.ripe.net/data/announced-prefixes/data.json"
            f"?resource=AS{asn}"
        )
        if not raw:
            continue
        try:
            found = [
                item["prefix"]
                for item in json.loads(raw).get("data", {}).get("prefixes", [])
                if valid_cidr(item.get("prefix", ""))
            ]
            networks.extend(found)
            available += bool(found)
        except Exception:
            pass
    if networks:
        return (
            networks,
            len(networks),
            f"{len(networks)} префиксов ({available}/{len(asns)} ASN)",
        )
    return [], 0, "недоступен"


def bgptools(
    asns: list[int],
    *,
    get: HttpGet = http_get,
) -> tuple[list[str], int, str]:
    allowed = set(asns)
    networks: list[str] = []
    for asn in asns:
        raw = get(f"https://bgp.tools/table.jsonl?asn={asn}", timeout=15)
        if not raw:
            continue
        for line in raw.decode("utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
                origin = item.get("ASN") or item.get("asn") or item.get("OriginAS")
                prefix = item.get("CIDR") or item.get("prefix") or item.get("Prefix")
                origin = int(str(origin).lstrip("AS"))
                if origin in allowed and valid_cidr(str(prefix)):
                    networks.append(str(prefix))
            except Exception:
                pass
    networks = list(dict.fromkeys(networks))
    if networks:
        return networks, len(networks), f"{len(networks)} префиксов"
    return [], 0, "недоступен"


def radb_command(
    command: str,
    host: str = "whois.radb.net",
    port: int = 43,
    timeout: int = 15,
) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall((command + "\r\n").encode("ascii"))
            chunks = []
            while chunk := sock.recv(4096):
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return None


def radb_irr(
    asns: list[int],
    *,
    query=radb_command,
) -> tuple[list[str], int, str]:
    extra: set[int] = set()
    response = query("!gAS-TELEGRAM")
    if response:
        for token in re.split(r"[\s,]+", response):
            try:
                extra.add(int(token.strip().upper().lstrip("AS")))
            except ValueError:
                pass
    networks: list[str] = []
    for asn in set(asns) | extra:
        for command, ipv6 in ((f"!rAS{asn},l", False), (f"!6AS{asn},l", True)):
            response = query(command)
            if response:
                networks.extend(
                    token
                    for token in re.split(r"\s+", response)
                    if valid_cidr(token) and ((":" in token) == ipv6)
                )
    if networks:
        return networks, len(networks), f"{len(networks)} записей"
    return [], 0, "недоступен"


def ripe_whois(
    *,
    get: HttpGet = http_get,
) -> tuple[list[str], int, str]:
    networks: list[str] = []
    for object_type in ("route", "route6"):
        raw = get(
            "https://rest.db.ripe.net/search.json"
            f"?query-string={TG_MNT}&type-filter={object_type}"
            "&flags=rG&source=RIPE"
        )
        if not raw:
            continue
        try:
            objects = json.loads(raw).get("objects", {}).get("object", [])
            for item in objects:
                for attribute in item.get("attributes", {}).get("attribute", []):
                    value = attribute.get("value", "").strip()
                    if attribute.get("name") == object_type and valid_cidr(value):
                        networks.append(value)
        except Exception:
            pass
    if networks:
        return networks, len(networks), f"{len(networks)} объектов"
    return [], 0, "недоступен"
