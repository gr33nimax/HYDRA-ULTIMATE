"""Console adapter and compatibility surface for Telegram network discovery."""
from __future__ import annotations

import re
import sys
import unicodedata
from datetime import datetime

from . import tg_nets_model as _model
from . import tg_nets_runtime as _runtime
from . import tg_nets_sources as _sources
from .tg_nets_model import (
    HTTP_TIMEOUT,
    NETS_FILE,
    STALE_DAYS,
    TG_ASNS,
    TG_MNT,
    WARN_DAYS,
)

_BUILTIN_NETS = _model.BUILTIN_NETS
_UA = _model.USER_AGENT
_RE_V4 = _model._RE_V4
_RE_V6 = _model._RE_V6
_BOX_W = 68
_palette = {
    "RED": "\033[31m",
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "CYAN": "\033[36m",
    "WHITE": "\033[97m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "NC": "\033[0m",
} if sys.stdout.isatty() else {key: "" for key in (
    "RED", "GREEN", "YELLOW", "CYAN", "WHITE", "BOLD", "DIM", "NC"
)}
_C = _palette
RED = _palette["RED"]
GREEN = _palette["GREEN"]
YELLOW = _palette["YELLOW"]
CYAN = _palette["CYAN"]
WHITE = _palette["WHITE"]
BOLD = _palette["BOLD"]
DIM = _palette["DIM"]
NC = _palette["NC"]


def _detect_colors() -> dict:
    return dict(_palette)


def _plain(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _vlen(text: str) -> int:
    return sum(
        2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        for char in _plain(text)
    )


def _box_row(text: str = "") -> None:
    print(f"{CYAN}║{NC}{text}{' ' * max(0, _BOX_W - _vlen(text))}{CYAN}║{NC}")


def _box_row_raw(text: str) -> None:
    _box_row(text)


def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        _box_row(title.center(_BOX_W))
        _box_sep()


def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}╣{NC}")


def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")


def _brow(text: str = "") -> None:
    _box_row(text)


def _bok(message: str) -> None:
    _box_row(f"  {GREEN}✓{NC}  {message}")


def _bwarn(message: str) -> None:
    _box_row(f"  {YELLOW}⚠{NC}  {message}")


def _binfo(message: str) -> None:
    _box_row(f"  {CYAN}→{NC}  {message}")


def _berr(message: str) -> None:
    _box_row(f"  {RED}✗{NC}  {message}")


def _bkv(key: str, value: str, kw: int = 18) -> None:
    _box_row(f"  {key}{' ' * max(0, kw - _vlen(key))}  {value}")


def _bsrc(num: str, name: str, detail: str) -> None:
    _box_row(f"  [{num}] {name}: {detail}")


def _valid_cidr(cidr: str) -> bool:
    return _model.valid_cidr(cidr)


def _remove_more_specific(networks: list[str]) -> list[str]:
    return _model.remove_more_specific(networks)


def _dedup(networks: list[str]) -> list[str]:
    return _model.dedup(networks)


def _load_from_file() -> list[str] | None:
    return _model.load_from_file(NETS_FILE)


def _save_to_file(
    networks: list[str],
    sources_used: list[str],
    raw_count: int = 0,
    removed_count: int = 0,
) -> None:
    _model.save_to_file(
        networks,
        sources_used,
        raw_count,
        removed_count,
        path=NETS_FILE,
    )


def _file_age_days() -> int | None:
    return _model.file_age_days(NETS_FILE)


def _http_get(url: str, timeout: int = HTTP_TIMEOUT) -> bytes | None:
    return _sources.http_get(url, timeout)


def _src_ripe_stat(asns: list[int]) -> tuple[list[str], int, str]:
    return _sources.ripe_stat(asns, get=_http_get)


def _src_bgptools(asns: list[int]) -> tuple[list[str], int, str]:
    return _sources.bgptools(asns, get=_http_get)


def _radb_cmd(
    cmd: str,
    host: str = "whois.radb.net",
    port: int = 43,
    timeout: int = 15,
) -> str | None:
    return _sources.radb_command(cmd, host, port, timeout)


def _src_radb_irr(asns: list[int]) -> tuple[list[str], int, str]:
    return _sources.radb_irr(asns, query=_radb_cmd)


def _src_ripe_whois_rest() -> tuple[list[str], int, str]:
    return _sources.ripe_whois(get=_http_get)


def fetch_tg_nets_from_sources(
    verbose: bool = True,
) -> tuple[list[str], list[str], dict]:
    del verbose
    return _runtime.fetch(
        [
            ("RIPE-stat", _src_ripe_stat),
        ]
    )


def _print_sources_table(stats: dict) -> None:
    labels = {
        "RIPE-stat": "RIPE NCC stat.ripe.net",
        "bgp.tools": "bgp.tools/as/* Originated",
        "RADB-IRR": "RADB / IRR whois TCP",
        "RIPE-WHOIS": "RIPE WHOIS REST",
    }
    for key, label in labels.items():
        count, message = stats.get(key, (0, "нет ответа"))
        mark = "✓" if count else "✗"
        print(f"  {mark} {label}: {message}")


def update_tg_nets_interactive() -> list[str]:
    print("\n  Обновление подсетей Telegram")
    print("  ASN:", " ".join(f"AS{asn}" for asn in TG_ASNS))
    print("  Запрашиваю источники...")
    networks, sources, stats = fetch_tg_nets_from_sources(verbose=False)
    _print_sources_table(stats)
    raw_count = stats.get("_raw_count", 0)
    removed_count = stats.get("_removed", 0)
    _save_to_file(networks, sources, raw_count, removed_count)
    ipv4 = sum(":" not in network for network in networks)
    print(
        f"  Сохранено {len(networks)} подсетей "
        f"({ipv4} IPv4, {len(networks) - ipv4} IPv6): {NETS_FILE}"
    )
    if not sources:
        print("  Источники недоступны, использован встроенный список.")
    return networks


def get_tg_nets() -> list[str]:
    return _load_from_file() or list(_BUILTIN_NETS)


def tg_nets_status_line() -> str:
    age = _file_age_days()
    count = len(get_tg_nets())
    if age is None:
        return f"Подсети TG: {count} (встроенный список)"
    date = datetime.fromtimestamp(NETS_FILE.stat().st_mtime).strftime("%Y-%m-%d")
    if age >= STALE_DAYS:
        return f"Подсети TG: {count} ({date} — УСТАРЕЛ {age} дн.!)"
    if age >= WARN_DAYS:
        return f"Подсети TG: {count} ({date} — {age} дн., обновить)"
    return f"Подсети TG: {count} ({date}, {age} дн.)"
