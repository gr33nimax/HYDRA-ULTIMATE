"""
hydra/plugins/fail2ban/manager.py — TUI-консоль управления Fail2ban.
"""
from __future__ import annotations

import re
import ipaddress
import json
import sys

from hydra.core.state_models import AppState, get_protocol
from hydra.services.application import ApplicationService
from hydra.ui.plugin_managers._facade_bridge import bind_facade
from hydra.ui.tui import (
    clear, menu, prompt, confirm, panel, info, success, warn, error,
    RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC
)

_F2B_LOG = "/var/log/fail2ban.log"
_PROTOCOL_JAILS: list[str] = []
_SYSTEM_JAILS = ["hydra-sshd", "hydra-recidive"]


def _implementation_scope():
    return bind_facade(sys.modules[__name__])

_BAN_LINE_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}),\d+\s+'
    r'fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+Ban\s+(?P<ip>\S+)'
)

# ── Низкоуровневые обёртки над fail2ban-client / systemd ──────────────────────
def _f2b_active(app: ApplicationService) -> bool:
    return app.admin.unit_active("fail2ban")


def _f2b_client(
    app: ApplicationService,
    *args: str,
    timeout: int = 15,
):
    try:
        return app.admin.run_command(
            ["fail2ban-client", *args],
            timeout=timeout,
            text=True,
        )
    except Exception:
        return None


def _f2b_reload(app: ApplicationService) -> bool:
    r = _f2b_client(app, "reload")
    if r is not None and r.returncode == 0:
        return True
    app.admin.restart_unit("fail2ban")
    app.monitoring.sleep(2)
    return _f2b_active(app)


def _f2b_list_jails(app: ApplicationService) -> list[str]:
    r = _f2b_client(app, "status")
    if r is None or r.returncode != 0:
        return []
    m = re.search(r"Jail list:\s*(.*)", r.stdout)
    if not m:
        return []
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def _extract_int(line: str) -> int:
    m = re.search(r":\s*(\d+)", line)
    return int(m.group(1)) if m else 0


def _f2b_jail_info(
    app: ApplicationService,
    jail: str,
) -> dict:
    info_dict = {"currently_failed": 0, "total_failed": 0,
                 "currently_banned": 0, "total_banned": 0, "banned_ips": []}
    r = _f2b_client(app, "status", jail)
    if r is None or r.returncode != 0:
        return info_dict
    for line in r.stdout.splitlines():
        s = line.strip()
        if "Currently failed" in s:
            info_dict["currently_failed"] = _extract_int(s)
        elif "Total failed" in s:
            info_dict["total_failed"] = _extract_int(s)
        elif "Currently banned" in s:
            info_dict["currently_banned"] = _extract_int(s)
        elif "Total banned" in s:
            info_dict["total_banned"] = _extract_int(s)
        elif "Banned IP list" in s and ":" in s:
            after = s.split(":", 1)[1].strip()
            info_dict["banned_ips"] = after.split() if after else []
    return info_dict


# ── История банов за сутки (накопительно, read-only) ─────────────────────────
def _f2b_log_lines(app: ApplicationService) -> list[str]:
    return list(app.plugin_query("fail2ban", "recent_logs", limit=10_000))


def _f2b_today_ban_history(app: ApplicationService) -> list[dict]:
    today = app.monitoring.local_time("%Y-%m-%d")
    stats: dict = {}
    for line in _f2b_log_lines(app):
        m = _BAN_LINE_RE.match(line)
        if not m or m.group("date") != today:
            continue
        key = (m.group("ip"), m.group("jail"))
        ts = m.group("time")
        e = stats.get(key)
        if e is None:
            stats[key] = {"ip": m.group("ip"), "jail": m.group("jail"),
                          "first_seen": ts, "last_seen": ts, "count": 1}
        else:
            e["last_seen"] = ts
            e["count"] += 1
    return sorted(stats.values(), key=lambda x: x["last_seen"], reverse=True)


def _f2b_clear_log(app: ApplicationService) -> tuple[bool, str]:
    return app.plugin_action("fail2ban", "clear_logs")


def _f2b_ban_many(
    app: ApplicationService,
    jail: str,
    ips: list[str],
) -> int:
    if not ips:
        return 0
    before = set(_f2b_jail_info(app, jail)["banned_ips"])
    for i in range(0, len(ips), 50):
        batch = ips[i:i + 50]
        _f2b_client(app, "set", jail, "banip", *batch)
    after = set(_f2b_jail_info(app, jail)["banned_ips"])
    return len(after - before)


def _f2b_unban(app: ApplicationService, ip: str) -> bool:
    r = _f2b_client(app, "unban", ip)
    return r is not None and r.returncode == 0


def _f2b_unban_many(
    app: ApplicationService,
    ips: list[str],
) -> tuple[int, int]:
    ok = fail = 0
    for ip in ips:
        if _f2b_unban(app, ip):
            ok += 1
        else:
            fail += 1
    return ok, fail


# ── Работа с jail-файлами конфигурации ───────────────────────────────────────
# ── Селф-контейнед парсинг пользовательского ввода ───────────────────────────
def _parse_ip(raw: str) -> list[str]:
    net = ipaddress.ip_address(raw)
    bits = 32 if net.version == 4 else 128
    return [f"{net}/{bits}"]


def _parse_cidr(raw: str) -> list[str]:
    net = ipaddress.ip_network(raw, strict=False)
    return [str(net)]


def _parse_range(raw: str) -> list[str]:
    parts = raw.split("-", 1)
    if len(parts) != 2:
        raise ValueError(f"Неверный диапазон: {raw!r}")
    start = ipaddress.IPv4Address(parts[0].strip())
    end = ipaddress.IPv4Address(parts[1].strip())
    if start > end:
        start, end = end, start
    return [str(n) for n in ipaddress.summarize_address_range(start, end)]


def _asn_normalize(raw: str) -> str:
    raw = raw.strip().upper()
    return raw if raw.startswith("AS") else f"AS{raw}"


def _fetch_asn_prefixes(
    asn: str,
    app: ApplicationService,
) -> list[str]:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    for attempt in range(1, 4):
        try:
            response = app.diagnostics.request(
                url,
                headers={
                    "User-Agent": "hydra/2.0",
                    "Accept": "application/json",
                },
                timeout=30,
            )
            if response.error_kind:
                raise RuntimeError(
                    response.error_detail or response.error_kind,
                )
            raw = response.text()
            break
        except Exception as exc:
            if attempt == 3:
                raise RuntimeError(f"RIPE Stat недоступен: {exc}")
            app.monitoring.sleep(2 ** attempt)
            
    try:
        data = json.loads(raw)
    except Exception as exc:
        raise RuntimeError(f"Неверный JSON от RIPE Stat: {exc}")
        
    prefixes = data.get("data", {}).get("prefixes", [])
    result = []
    for item in prefixes:
        p = item.get("prefix", "")
        try:
            net = ipaddress.ip_network(p, strict=False)
            result.append(str(net))
        except ValueError:
            continue
            
    if not result:
        raise RuntimeError(f"0 префиксов для {asn}")
    return result


def _resolve_to_cidrs(
    raw: str,
    app: ApplicationService,
) -> tuple[str, str, list[str]]:
    raw = raw.strip()
    up = raw.upper()
    if up.startswith("AS") or (raw.isdigit() and len(raw) <= 10):
        asn = _asn_normalize(raw)
        cidrs = _fetch_asn_prefixes(asn, app)
        return asn, "asn", cidrs
        
    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        return str(net), "cidr", [str(net)]
        
    if "-" in raw and ":" not in raw:
        cidrs = _parse_range(raw)
        return raw, "range", cidrs
        
    net = ipaddress.ip_address(raw)
    bits = 32 if net.version == 4 else 128
    return str(net), "ip", [f"{net}/{bits}"]


def _resolve_ban_targets(
    raw: str,
    app: ApplicationService,
) -> list[tuple[str, str, list[str]]]:
    tokens = [t.strip() for t in raw.replace(",", " ").split() if t.strip()]
    results = []
    for token in tokens:
        try:
            display, kind, cidrs = _resolve_to_cidrs(token, app)
            results.append((display, kind, cidrs))
        except Exception as exc:
            warn(f"Ошибка разбора '{token}': {exc}")
    return results


# ── Интерактивное TUI меню ───────────────────────────────────────────────────
def menu_fail2ban(
    state: AppState,
    app: ApplicationService,
) -> None:
    """Run the specialised controller through the stable manager facade."""
    from hydra.ui.plugin_managers._fail2ban_menu import run

    with _implementation_scope():
        run(state, app)
