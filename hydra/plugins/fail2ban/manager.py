"""
hydra/plugins/fail2ban/manager.py — TUI-консоль управления Fail2ban.
"""
from __future__ import annotations

import re
import time
import shutil
import subprocess
import ipaddress
import urllib.request
import json
from pathlib import Path

from hydra.core.state import AppState
from hydra.ui.tui import (
    clear, menu, prompt, confirm, panel, info, success, warn, error,
    RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC
)

_F2B_LOG = Path("/var/log/fail2ban.log")
_PROXY_JAILS = ["hydra-anytls", "hydra-trusttunnel", "hydra-naive", "hydra-awg"]
_SYSTEM_JAILS = ["hydra-sshd", "hydra-recidive", "hydra-portscan"]

_BAN_LINE_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}),\d+\s+'
    r'fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+Ban\s+(?P<ip>\S+)'
)

# ── Низкоуровневые обёртки над fail2ban-client / systemd ──────────────────────
def _f2b_installed() -> bool:
    return shutil.which("fail2ban-client") is not None


def _f2b_active() -> bool:
    r = subprocess.run(["systemctl", "is-active", "fail2ban"], capture_output=True, text=True)
    return r.stdout.strip() == "active"


def _f2b_client(*args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["fail2ban-client", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(list(args), 1, stdout="", stderr="timeout")
    except Exception:
        return subprocess.CompletedProcess(list(args), 1, stdout="", stderr="error")


def _f2b_reload() -> bool:
    r = _f2b_client("reload")
    if r.returncode == 0:
        return True
    subprocess.run(["systemctl", "restart", "fail2ban"], capture_output=True)
    time.sleep(2)
    return _f2b_active()


def _f2b_list_jails() -> list[str]:
    r = _f2b_client("status")
    if r.returncode != 0:
        return []
    m = re.search(r"Jail list:\s*(.*)", r.stdout)
    if not m:
        return []
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def _extract_int(line: str) -> int:
    m = re.search(r":\s*(\d+)", line)
    return int(m.group(1)) if m else 0


def _f2b_jail_info(jail: str) -> dict:
    info_dict = {"currently_failed": 0, "total_failed": 0,
                 "currently_banned": 0, "total_banned": 0, "banned_ips": []}
    r = _f2b_client("status", jail)
    if r.returncode != 0:
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
def _f2b_log_lines() -> list[str]:
    paths = [_F2B_LOG, Path(str(_F2B_LOG) + ".1")]
    lines: list[str] = []
    for p in paths:
        if not p.exists():
            continue
        try:
            lines.extend(p.read_text(errors="replace").splitlines())
        except Exception:
            pass
    return lines


def _f2b_today_ban_history() -> list[dict]:
    today = time.strftime("%Y-%m-%d")
    stats: dict = {}
    for line in _f2b_log_lines():
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


def _f2b_clear_log() -> tuple[bool, str]:
    cleared = []
    errors = []
    for p in (_F2B_LOG, Path(str(_F2B_LOG) + ".1")):
        if not p.exists():
            continue
        try:
            p.write_text("", encoding="utf-8")
            cleared.append(str(p))
        except Exception as exc:
            errors.append(f"{p.name}: {exc}")
    if errors:
        return False, "; ".join(errors)
    if not cleared:
        return True, "Лог-файлы не найдены"
    return True, f"Очищено: {', '.join(cleared)}"


def _f2b_ban_many(jail: str, ips: list[str]) -> int:
    if not ips:
        return 0
    before = set(_f2b_jail_info(jail)["banned_ips"])
    for i in range(0, len(ips), 50):
        batch = ips[i:i + 50]
        _f2b_client("set", jail, "banip", *batch)
    after = set(_f2b_jail_info(jail)["banned_ips"])
    return len(after - before)


def _f2b_unban(ip: str) -> bool:
    r = _f2b_client("unban", ip)
    return r.returncode == 0


def _f2b_unban_many(ips: list[str]) -> tuple[int, int]:
    ok = fail = 0
    for ip in ips:
        if _f2b_unban(ip):
            ok += 1
        else:
            fail += 1
    return ok, fail


# ── Работа с jail-файлами конфигурации ───────────────────────────────────────
def _portscan_add_log_rule():
    # This is a per-source SYN-rate detector, not a generic log of every
    # connection. The exact specification is also used for -C and -D.
    spec = [
        "-p", "tcp", "--syn",
        "-m", "hashlimit", "--hashlimit-above", "15/minute",
        "--hashlimit-burst", "15", "--hashlimit-mode", "srcip",
        "--hashlimit-name", "hydra_portscan",
        "-m", "comment", "--comment", "hydra-portscan-log",
        "-j", "LOG", "--log-prefix", "HYDRA-PORTSCAN ", "--log-level", "4",
    ]
    check = subprocess.run(["iptables", "-C", "INPUT", *spec], capture_output=True)
    if check.returncode != 0:
        subprocess.run(["iptables", "-I", "INPUT", "1", *spec], capture_output=True)


def _portscan_remove_log_rule():
    spec = [
        "-p", "tcp", "--syn",
        "-m", "hashlimit", "--hashlimit-above", "15/minute",
        "--hashlimit-burst", "15", "--hashlimit-mode", "srcip",
        "--hashlimit-name", "hydra_portscan",
        "-m", "comment", "--comment", "hydra-portscan-log",
        "-j", "LOG", "--log-prefix", "HYDRA-PORTSCAN ", "--log-level", "4",
    ]
    for _ in range(10):
        check = subprocess.run(["iptables", "-C", "INPUT", *spec], capture_output=True)
        if check.returncode != 0:
            break
        subprocess.run(["iptables", "-D", "INPUT", *spec], capture_output=True)


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


def _fetch_asn_prefixes(asn: str) -> list[str]:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "hydra/2.0", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            break
        except Exception as exc:
            if attempt == 3:
                raise RuntimeError(f"RIPE Stat недоступен: {exc}")
            time.sleep(2 ** attempt)
            
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


def _resolve_to_cidrs(raw: str) -> tuple[str, str, list[str]]:
    raw = raw.strip()
    up = raw.upper()
    if up.startswith("AS") or (raw.isdigit() and len(raw) <= 10):
        asn = _asn_normalize(raw)
        cidrs = _fetch_asn_prefixes(asn)
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


def _resolve_ban_targets(raw: str) -> list[tuple[str, str, list[str]]]:
    tokens = [t.strip() for t in raw.replace(",", " ").split() if t.strip()]
    results = []
    for token in tokens:
        try:
            display, kind, cidrs = _resolve_to_cidrs(token)
            results.append((display, kind, cidrs))
        except Exception as exc:
            warn(f"Ошибка разбора '{token}': {exc}")
    return results


# ── Интерактивное TUI меню ───────────────────────────────────────────────────
def menu_fail2ban(state: AppState, plugin) -> None:
    while True:
        clear()
        
        installed = _f2b_installed()
        active = _f2b_active() if installed else False
        live_jails = _f2b_list_jails() if active else []
        
        # В гидре мы ориентируемся на джейлы hydra-anytls, hydra-mieru, hydra-trusttunnel, hydra-naive, hydra-awg, hydra-sshd, hydra-recidive, hydra-portscan
        configured_jails = _PROXY_JAILS + _SYSTEM_JAILS
        jail_names = live_jails if live_jails else configured_jails
        
        total_banned = 0
        if active and live_jails:
            for j in live_jails:
                total_banned += _f2b_jail_info(j)["currently_banned"]
                
        status_lines = []
        if not installed:
            status_lines.append(f"  Статус:      {RED}не установлен{NC}")
        else:
            status_lines.append(f"  Статус:      {(GREEN+'● активен') if active else (DIM+'○ остановлен')}{NC}")
            
            # Группировка активных джейлов
            active_proxies = []
            active_systems = []
            for j in jail_names:
                if j in _PROXY_JAILS:
                    active_proxies.append(j.replace("hydra-", ""))
                else:
                    active_systems.append(j.replace("hydra-", ""))
            
            if active_proxies:
                status_lines.append(f"  Прокси:      {CYAN}{len(active_proxies)}{NC} ({', '.join(active_proxies)})")
            if active_systems:
                status_lines.append(f"  Система:     {YELLOW}{len(active_systems)}{NC} ({', '.join(active_systems)})")
                
            status_lines.append(f"  Забанено:    {(RED if total_banned else DIM)}{total_banned}{NC} IP (сейчас)")
            status_lines.append(f"  {DIM}Mieru: auth-jail отключён — ядро не журналирует IP ошибки ключа{NC}")
            
        panel("🛡️ FAIL2BAN — ЗАЩИТА ОТ ПЕРЕБОРА", status_lines)
        
        options = []
        if not installed:
            options.append(("1", "📥 Установить и настроить Fail2ban", "Установить пакет и создать базовые джейлы"))
        else:
            from hydra.core.state import get_protocol
            p_state = get_protocol(state, "fail2ban")
            wl = p_state.config.get("whitelist", [])
            options.append(("1", f"{'⏸️  Остановить' if active else '▶️  Запустить'} Fail2ban", "Переключить статус службы"))
            options.append(("2", "🔁 Перезапустить / применить конфигурацию", "Выполнить reload / restart"))
            options.append(("3", f"🚫 Забаненные IP ({total_banned} шт.)", "Просмотр заблокированных IP по джейлам и разбан"))
            options.append(("4", "➕ Забанить вручную (IP/диапазон/ASN)", "Добавить адреса в черный список"))
            options.append(("5", f"⚙️  Настройка джейла (bantime/findtime/maxretry)", "Изменить тайминги и попытки"))
            options.append(("6", "🔌 Включить/выключить джейл", "Активация отдельных джейлов"))
            options.append(("7", "📋 Лог Fail2ban (последние 30 строк)", "Просмотр лог-файла в реальном времени"))
            options.append(("8", "🛠️  Восстановить базовую конфигурацию", "Сбросить локальные изменения джейлов"))
            options.append(("9", "📊 История банов за сутки", "Просмотр накопленной статистики"))
            options.append(("W", f"⚪ Управление whitelist {DIM}({len(wl)} IP){NC}", "Список IP-адресов/подсетей-исключений"))
            options.append(("-", "", ""))
            options.append(("X", "🧹 Очистить лог Fail2ban", "Безопасное усечение (copytruncate) файлов лога"))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "УПРАВЛЕНИЕ FAIL2BAN")
        
        if choice == "0":
            break
            
        if not installed:
            if choice == "1":
                info("Устанавливаю и настраиваю Fail2ban...")
                if plugin.install():
                    from hydra.core.state import get_protocol, save_state
                    proto = get_protocol(state, "fail2ban")
                    proto.installed = True
                    proto.enabled = True
                    state.security.fail2ban_enabled = True
                    if plugin.apply(state):
                        save_state(state)
                        success("Fail2ban успешно установлен и запущен!")
                    else:
                        try:
                            plugin.on_disable(state)
                        except RuntimeError:
                            pass
                        proto.enabled = False
                        state.security.fail2ban_enabled = False
                        save_state(state)
                        error("Fail2ban установлен, но конфигурация протокольных jail не применена.")
                else:
                    error("Не удалось выполнить установку Fail2ban.")
                prompt("Нажмите Enter для продолжения")
            continue
            
        # ── 1. Запуск/остановка службы ────────────────────────────────────────
        if choice == "1":
            from hydra.core.state import get_protocol, save_state
            proto = get_protocol(state, "fail2ban")
            if active:
                info("Останавливаю Fail2ban...")
                try:
                    plugin.on_disable(state)
                except RuntimeError:
                    pass
                time.sleep(1)
                if not _f2b_active():
                    proto.enabled = False
                    state.security.fail2ban_enabled = False
                    save_state(state)
                    success("Служба остановлена.")
                else:
                    error("Не удалось остановить службу.")
            else:
                info("Запускаю Fail2ban...")
                try:
                    plugin.on_enable(state)
                except RuntimeError:
                    pass
                time.sleep(2)
                if _f2b_active():
                    proto.enabled = True
                    state.security.fail2ban_enabled = True
                    save_state(state)
                    success("Служба запущена.")
                else:
                    error("Служба не запустилась.")
            prompt("Нажмите Enter для продолжения")
            
        # ── 2. Reload / restart ───────────────────────────────────────────────
        elif choice == "2":
            info("Перечитываю конфигурацию (reload)...")
            if _f2b_reload():
                success("Конфигурация успешно применена!")
            else:
                error("Не удалось перезапустить Fail2ban. Проверьте: journalctl -u fail2ban")
            prompt("Нажмите Enter для продолжения")
            
        # ── 3. Забаненные IP + разбан ─────────────────────────────────────────
        elif choice == "3":
            clear()
            rows = []
            for j in jail_names:
                for ip in _f2b_jail_info(j)["banned_ips"]:
                    rows.append((ip, j))
            
            list_lines = []
            if not rows:
                list_lines.append(f"  {DIM}Забаненных IP нет{NC}")
            else:
                list_lines.append(f"  {BOLD}{'#':<4}{'IP':<24}Джейл{NC}")
                list_lines.append("  " + "─" * 40)
                for i, (ip, j) in enumerate(rows, 1):
                    list_lines.append(f"  {CYAN}{i:<4}{NC}{RED}{ip:<24}{NC}{DIM}{j}{NC}")
                list_lines.append("")
                list_lines.append(f"  {DIM}Введите номер(а), IP, CIDR или ASN для разбана{NC}")
                
            panel(f"🚫 ЗАБАНЕННЫЕ IP ({len(rows)} шт.)", list_lines)
            
            if rows:
                raw = prompt("Разбанить (Enter — отмена)").strip()
                if raw:
                    tokens = [t.strip() for t in raw.replace(",", " ").split() if t.strip()]
                    targets = []
                    for t in tokens:
                        if t.isdigit() and 1 <= int(t) <= len(rows):
                            targets.append(rows[int(t) - 1][0])
                        else:
                            for _disp, _kind, cidrs in _resolve_ban_targets(t):
                                targets.extend(cidrs)
                    if not targets:
                        error("Не удалось распознать цели для разбана.")
                    else:
                        ok, fail = _f2b_unban_many(targets)
                        if ok:
                            success(f"Разбанено адресов: {ok}")
                        if fail:
                            warn(f"Не забанено / не найдено: {fail}")
                    prompt("Нажмите Enter для продолжения")
            else:
                prompt("Нажмите Enter для продолжения")
                
        # ── 4. Бан вручную ────────────────────────────────────────────────────
        elif choice == "4":
            clear()
            if not jail_names:
                error("Нет доступных активных джейлов.")
                prompt("Нажмите Enter...")
                continue
                
            jail_opts = []
            for i, j in enumerate(jail_names, 1):
                jail_opts.append((str(i), j, ""))
            jail_opts.append(("0", "Отмена", ""))
                
            raw_j = menu(jail_opts, "ВЫБЕРИТЕ ДЖЕЙЛ ДЛЯ БАНА")
            if raw_j == "0" or not (raw_j.isdigit() and 1 <= int(raw_j) <= len(jail_names)):
                continue
            jail = jail_names[int(raw_j) - 1]
            
            clear()
            add_lines = [
                "  Можно ввести несколько целей через пробел или запятую:",
                "",
                f"    {CYAN}1.2.3.4{NC}              — одиночный IP",
                f"    {CYAN}10.0.0.0/24{NC}          — подсеть (CIDR)",
                f"    {CYAN}10.0.0.1-10.0.0.255{NC}  — диапазон IPv4",
                f"    {CYAN}AS12345{NC}              — автономная система (ASN)",
                "",
                f"  {DIM}Пример: 1.2.3.4, AS1234{NC}"
            ]
            panel(f"БАН В ДЖЕЙЛЕ {jail}", add_lines)
            raw_inp = prompt("Цели для бана").strip()
            if not raw_inp:
                continue
                
            targets = _resolve_ban_targets(raw_inp)
            if not targets:
                error("Не удалось разобрать ни одной цели.")
                prompt("Нажмите Enter...")
                continue
                
            all_cidrs = []
            for display, kind, cidrs in targets:
                all_cidrs.extend(cidrs)
                info(f"Разрешено {display} ({kind}): {len(cidrs)} CIDR")
                
            info(f"Применяю бан в джейле {jail} ({len(all_cidrs)} CIDR)...")
            newly = _f2b_ban_many(jail, all_cidrs)
            if newly:
                success(f"Успешно забанено новых записей: {newly} в {jail}")
            else:
                warn("Новых записей не добавлено (возможно, они уже в бане или служба остановлена)")
            prompt("Нажмите Enter для продолжения")
            
        # ── 5. Настройка параметров джейла ────────────────────────────────────
        elif choice == "5":
            clear()
            jail_opts = []
            proxies = _PROXY_JAILS
            systems = _SYSTEM_JAILS
            all_jails = proxies + systems
            
            idx = 1
            for j in proxies:
                jail_opts.append((str(idx), f"{CYAN}[Прокси]{NC} {j}", ""))
                idx += 1
            jail_opts.append(("-", "", ""))
            for j in systems:
                jail_opts.append((str(idx), f"{YELLOW}[Система]{NC} {j}", ""))
                idx += 1
            jail_opts.append(("0", "Отмена", ""))
                
            raw_j = menu(jail_opts, "ВЫБЕРИТЕ ДЖЕЙЛ ДЛЯ НАСТРОЙКИ")
            if raw_j == "0" or not (raw_j.isdigit() and 1 <= int(raw_j) <= len(all_jails)):
                continue
            jail = all_jails[int(raw_j) - 1]
            
            current = plugin.jail_options(state).get(jail, {})
            cur_bt = current.get("bantime", "3600")
            cur_ft = current.get("findtime", "600")
            cur_mr = current.get("maxretry", "5")
            
            clear()
            panel(f"⚙️ НАСТРОЙКА ДЖЕЙЛА {jail}", [
                f"  Текущие параметры:",
                f"    bantime (время бана):     {cur_bt} сек",
                f"    findtime (окно поиска):   {cur_ft} сек",
                f"    maxretry (кол-во попыток): {cur_mr}"
            ])
            
            new_bt = prompt("bantime, сек", default=cur_bt).strip()
            new_ft = prompt("findtime, сек", default=cur_ft).strip()
            new_mr = prompt("maxretry", default=cur_mr).strip()
            
            if not (new_bt.isdigit() and new_ft.isdigit() and new_mr.isdigit()) or min(map(int, (new_bt, new_ft, new_mr))) < 1:
                error("Параметры должны быть положительными целыми числами!")
                prompt("Нажмите Enter...")
                continue
                
            from hydra.core.state import get_protocol, save_state
            p_state = get_protocol(state, "fail2ban")
            jail_config = p_state.config.setdefault("jails", {}).setdefault(jail, {})
            previous = dict(jail_config)
            jail_config.update({"bantime": new_bt, "findtime": new_ft, "maxretry": new_mr})
            info("Сохраняю настройки...")
            if plugin.apply(state):
                save_state(state)
                success(f"Настройки применены: bantime={new_bt}, findtime={new_ft}, maxretry={new_mr}")
            else:
                p_state.config["jails"][jail] = previous
                error("Настройки не применены: конфигурация Fail2ban не прошла проверку")
            prompt("Нажмите Enter для продолжения")
            
        # ── 6. Включение/выключение джейла ────────────────────────────────────
        elif choice == "6":
            clear()
            jail_opts = []
            proxies = _PROXY_JAILS
            systems = _SYSTEM_JAILS
            all_jails = proxies + systems
            
            idx = 1
            for j in proxies:
                en = plugin.jail_options(state).get(j, {}).get("enabled", "false") == "true"
                state_str = f"{GREEN}вкл{NC}" if en else f"{DIM}выкл{NC}"
                jail_opts.append((str(idx), f"{CYAN}[Прокси]{NC} {j} [{state_str}]", ""))
                idx += 1
            jail_opts.append(("-", "", ""))
            for j in systems:
                en = plugin.jail_options(state).get(j, {}).get("enabled", "false") == "true"
                state_str = f"{GREEN}вкл{NC}" if en else f"{DIM}выкл{NC}"
                jail_opts.append((str(idx), f"{YELLOW}[Система]{NC} {j} [{state_str}]", ""))
                idx += 1
                
            jail_opts.append(("0", "Отмена", ""))
                
            raw_j = menu(jail_opts, "ВКЛЮЧИТЬ / ВЫКЛЮЧИТЬ ДЖЕЙЛ")
            if raw_j == "0" or not (raw_j.isdigit() and 1 <= int(raw_j) <= len(all_jails)):
                continue
            jail = all_jails[int(raw_j) - 1]
            
            cur_en = plugin.jail_options(state).get(jail, {}).get("enabled", "false") == "true"
            new_en = not cur_en
            required_protocol = {
                "hydra-anytls": "anytls",
                "hydra-trusttunnel": "trusttunnel",
                "hydra-naive": "naive",
                "hydra-awg": "amneziawg",
            }.get(jail)
            if new_en and required_protocol:
                required_state = state.protocols.get(required_protocol)
                if not required_state or not required_state.enabled:
                    error(f"Сначала включите протокол {required_protocol}.")
                    prompt("Нажмите Enter для продолжения")
                    continue
            from hydra.core.state import get_protocol, save_state
            p_state = get_protocol(state, "fail2ban")
            jail_config = p_state.config.setdefault("jails", {}).setdefault(jail, {})
            previous = dict(jail_config)
            jail_config["enabled"] = new_en
            
            info(f"Переключаю статус {jail}...")
            if plugin.apply(state):
                save_state(state)
                if jail == "hydra-portscan":
                    plugin._sync_portscan_rule(new_en)
                success(f"Джейл {jail} успешно {'выключен' if cur_en else 'включен'}!")
            else:
                p_state.config["jails"][jail] = previous
                error("Статус не изменён: конфигурация Fail2ban не прошла проверку")
            prompt("Нажмите Enter для продолжения")
            
        # ── 7. Просмотр лога ──────────────────────────────────────────────────
        elif choice == "7":
            clear()
            if _F2B_LOG.exists():
                try:
                    lines = _F2B_LOG.read_text(errors="replace").splitlines()[-30:]
                except Exception:
                    lines = []
                print()
                print(f"  {BOLD}{CYAN}📋 ЛОГ FAIL2BAN (последние 30 строк){NC}")
                print(f"  {CYAN}" + "═" * 70 + f"{NC}")
                if not lines:
                    print(f"  {DIM}Лог-файл пуст{NC}")
                else:
                    for line in lines:
                        col = RED if " Ban " in line else (YELLOW if " Unban " in line else DIM)
                        print(f"  {col}{line}{NC}")
                print(f"  {CYAN}" + "═" * 70 + f"{NC}")
            else:
                error(f"Файл лога не найден: {_F2B_LOG}")
            print()
            prompt("Нажмите Enter для продолжения")
            
        # ── 8. Восстановление базового конфига ────────────────────────────────
        elif choice == "8":
            warn("СБРОС КОНФИГУРАЦИИ ДЖЕЙЛОВ!")
            warn("Локальные изменения лимитов и параметров джейлов будут удалены.")
            if confirm("Продолжить?", default=False):
                info("Восстанавливаю конфигурации...")
                from hydra.core.state import get_protocol, save_state
                p_state = get_protocol(state, "fail2ban")
                previous_jails = p_state.config.pop("jails", None)
                if plugin.apply(state):
                    save_state(state)
                    success("Базовая конфигурация восстановлена!")
                else:
                    if previous_jails is not None:
                        p_state.config["jails"] = previous_jails
                    error("Базовая конфигурация записана, но служба не запустилась.")
            else:
                info("Отменено.")
            prompt("Нажмите Enter для продолжения")
            
        # ── 9. История банов за сутки ─────────────────────────────────────────
        elif choice == "9":
            clear()
            hist = _f2b_today_ban_history()
            hist_lines = [
                f"  {DIM}Накопительный список за текущие сутки (сбрасывается в полночь).{NC}",
                f"  {DIM}Показывает факт бана, даже если bantime уже истек и IP разбанен.{NC}",
                "  " + "─" * 68,
                f"  {BOLD}{'#':<4}{'IP':<22}{'Джейл':<15}{'Раз':<5}{'Впервые':<10}Последний{NC}",
                "  " + "─" * 68
            ]
            if not hist:
                hist_lines.append(f"  {DIM}За сегодня событий бана не зафиксировано.{NC}")
            else:
                for i, e in enumerate(hist, 1):
                    hist_lines.append(
                        f"  {CYAN}{i:<4}{NC}{RED}{e['ip']:<22}{NC}{DIM}{e['jail']:<15}{NC}"
                        f"{e['count']:<5}{DIM}{e['first_seen']:<10}{NC}{e['last_seen']}"
                    )
            panel(f"📊 ИСТОРИЯ БАНОВ ЗА СЕГОДНЯ ({len(hist)} шт.)", hist_lines)
            prompt("Нажмите Enter для продолжения")
            
        # ── W. Управление whitelist ───────────────────────────────────────────
        elif choice == "w" or choice == "W":
            while True:
                clear()
                from hydra.core.state import get_protocol, save_state
                p_state = get_protocol(state, "fail2ban")
                wl = p_state.config.setdefault("whitelist", [])
                
                wl_lines = []
                for i, ip in enumerate(wl, 1):
                    wl_lines.append(f"  {CYAN}{i:>2}.{NC} {ip}")
                
                panel("Доверенные IP / подсети (Whitelist)", wl_lines if wl_lines else ["  Список пуст"])
                
                wl_opts = [
                    ("1", "➕ Добавить IP/подсеть", "Внести адрес в список исключений"),
                    ("2", "➖ Удалить IP/подсеть", "Исключить адрес из списка исключений"),
                    ("0", "↩ Назад", "")
                ]
                wl_choice = menu(wl_opts, "WHITELIST FAIL2BAN")
                
                if wl_choice == "0":
                    break
                elif wl_choice == "1":
                    new_ip = prompt("Введите IP или подсеть (например, 192.168.1.100 или 10.0.0.0/24)").strip()
                    if new_ip:
                        try:
                            if "/" in new_ip:
                                ipaddress.ip_network(new_ip, strict=False)
                            else:
                                ipaddress.ip_address(new_ip)
                            
                            if new_ip not in wl:
                                wl.append(new_ip)
                                p_state.config["whitelist"] = wl
                                save_state(state)
                                
                                info("Применяю конфигурацию whitelist...")
                                if plugin.apply(state):
                                    success(f"Добавлен в whitelist и применен: {new_ip}")
                                else:
                                    warn(f"Добавлен в whitelist: {new_ip}, но Fail2ban не смог применить конфигурацию автоматически")
                            else:
                                warn("Этот IP/подсеть уже есть в списке.")
                        except ValueError:
                            error("Некорректный формат IP-адреса или подсети!")
                    else:
                        warn("Ввод пуст.")
                    prompt("Нажмите Enter для продолжения")
                    
                elif wl_choice == "2":
                    if not wl:
                        error("Список пуст, нечего удалять.")
                        prompt("Нажмите Enter...")
                        continue
                        
                    del_opts = []
                    for i, ip in enumerate(wl, 1):
                        del_opts.append((str(i), ip, ""))
                    del_opts.append(("0", "Отмена", ""))
                    
                    del_choice = menu(del_opts, "УДАЛЕНИЕ ИЗ WHITELIST")
                    if del_choice == "0" or not (del_choice.isdigit() and 1 <= int(del_choice) <= len(wl)):
                        continue
                        
                    removed_ip = wl.pop(int(del_choice) - 1)
                    p_state.config["whitelist"] = wl
                    save_state(state)
                    
                    info("Применяю конфигурацию whitelist...")
                    if plugin.apply(state):
                        success(f"Удален из whitelist и применен: {removed_ip}")
                    else:
                        warn(f"Удален из whitelist: {removed_ip}, но Fail2ban не смог применить конфигурацию автоматически")
                    prompt("Нажмите Enter для продолжения")

        # ── X. Очистить лог ───────────────────────────────────────────────────
        elif choice == "x" or choice == "X":
            warn("ОЧИСТКА ЛОГА FAIL2BAN")
            warn(f"Будут очищены файлы {_F2B_LOG} и .1.")
            warn("Текущие баны и работа Fail2ban не пострадают.")
            if confirm("Продолжить?", default=False):
                ok, msg = _f2b_clear_log()
                if ok:
                    success(msg)
                else:
                    error(f"Не удалось очистить: {msg}")
            else:
                info("Отменено.")
            prompt("Нажмите Enter для продолжения")
