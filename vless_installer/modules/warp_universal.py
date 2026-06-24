"""
vless_installer/modules/warp_universal.py
───────────────────────────────────────────────────────────────────────────────
Универсальная маршрутизация через Cloudflare WARP на уровне ОС (ip route).
Позволяет заворачивать определенные домены и подсети через WARP для всех
прокси-протоколов (xray, NaiveProxy, Mieru, Hysteria2 и др.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Any

from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_item_exit,
    _box_ok, _box_warn, _box_info, _box_desc, _box_input,
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
)

STATE_FILE = Path("/var/lib/xray-installer/state.json")
LOG_FILE = Path("/var/log/vless-install.log")
CRON_FILE = Path("/etc/cron.d/warp-universal-sync")


def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [WARP-UNIV-{level}] {clean}\n")
    except Exception:
        pass


def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("OK", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def error(msg: str)   -> None: print(f"{RED}[ERR]{NC}   {msg}"); _log("ERR", msg)


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_state(state: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        error(f"Не удалось сохранить state.json: {e}")


def detect_warp_interface() -> Optional[str]:
    """Определить имя активного сетевого интерфейса WARP.
    Проверяет: warp0, wg-warp, CloudflareWARP, tun0 (warp-go).
    Использует `ip link show` для проверки.
    """
    candidates = ["warp0", "wg-warp", "CloudflareWARP", "tun0"]
    try:
        r = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, check=True)
        lines = r.stdout.splitlines()
        # Сначала ищем точное совпадение из кандидатов, которые в статусе UP
        for cand in candidates:
            for line in lines:
                if cand in line and "state UP" in line:
                    return cand
        # Если не нашли UP, берем просто первый существующий из кандидатов
        for cand in candidates:
            for line in lines:
                if cand in line:
                    return cand
    except Exception as e:
        _log("WARN", f"Ошибка при автоопределении интерфейса WARP: {e}")
    return None


def get_warp_gateway(iface: str) -> Optional[str]:
    """Возвращает шлюз интерфейса WARP (обычно для dev-интерфейсов не требуется)."""
    return None


def resolve_domain(domain: str) -> list[str]:
    """Разрешить доменное имя в список IPv4-адресов (/32)."""
    ips = set()
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        for item in infos:
            ip = item[4][0]
            ips.add(ip)
    except Exception as e:
        _log("WARN", f"Не удалось разрешить домен {domain}: {e}")
    return sorted(list(ips))


def get_current_warp_routes(iface: str) -> set[str]:
    """Получить все маршруты, направленные в WARP-интерфейс."""
    routes = set()
    try:
        r = subprocess.run(["ip", "route", "show", "dev", iface], capture_output=True, text=True, check=True)
        for line in r.stdout.splitlines():
            parts = line.strip().split()
            if parts:
                cidr = parts[0]
                if cidr == "default":
                    continue
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', cidr):
                    continue
                if "/" not in cidr:
                    cidr = f"{cidr}/32"
                routes.add(cidr)
    except Exception as e:
        _log("WARN", f"Ошибка получения текущих маршрутов для {iface}: {e}")
    return routes


def add_route(cidr: str, iface: str) -> bool:
    """Добавить системный маршрут через WARP-интерфейс."""
    try:
        r = subprocess.run(["ip", "route", "add", cidr, "dev", iface], capture_output=True, text=True)
        if r.returncode == 0:
            return True
        if "File exists" in r.stderr:
            return True
        _log("WARN", f"Ошибка добавления маршрута {cidr} dev {iface}: {r.stderr.strip()}")
        return False
    except Exception as e:
        _log("WARN", f"Исключение при добавлении маршрута {cidr}: {e}")
        return False


def remove_route(cidr: str, iface: str) -> bool:
    """Удалить системный маршрут через WARP-интерфейс."""
    try:
        r = subprocess.run(["ip", "route", "del", cidr, "dev", iface], capture_output=True, text=True)
        if r.returncode == 0:
            return True
        if "No such process" in r.stderr or "Cannot find" in r.stderr:
            return True
        _log("WARN", f"Ошибка удаления маршрута {cidr} dev {iface}: {r.stderr.strip()}")
        return False
    except Exception as e:
        _log("WARN", f"Исключение при удалении маршрута {cidr}: {e}")
        return False


def sync_routes(state: Optional[dict] = None) -> dict:
    """Синхронизация маршрутов:
    - Разрешает домены в IP
    - Сопоставляет со списком subnets
    - Добавляет недостающие маршруты на WARP интерфейсе
    - Удаляет устаревшие маршруты
    """
    summary = {"added": 0, "removed": 0, "errors": 0}
    if state is None:
        state = _load_state()

    warp_routing = state.get("warp_routing", {})
    enabled = warp_routing.get("enabled", False)
    domains = warp_routing.get("domains", [])
    subnets = warp_routing.get("subnets", [])
    resolved_cache = warp_routing.get("resolved_cache", {})

    iface = detect_warp_interface()
    if not iface:
        if enabled:
            _log("ERR", "Интерфейс WARP не обнаружен. Пропуск синхронизации.")
        return summary

    desired_cidrs = set()

    if enabled:
        for subnet in subnets:
            if "/" not in subnet:
                desired_cidrs.add(f"{subnet}/32")
            else:
                desired_cidrs.add(subnet)

        new_resolved_cache = {}
        for domain in domains:
            ips = resolve_domain(domain)
            if ips:
                new_resolved_cache[domain] = ips
                for ip in ips:
                    desired_cidrs.add(f"{ip}/32")
            else:
                old_ips = resolved_cache.get(domain, [])
                if old_ips:
                    new_resolved_cache[domain] = old_ips
                    for ip in old_ips:
                        desired_cidrs.add(f"{ip}/32")
                    _log("INFO", f"Домен {domain} не разрешен, использован кэш: {old_ips}")

        warp_routing["resolved_cache"] = new_resolved_cache
    else:
        pass

    current_cidrs = get_current_warp_routes(iface)

    managed_cidrs = set(desired_cidrs)
    for subnet in subnets:
        if "/" not in subnet:
            managed_cidrs.add(f"{subnet}/32")
        else:
            managed_cidrs.add(subnet)
    for ips in resolved_cache.values():
        for ip in ips:
            managed_cidrs.add(f"{ip}/32")

    to_remove = (current_cidrs & managed_cidrs) - desired_cidrs
    to_add = desired_cidrs - current_cidrs

    for cidr in to_remove:
        if remove_route(cidr, iface):
            summary["removed"] += 1
        else:
            summary["errors"] += 1

    for cidr in to_add:
        if add_route(cidr, iface):
            summary["added"] += 1
        else:
            summary["errors"] += 1

    from datetime import datetime
    warp_routing["last_sync"] = datetime.now().isoformat()
    state["warp_routing"] = warp_routing
    _save_state(state)

    if summary["added"] > 0 or summary["removed"] > 0:
        _log("INFO", f"Синхронизация завершена: добавлено {summary['added']}, удалено {summary['removed']}, ошибок {summary['errors']}")
    return summary


def enable_warp_routing(domains: list[str], subnets: list[str]) -> None:
    state = _load_state()
    warp_routing = state.setdefault("warp_routing", {})
    warp_routing["enabled"] = True
    warp_routing["domains"] = domains
    warp_routing["subnets"] = subnets
    state["warp_routing"] = warp_routing
    _save_state(state)
    install_cron_job()
    sync_routes(state)


def disable_warp_routing() -> None:
    state = _load_state()
    warp_routing = state.setdefault("warp_routing", {})
    warp_routing["enabled"] = False
    state["warp_routing"] = warp_routing
    _save_state(state)
    uninstall_cron_job()
    sync_routes(state)


def add_domains(domains_to_add: list[str]) -> None:
    state = _load_state()
    warp_routing = state.setdefault("warp_routing", {})
    domains = warp_routing.setdefault("domains", [])
    added = False
    for d in domains_to_add:
        if d not in domains:
            domains.append(d)
            added = True
    if added:
        warp_routing["domains"] = domains
        state["warp_routing"] = warp_routing
        _save_state(state)
        sync_routes(state)


def add_subnets(subnets_to_add: list[str]) -> None:
    state = _load_state()
    warp_routing = state.setdefault("warp_routing", {})
    subnets = warp_routing.setdefault("subnets", [])
    added = False
    for s in subnets_to_add:
        if s not in subnets:
            subnets.append(s)
            added = True
    if added:
        warp_routing["subnets"] = subnets
        state["warp_routing"] = warp_routing
        _save_state(state)
        sync_routes(state)


def add_domain(domain: str) -> None:
    state = _load_state()
    warp_routing = state.setdefault("warp_routing", {})
    domains = warp_routing.setdefault("domains", [])
    if domain not in domains:
        domains.append(domain)
        warp_routing["domains"] = domains
        state["warp_routing"] = warp_routing
        _save_state(state)
        sync_routes(state)


def remove_domain(domain: str) -> None:
    state = _load_state()
    warp_routing = state.setdefault("warp_routing", {})
    domains = warp_routing.setdefault("domains", [])
    if domain in domains:
        domains.remove(domain)
        warp_routing["domains"] = domains
        state["warp_routing"] = warp_routing
        _save_state(state)
        sync_routes(state)


def add_subnet(subnet: str) -> None:
    state = _load_state()
    warp_routing = state.setdefault("warp_routing", {})
    subnets = warp_routing.setdefault("subnets", [])
    if subnet not in subnets:
        subnets.append(subnet)
        warp_routing["subnets"] = subnets
        state["warp_routing"] = warp_routing
        _save_state(state)
        sync_routes(state)


def remove_subnet(subnet: str) -> None:
    state = _load_state()
    warp_routing = state.setdefault("warp_routing", {})
    subnets = warp_routing.setdefault("subnets", [])
    if subnet in subnets:
        subnets.remove(subnet)
        warp_routing["subnets"] = subnets
        state["warp_routing"] = warp_routing
        _save_state(state)
        sync_routes(state)


def get_status() -> dict:
    state = _load_state()
    warp_routing = state.get("warp_routing", {})
    iface = detect_warp_interface()
    routes_count = len(get_current_warp_routes(iface)) if iface else 0
    return {
        "enabled": warp_routing.get("enabled", False),
        "interface": iface,
        "routes_count": routes_count,
        "domains": warp_routing.get("domains", []),
        "subnets": warp_routing.get("subnets", []),
        "last_sync": warp_routing.get("last_sync", ""),
    }


def install_cron_job() -> None:
    """Установить cron-задачу для синхронизации маршрутов каждые 5 минут."""
    try:
        main_path = Path(__file__).resolve().parent.parent.parent / "main.py"
        if not main_path.exists():
            main_path = Path("/opt/vless-ultimate/main.py")
        
        cron_line = f"*/5 * * * * root /usr/bin/python3 {main_path} --warp-sync-routes >/dev/null 2>&1\n"
        CRON_FILE.write_text(cron_line, encoding="utf-8")
        CRON_FILE.chmod(0o644)
        _log("INFO", f"Установлена задача cron: {CRON_FILE}")
    except Exception as e:
        _log("ERR", f"Не удалось установить cron-задачу: {e}")


def uninstall_cron_job() -> None:
    """Удалить cron-задачу синхронизации маршрутов."""
    try:
        CRON_FILE.unlink(missing_ok=True)
        _log("INFO", "Удалена задача cron синхронизации маршрутов.")
    except Exception as e:
        _log("ERR", f"Не удалось удалить cron-задачу: {e}")


def do_warp_routing_menu() -> None:
    """Интерактивное меню для настройки системного обхода WARP."""
    while True:
        status = get_status()
        os.system("clear")
        _box_top("УНИВЕРСАЛЬНЫЙ ОБХОД ЧЕРЕЗ WARP")
        _box_row(f"  {DIM}Маршрутизация доменов/подсетей через WARP на уровне ОС{NC}")
        _box_sep()
        
        status_str = f"{GREEN}ВКЛЮЧЕН{NC}" if status["enabled"] else f"{YELLOW}ВЫКЛЮЧЕН{NC}"
        iface_str = f"{GREEN}{status['interface']}{NC}" if status["interface"] else f"{RED}не найден{NC}"
        
        _box_row(f"  Статус обхода:    {status_str}")
        _box_row(f"  WARP Интерфейс:   {iface_str}")
        _box_row(f"  Активных путей:   {CYAN}{status['routes_count']}{NC}")
        _box_row(f"  Всего доменов:    {len(status['domains'])}")
        _box_row(f"  Всего подсетей:   {len(status['subnets'])}")
        _box_row(f"  Последняя синхр.: {DIM}{status['last_sync']}{NC}")
        _box_sep()
        
        _box_item("1", f"{'Выключить' if status['enabled'] else 'Включить'} обход")
        _box_item("2", "🌐 Управление доменами")
        _box_item("3", "📡 Управление подсетями")
        _box_item("4", "🔄 Синхронизировать маршруты сейчас")
        _box_item("5", "📋 Показать список доменов и подсетей")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()
        
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
            
        if ch in ("0", "q", "Q", ""):
            break
            
        elif ch == "1":
            if status["enabled"]:
                disable_warp_routing()
                _box_ok("Обход выключен, маршруты удалены")
            else:
                if not status["interface"]:
                    _box_warn("Внимание: Интерфейс WARP не найден. Маршруты не будут работать, пока интерфейс не поднимется.")
                enable_warp_routing(status["domains"], status["subnets"])
                _box_ok("Обход включен")
            time.sleep(1.5)
            
        elif ch == "2":
            _manage_domains_menu(status)
            
        elif ch == "3":
            _manage_subnets_menu(status)
            
        elif ch == "4":
            info("Синхронизация маршрутов...")
            summary = sync_routes()
            _box_ok(f"Готово: добавлено {summary['added']}, удалено {summary['removed']}, ошибок {summary['errors']}")
            time.sleep(2)
            
        elif ch == "5":
            _show_lists_menu(status)


def _manage_domains_menu(status: dict) -> None:
    while True:
        status = get_status()
        os.system("clear")
        _box_top("УПРАВЛЕНИЕ ДОМЕНАМИ ДЛЯ WARP")
        _box_row("  Список доменов, трафик к которым пойдет через WARP:")
        _box_sep()
        
        domains = status["domains"]
        if not domains:
            _box_row(f"  {DIM}(список пуст){NC}")
        else:
            for idx, domain in enumerate(domains, 1):
                _box_row(f"  {idx}. {domain}")
                
        _box_sep()
        _box_item("1", "➕ Добавить домен")
        _box_item("2", "➖ Удалить домен")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()
        
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
            
        if ch in ("0", ""):
            break
        elif ch == "1":
            raw_input = input(f"{CYAN}Введите имя домена или список через запятую:{NC} ").strip()
            if raw_input:
                parts = [p.strip().lower() for p in raw_input.split(",") if p.strip()]
                if parts:
                    add_domains(parts)
                    _box_ok(f"Добавлено доменов ({len(parts)}): {', '.join(parts)}")
                    time.sleep(1.5)
        elif ch == "2":
            if not domains:
                _box_warn("Список пуст")
                time.sleep(1)
                continue
            idx_str = input(f"{CYAN}Введите номер домена для удаления:{NC} ").strip()
            try:
                idx = int(idx_str) - 1
                if 0 <= idx < len(domains):
                    removed = domains[idx]
                    remove_domain(removed)
                    _box_ok(f"Домен {removed} удален")
                else:
                    _box_warn("Неверный номер")
            except ValueError:
                _box_warn("Введите число")
            time.sleep(1)


def _manage_subnets_menu(status: dict) -> None:
    while True:
        status = get_status()
        os.system("clear")
        _box_top("УПРАВЛЕНИЕ ПОДСЕТЯМИ ДЛЯ WARP")
        _box_row("  Список подсетей (CIDR), трафик к которым пойдет через WARP:")
        _box_sep()
        
        subnets = status["subnets"]
        if not subnets:
            _box_row(f"  {DIM}(список пуст){NC}")
        else:
            for idx, subnet in enumerate(subnets, 1):
                _box_row(f"  {idx}. {subnet}")
                
        _box_sep()
        _box_item("1", "➕ Добавить подсеть")
        _box_item("2", "➖ Удалить подсеть")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()
        
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
            
        if ch in ("0", ""):
            break
        elif ch == "1":
            raw_input = input(f"{CYAN}Введите подсеть или список через запятую:{NC} ").strip()
            if raw_input:
                parts = [p.strip() for p in raw_input.split(",") if p.strip()]
                valid_parts = []
                for subnet in parts:
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', subnet):
                        valid_parts.append(subnet)
                    else:
                        _box_warn(f"Неверный формат подсети: {subnet}")
                        time.sleep(1.5)
                if valid_parts:
                    add_subnets(valid_parts)
                    _box_ok(f"Добавлено подсетей ({len(valid_parts)}): {', '.join(valid_parts)}")
                    time.sleep(1.5)
        elif ch == "2":
            if not subnets:
                _box_warn("Список пуст")
                time.sleep(1)
                continue
            idx_str = input(f"{CYAN}Введите номер подсети для удаления:{NC} ").strip()
            try:
                idx = int(idx_str) - 1
                if 0 <= idx < len(subnets):
                    removed = subnets[idx]
                    remove_subnet(removed)
                    _box_ok(f"Подсеть {removed} удалена")
                else:
                    _box_warn("Неверный номер")
            except ValueError:
                _box_warn("Введите число")
            time.sleep(1)


def _show_lists_menu(status: dict) -> None:
    os.system("clear")
    _box_top("ТЕКУЩИЕ ДОМЕНЫ И ПОДСЕТИ")
    _box_row(f"  {BOLD}Домены:{NC}")
    if not status["domains"]:
        _box_row("    (нет)")
    else:
        for d in status["domains"]:
            _box_row(f"    • {d}")
    
    _box_row("")
    _box_row(f"  {BOLD}Подсети:{NC}")
    if not status["subnets"]:
        _box_row("    (нет)")
    else:
        for s in status["subnets"]:
            _box_row(f"    • {s}")
            
    _box_row("")
    _box_row(f"  {BOLD}Разрешенные IP (кэш резолва):{NC}")
    state = _load_state()
    cache = state.get("warp_routing", {}).get("resolved_cache", {})
    if not cache:
        _box_row("    (пусто)")
    else:
        for dom, ips in cache.items():
            ips_str = ", ".join(ips)
            _box_row(f"    • {dom} → {ips_str}")
            
    _box_sep()
    _box_bottom()
    input(f"{BLUE}Нажмите Enter для возврата...{NC}")
