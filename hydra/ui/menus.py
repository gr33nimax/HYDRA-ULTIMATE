"""
hydra/ui/menus.py — Главное меню и подменю HYDRA v2.

Архитектура:
  • main_menu — корень, 7 разделов (ядро, протоколы, пользователи, Telegram,
    мониторинг, безопасность, VPS)
  • Раздел «Протоколы» разбит на категории: TRANSPORT, ENHANCEMENT, SECURITY
  • Раздел «Пользователи» содержит детальный просмотр + ссылки/конфиги
  • Раздел «Безопасность» — полноценное управление, а не просто toggle
  • Раздел «Мониторинг» — система, трафик, логи
"""
from __future__ import annotations

import subprocess
import sys
import uuid as _uuid
import math
import re
import random
from datetime import datetime
from pathlib import Path

from hydra.core.state import (
    AppState, User, save_state, load_state, update_state, find_user, get_protocol,
)
from hydra.core.singbox import (
    install as install_singbox,
    generate_config, write_config, reload as reload_singbox,
    start as start_singbox, is_running,
    is_installed as singbox_installed, get_version as singbox_version,
)
from hydra.plugins.registry import (
    enabled, collect_fragments,
    status_all, transports, enhancements, security as sec_plugins,
)
from hydra.plugins.base import PluginCategory
from hydra.core.systemd import install_service, install_timer, remove_unit
from hydra.core import orchestrator
from hydra.services.subscriptions.generator import (
    get_subscription_urls, get_user_access_status,
    get_user_entitlement_status,
)
from hydra.services.traffic import (
    collect_traffic, update_user_traffic, refresh_traffic_state, protocol_totals,
)
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt, panel, kv,
    confirm, _bytes_auto, _bar, _ok, _width,
    BANNER, GREEN, CYAN, YELLOW, RED, BOLD, DIM, WHITE, TEXT, NC,
    PANEL_W, dashboard_menu,
)
from hydra.ui.protocol_ui import (
    protocol_label, protocol_menu_title, protocol_status_panel, status_badge,
)


HYDRA_SAYINGS = (
    "Одна голова хорошо, а десять — лучше.",
    "Сначала проверь конфигурацию — потом перезапускай.",
    "Семь раз проверь конфиг — один раз примени.",
    "Логи не спорят с реальностью.",
    "Каждому потоку — свой маршрут.",
    "Стабильный туннель — незаметный туннель.",
    "Сначала резервная копия, потом магия.",
    "Не всё то offline, что не отвечает на ping.",
    "Если сервис молчит — проверь журнал.",
    "Конфигурация применена. Паника отменяется.",
)
HYDRA_SAYING = random.choice(HYDRA_SAYINGS)



# ═════════════════════════════════════════════════════════════════════════════
#  Утилиты
# ═════════════════════════════════════════════════════════════════════════════

import threading
import os
from pathlib import Path

# 1. DNS резолвится синхронно и моментально на этапе импорта модуля
_cached_dns = "1.1.1.1"
try:
    if os.path.exists("/etc/resolv.conf"):
        dns_list = []
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    dns_list.append(line.split()[1])
        if dns_list:
            _cached_dns = dns_list[0]
except Exception:
    pass

# 2. Определение IP адресов и GeoIP флага
_cached_pub_ip = "Получение..."
_cached_country_flag = ""
_cached_country_code = ""
_network_fetched = False

def _is_private_ip(ip: str) -> bool:
    if not ip or ip == "127.0.0.1":
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        p0, p1 = int(parts[0]), int(parts[1])
        if p0 == 10:
            return True
        if p0 == 192 and p1 == 168:
            return True
        if p0 == 172 and (16 <= p1 <= 31):
            return True
        if p0 == 127:
            return True
        return False
    except ValueError:
        return True

def _fetch_network_info_bg():
    global _cached_pub_ip, _cached_country_flag, _cached_country_code, _network_fetched
    try:
        from hydra.utils.net import public_ip
        ip = public_ip()
        _cached_pub_ip = ip
        
        # Получаем код страны для флага
        country_code = ""
        import subprocess
        for url in ("https://ipinfo.io/country", "https://ipapi.co/country/"):
            try:
                r = subprocess.run(
                    ["curl", "-s", "--max-time", "3", url],
                    capture_output=True, text=True, timeout=4
                )
                code = r.stdout.strip().upper()
                if len(code) == 2 and code.isalpha():
                    country_code = code
                    break
            except Exception:
                continue
                
        if country_code:
            # Конвертируем код страны в региональные индикаторы (флаг)
            flag = chr(ord(country_code[0]) + 127397) + chr(ord(country_code[1]) + 127397)
            _cached_country_flag = flag
            _cached_country_code = country_code
            
    except Exception:
        _cached_pub_ip = "127.0.0.1"
    _network_fetched = True

# Инициализируем IP-адреса и GeoIP в фоне
try:
    from hydra.utils.net import local_ip
    loc = local_ip()
    if loc and not _is_private_ip(loc):
        _cached_pub_ip = loc
        # Всё равно запускаем фоновый поток для определения GeoIP флага
        t = threading.Thread(target=_fetch_network_info_bg, daemon=True)
        t.start()
    else:
        t = threading.Thread(target=_fetch_network_info_bg, daemon=True)
        t.start()
except Exception:
    t = threading.Thread(target=_fetch_network_info_bg, daemon=True)
    t.start()


def _pad_visible(text: str, width: int) -> str:
    return text + " " * max(0, width - _width(text))


def _status_row(icon: str, label: str, value: str, detail: str = "") -> str:
    label_part = f"{icon} {TEXT}{label}{NC}"
    return f"  {_pad_visible(label_part, 20)}{_pad_visible(value, 18)}{detail}"


def _service_cell(icon: str, label: str, value: str) -> str:
    label_part = f"{icon} {TEXT}{label}{NC}"
    return _pad_visible(label_part, 19) + value


def _sys_info(state: AppState | None = None) -> list[str]:
    """Возвращает компактный статус узла для главного экрана."""
    cpu_pct: float | None = None
    mem_pct: float | None = None
    disk_pct: float | None = None
    uptime_str = "—"
    try:
        import psutil
        cpu_pct = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        mem_pct = mem.percent
        disk_pct = disk.percent
        boot = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot
        d, r = divmod(int(uptime.total_seconds()), 86400)
        h, m = divmod(r, 3600)
        m, _ = divmod(m, 60)
        uptime_str = f"{d} дн. {h} ч. {m} мин."
    except ImportError:
        try:
            import shutil
            total_d, used_d, free_d = shutil.disk_usage("/")
            disk_pct = (used_d / total_d) * 100 if total_d > 0 else 0
            if os.name != "nt":
                uptime_file = Path("/proc/uptime")
                if uptime_file.exists():
                    with open(uptime_file, "r") as f:
                        uptime_sec = float(f.readline().split()[0])
                    d, r = divmod(int(uptime_sec), 86400)
                    h, m = divmod(r, 3600)
                    m, _ = divmod(m, 60)
                    uptime_str = f"{d} дн. {h} ч. {m} мин."
                meminfo_file = Path("/proc/meminfo")
                if meminfo_file.exists():
                    meminfo = {}
                    with open(meminfo_file, "r") as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 2:
                                meminfo[parts[0].rstrip(":")] = int(parts[1]) * 1024
                    m_total = meminfo.get("MemTotal", 0)
                    m_free = meminfo.get("MemFree", 0)
                    m_buffers = meminfo.get("Buffers", 0)
                    m_cached = meminfo.get("Cached", 0)
                    m_used = m_total - m_free - m_buffers - m_cached
                    mem_pct = (m_used / m_total) * 100 if m_total > 0 else 0
        except Exception:
            pass
    except Exception:
        pass

    pub_ip = _cached_pub_ip
    if pub_ip == "Получение..." and state and state.network.server_ip:
        pub_ip = state.network.server_ip
    geo = _cached_country_flag or (f"[{_cached_country_code}]" if _cached_country_code else "")

    dns_service = _cached_dns
    dns_detail = ""
    try:
        r = subprocess.run(["systemctl", "is-active", "dnscrypt-proxy"], capture_output=True, text=True, timeout=1)
        if r.stdout.strip() == "active":
            conf_path = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
            if conf_path.exists():
                content = conf_path.read_text(encoding="utf-8")
                match = re.search(r"^server_names\s*=\s*\[(.*?)\]", content, flags=re.MULTILINE | re.DOTALL)
                if match:
                    names = [n.strip("'\" ") for n in match.group(1).split(",") if n.strip("'\" ")]
                    dns_service = "DNSCrypt"
                    dns_detail = ", ".join(names) if names else "активен"
                else:
                    dns_service = "DNSCrypt"
                    dns_detail = "активен"
            else:
                dns_service = "DNSCrypt"
                dns_detail = "активен"
    except Exception:
        pass

    def usage(value: float | None) -> str:
        if value is None:
            return f"{DIM}{'░' * 8}{NC}  —"
        filled = min(8, max(0, round(value / 100 * 8)))
        return f"{GREEN}{'█' * filled}{DIM}{'░' * (8 - filled)}{NC} {value:.0f}%"

    return [
        _status_row("🌐", "Публичный IP", f"{CYAN}{pub_ip}{NC}", geo),
        _status_row("🔒", "DNS", f"{GREEN}{dns_service}{NC}", dns_detail),
        _status_row("⏱", "Аптайм", uptime_str),
        "",
        f"  {TEXT}CPU{NC}  {usage(cpu_pct)}     {TEXT}RAM{NC}  {usage(mem_pct)}     {TEXT}Диск{NC}  {usage(disk_pct)}",
    ]


def _select_user(state: AppState, prompt_text: str = "") -> User | None:
    """Показывает нумерованный список пользователей и возвращает выбранного."""
    if not state.users:
        warn("Нет пользователей.")
        return None

    update_user_traffic(state)
    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, u in enumerate(state.users, 1):
        available, reason = get_user_access_status(u)
        ico = f"{GREEN}🟢{NC}" if available else f"{RED}🔴{NC}"
        used = _bytes_auto(u.traffic_used_bytes)
        lim = f"{u.traffic_limit_gb:g} GiB" if u.traffic_limit_gb else "∞"
        ttl = u.expiry_date[:10] if u.expiry_date else "∞"
        state_text = "" if available else f"  {RED}{reason}{NC}"
        print(f"  {i}. {ico} {BOLD}{u.email:<24}{NC}  {used} / {lim}  до {ttl}{state_text}")
    print()

    try:
        idx = int(prompt(prompt_text or "Номер пользователя", "1")) - 1
    except ValueError:
        warn("Введите число.")
        return None
    if not (0 <= idx < len(state.users)):
        warn("Неверный номер.")
        return None
    return state.users[idx]


def _show_user_detail(state: AppState, user: User):
    """Monitoring-only user statistics without secrets or client links."""
    clear()
    update_user_traffic(state)
    used = user.traffic_used_bytes
    lim = int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0
    status = f"{RED}заблокирован 🔴{NC}" if user.blocked else f"{GREEN}активен 🟢{NC}"
    expiry = user.expiry_date[:10] if user.expiry_date else "бессрочно"
    if user.expiry_date:
        try:
            expiry_dt = datetime.fromisoformat(user.expiry_date)
            remaining = (expiry_dt - datetime.now(expiry_dt.tzinfo)).days
            expiry = f"{expiry} · {'истёк' if remaining < 0 else f'{remaining} дн.'}"
        except (TypeError, ValueError):
            pass

    summary = [
        kv("Статус:", status),
        kv("Трафик:", f"{BOLD}{_bytes_auto(used)}{NC}"),
        kv("Лимит:", f"{user.traffic_limit_gb:g} GiB" if user.traffic_limit_gb else "без ограничений"),
        *([kv("Прогресс:", _bar(used, lim))] if user.traffic_limit_gb else []),
        kv("Подписка:", expiry),
        kv("Создан:", user.created_at[:10] if user.created_at else "—"),
    ]
    panel(f"👤 {user.email}", summary)

    enabled_names = {
        plugin.meta.name for plugin in enabled(state, PluginCategory.TRANSPORT)
        if plugin.meta.name != "wdtt"
    }
    labels = {
        "amneziawg": "AmneziaWG", "naive": "NaiveProxy",
        "anytls": "AnyTLS", "mieru": "Mieru",
        "trusttunnel": "TrustTunnel", "shadowtls": "ShadowTLS",
        "hysteria2": "Hysteria2", "snell": "Snell",
        "telemt": "Telemt",
    }
    order = [
        "amneziawg", "naive", "anytls", "mieru", "trusttunnel",
        "shadowtls", "hysteria2", "snell", "telemt",
    ]
    protocol_values = {
        name: max(0, int(stats.get("traffic_used_bytes", 0)))
        for name, stats in user.credentials.items()
        if isinstance(stats, dict)
    }
    names = [name for name in order if name in enabled_names or protocol_values.get(name, 0)]
    names.extend(sorted(set(protocol_values) - set(names) - {"wdtt"}))
    attributed = sum(protocol_values.get(name, 0) for name in names)

    print()
    print(f"  {BOLD}Трафик по протоколам{NC}")
    print(f"  {BOLD}{'Протокол':<18} {'Накоплено':>14} {'Доля':>9}{NC}")
    print(f"  {DIM}{'─' * 45}{NC}")
    for name in names:
        value = protocol_values.get(name, 0)
        share = value / used * 100 if used else 0
        print(f"  {labels.get(name, name):<18} {_bytes_auto(value):>14} {share:>8.1f}%")
    legacy = max(0, used - attributed)
    if legacy:
        share = legacy / used * 100 if used else 0
        print(f"  {'Без разбивки':<18} {_bytes_auto(legacy):>14} {share:>8.1f}%")
    if not names and not legacy:
        print(f"  {DIM}Пользователь пока не расходовал трафик.{NC}")
    print(f"  {DIM}{'─' * 45}{NC}")
    print(f"  {DIM}qWDTT здесь не отображается: для него доступен только общий счётчик.{NC}")
    print()
    prompt("Нажмите Enter")


def _user_links(state: AppState, user: User):
    """Показывает ссылки и конфиги пользователя для всех протоколов."""
    clear()
    print(f"\n  {CYAN}Конфиги и ссылки для {BOLD}{user.email}{NC}\n")

    for p in enabled(state, PluginCategory.TRANSPORT):
        if p.meta.name == "amneziawg":
            ps = state.protocols.get("amneziawg")
            has_mobile = ps and "profiles" in ps.config and "mobile" in ps.config["profiles"]
            profiles = ["desktop"]
            if has_mobile:
                profiles.append("mobile")
            
            for prof in profiles:
                conf = ""
                link = ""
                vpn_link = ""
                try:
                    conf = p.generate_client_config(user, state, profile=prof) or ""
                except Exception:
                    pass
                try:
                    link = p.client_link(user, state, profile=prof) or ""
                except Exception:
                    pass
                try:
                    vpn_link = p.amnezia_link(user, state, profile=prof) or ""
                except Exception:
                    pass
                if not conf and not link and not vpn_link:
                    continue
                label_ru = "ПК / Desktop" if prof == "desktop" else "Смартфон / Mobile"
                print(f"  {CYAN}── {BOLD}{p.meta.name.upper()} ({label_ru}){NC}{CYAN}{'─' * (PANEL_W - 14 - len(p.meta.name) - len(label_ru))}{NC}")
                if link:
                    print(f"  {GREEN}Ссылка (WireGuard):{NC}  {link}")
                if conf:
                    try:
                        import qrcode
                        qr = qrcode.QRCode()
                        qr.add_data(conf)
                        qr.print_ascii()
                    except Exception:
                        pass
                if conf:
                    print(f"  {DIM}{'─' * PANEL_W}{NC}")
                    for line in conf.splitlines():
                        print(f"  {DIM}{line}{NC}")
                    print(f"  {DIM}{'─' * PANEL_W}{NC}")
                print()
            continue

        conf = ""
        links = []
        try:
            conf = p.generate_client_config(user, state) or ""
        except Exception:
            pass
        try:
            if hasattr(p, "client_links"):
                links = p.client_links(user, state)
            else:
                l = p.client_link(user, state)
                if l:
                    links = [l]
        except Exception:
            pass
        if not conf and not links:
            continue
        print(f"  {CYAN}── {BOLD}{p.meta.name}{NC}{CYAN}{'─' * (PANEL_W - 10 - len(p.meta.name))}{NC}")
        if links:
            for l in links:
                print(f"  {GREEN}Ссылка:{NC}  {l}")
        if conf:
            print(f"  {DIM}{'─' * PANEL_W}{NC}")
            for line in conf.splitlines():
                print(f"  {DIM}{line}{NC}")
            print(f"  {DIM}{'─' * PANEL_W}{NC}")
        print()

    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  Главное меню
# ═════════════════════════════════════════════════════════════════════════════

def main_menu(state: AppState):
    while True:
        clear()

        sb_ok = singbox_installed() and is_running()
        plugins = status_all()

        active_t = sum(1 for p in transports() if plugins.get(p.meta.name, {}).get("running"))
        total_t = len(transports())

        active_s = sum(1 for p in sec_plugins() if plugins.get(p.meta.name, {}).get("running"))
        total_s = len(sec_plugins())

        u_active = sum(1 for u in state.users if get_user_access_status(u)[0])

        core_status = f"{GREEN}запущен{NC}" if sb_ok else f"{RED}остановлен{NC}"
        core_version = singbox_version() or "не установлен"
        node_lines = [_status_row("🟢" if sb_ok else "🔴", "Sing-Box", core_status, f"· {core_version}")]
        node_lines += _sys_info(state)

        warp_running = bool(plugins.get("warp", {}).get("running"))
        warp_status = f"{GREEN}активен{NC}" if warp_running else f"{DIM}отключён{NC}"
        transport_status = f"{GREEN}{active_t} / {total_t} активны{NC}"
        users_status = f"{GREEN if u_active else YELLOW}{u_active} / {len(state.users)}{NC}"
        security_status = f"{GREEN}{active_s} / {total_s} активны{NC}"

        choice = dashboard_menu(
            [
                ("СОСТОЯНИЕ УЗЛА", node_lines),
                ("СЛУЖБЫ", [
                    "  " + _pad_visible(_service_cell("🐍", "Протоколы", transport_status), 38)
                    + _service_cell("👥", "Пользователи", users_status),
                    "  " + _pad_visible(_service_cell("🛡️", "Безопасность", security_status), 38)
                    + _service_cell("🌐", "WARP", warp_status),
                ]),
                ("ГИДРА СОВЕТУЕТ", [f"💬 {HYDRA_SAYING}"]),
            ],
            [
                ("1", "⚙️  Ядро и система",      "Установка, настройка и обновления"),
                ("2", "🐍 Протоколы",           "Транспортные протоколы и подключения"),
                ("3", "👥 Пользователи",        "Доступ, лимиты и подписки"),
                ("4", "🤖 Telegram-боты",       "Управление ботами"),
                ("5", "📊 Мониторинг",          "Трафик, подключения и журналы"),
                ("6", "🛡️  Безопасность",       f"Fail2ban, Honeypot, IPBan  [{active_s}/{total_s}]"),
                ("7", "🌐 Сетевые службы",      "DNSCrypt, WARP и маршрутизация"),
                ("8", "🧪  Диагностика",        "Доступность, GeoIP и производительность"),
                ("0", "🚪 Выход", ""),
            ],
            banner=BANNER.strip(),
            options_header="УПРАВЛЕНИЕ",
        )

        if choice == "0":
            print(f"\n{GREEN}До свидания! 👋{NC}")
            sys.exit(0)
        elif choice == "1":
            menu_core(state)
        elif choice == "2":
            menu_protocols(state)
        elif choice == "3":
            menu_users(state)
        elif choice == "4":
            menu_telegram(state)
        elif choice == "5":
            menu_monitoring(state)
        elif choice == "6":
            menu_security(state)
        elif choice == "7":
            menu_network_services(state)
        elif choice == "8":
            from hydra.ui.diagnostics import menu_diagnostics
            menu_diagnostics(state)


# ═════════════════════════════════════════════════════════════════════════════
#  1. Ядро и система
# ═════════════════════════════════════════════════════════════════════════════

def menu_core(state: AppState):
    while True:
        state = load_state()
        clear()
        ok_i = singbox_installed()
        ok_r = is_running()
        ver = singbox_version()

        update_available = state.install.get("singbox_update_available", False)
        latest_version = state.install.get("singbox_latest_version", "")

        ver_text = ver or "—"
        if ok_i and update_available:
            ver_text += f" {YELLOW}(Доступно обновление){NC}"

        panel("Sing-Box", [
            kv("Статус:", f"{_ok(ok_r)} {'запущен' if ok_r else 'остановлен'}"),
            kv("Версия:", ver_text),
            kv("Конфиг:", f"{DIM}/etc/sing-box/config.json{NC}"),
            kv("Лог:", f"{DIM}journalctl -u sing-box{NC}"),
        ])

        menu_items = [
            ("1", "📦 Установить Sing-Box Extended" if not ok_i else "🔄 Переустановить",
             "shtorm-7/sing-box-extended"),
            ("2", "▶️  Запустить" if not ok_r else "⏸️  Остановить", ""),
            ("3", "🔄 Применить конфиг",
             "Собрать /etc/sing-box/config.json и перезагрузить"),
            ("4", "🚀 Оптимизировать сеть", "BBR/FQ, TCP/UDP-буферы и очереди в один клик"),
            ("5", "↩️  Откатить оптимизацию сети", "Восстановить параметры до первого применения"),
        ]

        if ok_i:
            if update_available:
                menu_items.append(("6", "🆙 Установить обновление", f"Доступна версия sing-box-extended {latest_version}"))
            else:
                menu_items.append(("X", "🆙 Установить обновления", "Установлена последняя версия sing-box-extended"))

        menu_items.append(("0", "↩ Назад", ""))

        choice = menu(menu_items, "ЯДРО И СИСТЕМА")

        if choice == "0":
            return
        elif choice == "1":
            info("Устанавливаю Sing-Box...")
            if install_singbox(force=ok_i):
                success(f"Sing-Box {singbox_version()} установлен")
                if orchestrator.apply_config(state):
                    success("Конфигурация пересобрана и применена")
                else:
                    warn("Внимание: не удалось автоматически применить конфиг")
            else:
                error("Не удалось установить")
            prompt("Нажмите Enter")
        elif choice == "6" and ok_i and update_available:
            info("Устанавливаю обновление Sing-Box...")
            from hydra.core.singbox import update_kernel
            ok, msg = update_kernel()
            if ok:
                success(msg)
                if orchestrator.apply_config(state):
                    success("Конфигурация пересобрана и применена")
                else:
                    warn("Внимание: не удалось автоматически применить конфиг")
            else:
                error(msg)
            prompt("Нажмите Enter")
        elif choice == "X" and ok_i and not update_available:
            continue
        elif choice == "2":
            if ok_r:
                from hydra.core.singbox import stop
                stop()
                success("Остановлен")
            else:
                if start_singbox():
                    success("Запущен")
                else:
                    error("Не удалось запустить. Проверьте: systemctl status sing-box")
            prompt("Нажмите Enter")
        elif choice == "3":
            info("Пересобираю конфиг...")
            if orchestrator.apply_config(state):
                success("Конфиг применён, Sing-Box перезагружен")
            else:
                error("Ошибка применения конфига")
            prompt("Нажмите Enter")
        elif choice == "4":
            _apply_network_tuning_menu()
        elif choice == "5":
            _rollback_network_tuning_menu()


def _apply_network_tuning_menu() -> None:
    from hydra.core.network_tuning import apply_network_tuning

    if not confirm(
        "Применить оптимальный сетевой профиль HYDRA? Текущие значения будут сохранены",
        default=True,
    ):
        return
    info("Настраиваю сетевой стек VPS...")
    try:
        report = apply_network_tuning()
    except Exception as exc:
        error(f"Не удалось применить сетевой профиль: {exc}")
        prompt("Нажмите Enter")
        return
    changed = sum(1 for item in report["sysctl"].values() if item.get("changed"))
    skipped = sum(1 for item in report["sysctl"].values() if item.get("skipped"))
    lines = [
        f"  Изменено параметров: {GREEN}{changed}{NC}",
        f"  BBR: {_ok(report['bbr_available'])}",
        f"  Постоянный профиль: {DIM}{report['config_path']}{NC}",
    ]
    if skipped:
        lines.append(f"  Не поддерживается ядром: {YELLOW}{skipped}{NC}")
    for message in report["errors"][:5]:
        lines.append(f"  {RED}{message}{NC}")
    panel("Сетевая оптимизация", lines)
    if report["success"]:
        success("Сетевой профиль применён. Перезагрузка не требуется")
    else:
        warn("Профиль применён частично; подробности показаны выше")
    prompt("Нажмите Enter")


def _rollback_network_tuning_menu() -> None:
    from hydra.core.network_tuning import rollback_network_tuning

    if not confirm("Восстановить сетевые параметры до оптимизации?", default=False):
        return
    try:
        report = rollback_network_tuning()
    except Exception as exc:
        error(f"Не удалось откатить сетевой профиль: {exc}")
        prompt("Нажмите Enter")
        return
    if report["success"]:
        success(f"Восстановлено параметров: {report['restored']}")
    else:
        error("Не удалось полностью откатить сетевой профиль")
        for message in report["errors"]:
            warn(message)
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  2. Протоколы — разбиты по категориям
# ═════════════════════════════════════════════════════════════════════════════

def menu_protocols(state: AppState):
    while True:
        clear()
        st = status_all()

        transport_lines = []
        for p in transports():
            s = st.get(p.meta.name, {})
            port = str(s["port"]) if s.get("port") else "—"
            transport_lines.append(
                f"  {status_badge(s)}  {protocol_label(p.meta.name):<16} "
                f"{DIM}порт {port}{NC}"
            )

        lines = [
            f"  {BOLD}Транспортные протоколы{NC}",
            *transport_lines,
        ]
        panel("Протоколы · обзор", lines)

        all_p = transports()
        opts: list[tuple[str, str, str]] = []
        for i, p in enumerate(all_p, 1):
            s = st.get(p.meta.name, {})
            badge = status_badge(s)
            desc = s.get("error") or p.meta.description
            opts.append((str(i),
                         f"{badge}  {protocol_label(p.meta.name)}",
                         desc))
        opts += [("-", "", ""), ("0", "↩ Назад", "")]

        choice = menu(opts, "ПРОТОКОЛЫ · УПРАВЛЕНИЕ")
        if choice == "0":
            return
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(all_p):
                    p = all_p[idx]
                    menu_plugin(state, p)
            except ValueError:
                pass


def menu_network_services(state: AppState):
    while True:
        clear()
        st = status_all()

        enhancement_lines = []
        for p in enhancements():
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}●{NC}" if s.get("running") else (f"{YELLOW}●{NC}" if s.get("installed") else f"{DIM}●{NC}")
            port = f":{s['port']}" if s.get("port") else ""
            st_txt = "вкл" if s.get("enabled") else "выкл"
            enhancement_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{st_txt:>4}{NC}  порт{port}")

        lines = [
            f"  {BOLD}Сетевые службы (DNS / Маршрутизация):{NC}",
            *enhancement_lines,
        ]
        panel("Сетевые службы", lines)

        all_p = enhancements()
        opts: list[tuple[str, str, str]] = []
        for i, p in enumerate(all_p, 1):
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}✓{NC}" if s.get("running") else (f"{YELLOW}⚠{NC}" if s.get("installed") else f"{RED}✗{NC}")
            opts.append((str(i),
                         f"{ico} {p.meta.name}",
                         f"{p.meta.description}"))
        opts += [("-", "", ""), ("0", "↩ Назад", "")]

        choice = menu(opts, "СЕТЕВЫЕ СЛУЖБЫ")
        if choice == "0":
            return
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(all_p):
                    p = all_p[idx]
                    menu_plugin(state, p)
            except ValueError:
                pass


def menu_plugin(state: AppState, p):
    """Универсальное меню плагина."""
    if p.meta.name == "amneziawg":
        _menu_amneziawg(state, p)
        return
    if p.meta.name == "anytls":
        _menu_anytls(state, p)
        return
    if p.meta.name == "mieru":
        _menu_mieru(state, p)
        return
    if p.meta.name == "trusttunnel":
        _menu_trusttunnel(state, p)
        return
    if p.meta.name == "dnscrypt":
        from hydra.plugins.dnscrypt.manager import menu_dnscrypt
        menu_dnscrypt(state, p)
        return
    if p.meta.name == "fail2ban":
        from hydra.plugins.fail2ban.manager import menu_fail2ban
        menu_fail2ban(state, p)
        return
    if p.meta.name == "ipban":
        from hydra.plugins.ipban.manager import menu_ipban
        menu_ipban(state, p)
        return
    if p.meta.name == "honeypot":
        from hydra.plugins.honeypot.manager import menu_honeypot
        menu_honeypot(state, p)
        return
    if p.meta.name == "warp":
        from hydra.plugins.warp.manager import menu_warp
        menu_warp(state, p)
        return
    if p.meta.name == "telemt":
        from hydra.plugins.telemt.manager import menu_telemt
        menu_telemt(state, p)
        return
    if p.meta.name == "wdtt":
        from hydra.plugins.wdtt.manager import menu_wdtt
        menu_wdtt(state, p)
        return

    from hydra.core.state import get_protocol
    
    while True:
        clear()
        ps = get_protocol(state, p.meta.name)
        
        # Единая карточка статуса для протоколов без собственного менеджера.
        try:
            st = p.status()
            protocol_status_panel(
                p.meta.name,
                installed=st.installed,
                enabled=st.enabled,
                running=st.running,
                port=st.port,
                details=(st.info or {}).items(),
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name,
                installed=ps.installed,
                enabled=ps.enabled,
                running=False,
                port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )
        
        # Опции зависят от состояния
        options = []
        
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))
            
            # Для TRANSPORT-плагинов: показать подключённых клиентов
            if p.meta.category == PluginCategory.TRANSPORT and ps.enabled:
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
            
            # Для NaiveProxy — пункт смены транспорта
            if p.meta.name == "naive" and ps.enabled:
                current_net = ps.config.get("network", "tcp") if ps.config else "tcp"
                net_label = {"tcp": "HTTP/2", "quic": "QUIC", "both": "HTTP/2+QUIC"}.get(current_net, current_net)
                options.append(("3", "🔀 Сменить транспорт", f"Текущий: {net_label}"))

            if p.meta.name == "shadowtls":
                current_sni = ps.config.get("handshake_sni", "не выбран") if ps.config else "не выбран"
                options.append(("3", "🌐 Сменить SNI", f"Текущий: {current_sni}"))

            if p.meta.name in {"hysteria2", "snell"}:
                options.append(("3", "⚙️  Настройки", "Параметры транспорта и обфускации"))

            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))
        
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, protocol_menu_title(p.meta.name))
        
        if choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if orchestrator.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error("Ошибка применения конфигурации")
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if orchestrator.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error("Ошибка применения конфигурации")
            else:
                try:
                    if orchestrator.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error("Ошибка применения конфигурации")
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")
        
        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)
        
        elif choice == "3" and p.meta.name == "naive" and ps.enabled:
            mode_choice = menu([
                ("1", "HTTP/2 (TCP)", "Стандартный режим, максимальная совместимость"),
                ("2", "QUIC (UDP)", "HTTP/3 через UDP, может быть быстрее"),
                ("3", "HTTP/2 + QUIC", "Оба транспорта одновременно"),
                ("0", "↩ Отмена", ""),
            ], header="Транспорт NaiveProxy")
            if mode_choice != "0":
                mode_map = {"1": "tcp", "2": "quic", "3": "both"}
                new_mode = mode_map.get(mode_choice)
                if new_mode:
                    if p.set_transport(state, new_mode):
                        success(f"Транспорт изменён на {new_mode}")
                    else:
                        error(
                            "Не удалось применить транспорт. Возможно, UDP/443 уже "
                            "занят TrustTunnel QUIC; прежний режим восстановлен."
                        )
                    prompt("Нажмите Enter")

        elif choice == "3" and p.meta.name == "shadowtls" and ps.installed:
            new_sni = p.choose_handshake_sni()
            if new_sni:
                try:
                    if p.set_handshake_sni(state, new_sni):
                        success(f"SNI ShadowTLS изменён на {new_sni}")
                    else:
                        error("Не удалось применить SNI; прежняя конфигурация восстановлена")
                except ValueError as exc:
                    error(str(exc))
            prompt("Нажмите Enter")

        elif choice == "3" and p.meta.name == "hysteria2" and ps.installed:
            _menu_hysteria2_settings(state, p)

        elif choice == "3" and p.meta.name == "snell" and ps.installed:
            _menu_snell_settings(state, p)

        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = orchestrator.reinstall_plugin(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка переустановки")
                prompt("Нажмите Enter")
        
        elif choice == "9" and ps.installed:
            if confirm(f"Удалить {p.meta.name}?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return
        
        elif choice == "0":
            return


def _menu_hysteria2_settings(state: AppState, plugin) -> None:
    """Runtime-safe Hysteria2 settings editor."""
    from hydra.core.state import get_protocol
    from hydra.utils.crypto import gen_token

    while True:
        ps = get_protocol(state, "hysteria2")
        mode = ps.config.get("congestion_mode", "bbr")
        bandwidth = ""
        if mode == "brutal":
            bandwidth = f" · {ps.config.get('up_mbps', 100)}/{ps.config.get('down_mbps', 100)} Mbps"
        choice = menu([
            ("1", "🌐 Домен и TLS", ps.config.get("domain", "не задан")),
            ("2", "🔌 UDP-порт", str(ps.config.get("port", 8443))),
            ("3", "🚀 Congestion control", f"{str(mode).upper()}{bandwidth}"),
            ("4", "🔑 Сменить Salamander-пароль", "Клиентские ссылки обновятся"),
            ("0", "↩ Назад", ""),
        ], "НАСТРОЙКИ HYSTERIA2")
        if choice == "0":
            return
        try:
            if choice == "1":
                domain = prompt("Новый домен Hysteria2", default=ps.config.get("domain", ""))
                if domain and plugin.set_domain(state, domain):
                    success("Домен и TLS-сертификат обновлены")
                elif domain:
                    error("Не удалось применить домен; прежняя конфигурация восстановлена")
            elif choice == "2":
                value = prompt("Новый UDP-порт", default=str(ps.config.get("port", 8443)))
                if plugin.set_port(state, int(value)):
                    success("UDP-порт обновлён")
                else:
                    error("Не удалось применить порт; прежняя конфигурация восстановлена")
            elif choice == "3":
                selected = menu([
                    ("1", "BBR", "Автоматическая оценка пропускной способности"),
                    ("2", "Brutal", "Явно заданные upload/download Mbps"),
                    ("0", "Отмена", ""),
                ], "CONGESTION CONTROL HYSTERIA2")
                if selected == "1":
                    ok = plugin.set_congestion(state, "bbr")
                elif selected == "2":
                    up = int(prompt("Upload Mbps", default=str(ps.config.get("up_mbps", 100))))
                    down = int(prompt("Download Mbps", default=str(ps.config.get("down_mbps", 100))))
                    ok = plugin.set_congestion(state, "brutal", up, down)
                else:
                    continue
                success("Congestion control обновлён") if ok else error(
                    "Не удалось применить режим; прежняя конфигурация восстановлена"
                )
            elif choice == "4":
                value = prompt(
                    "Новый пароль (пусто = сгенерировать)", default="",
                ).strip() or gen_token(24)
                if plugin.set_obfs_password(state, value):
                    success("Salamander-пароль обновлён")
                else:
                    error("Не удалось сменить пароль; прежняя конфигурация восстановлена")
        except (TypeError, ValueError) as exc:
            error(str(exc))
        prompt("Нажмите Enter")


def _menu_snell_settings(state: AppState, plugin) -> None:
    """Runtime-safe Snell simple-obfs editor."""
    from hydra.core.state import get_protocol

    while True:
        ps = get_protocol(state, "snell")
        version = plugin._version(state)
        mode = str(ps.config.get("obfs_mode", "http"))
        host = str(ps.config.get("obfs_host", "www.bing.com"))
        choice = menu([
            ("1", "🎭 Simple obfs", f"{mode.upper()} · {host}" if mode else "выключен"),
            ("0", "↩ Назад", ""),
        ], f"НАСТРОЙКИ SNELL v{version}")
        if choice == "0":
            return
        try:
            if choice == "1":
                selected = menu([
                    ("1", "HTTP obfs", "Имитация HTTP-трафика"),
                    ("2", "Выключить", "Чистый Snell без simple-obfs"),
                    ("0", "Отмена", ""),
                ], "SIMPLE OBFS SNELL")
                new_mode = {"1": "http", "2": ""}.get(selected)
                if new_mode is None:
                    continue
                new_host = host
                if new_mode:
                    new_host = prompt("Маскировочный host", default=host)
                ok = plugin.set_settings(state, version, new_mode, new_host)
            else:
                continue
            success("Настройки Snell обновлены") if ok else error(
                "Не удалось применить настройки; прежняя конфигурация восстановлена"
            )
        except (TypeError, ValueError) as exc:
            error(str(exc))
        prompt("Нажмите Enter")


def _show_plugin_clients(state: AppState, p):
    """Показывает подключённых клиентов и трафик для протокола с двойными рамками."""
    clear()
    
    try:
        # Безопасно проверяем, поддерживает ли метод connected_clients передачу state
        import inspect
        sig = inspect.signature(p.connected_clients)
        if "state" in sig.parameters or len(sig.parameters) > 0:
            clients = p.connected_clients(state)
        else:
            clients = p.connected_clients()
            
        traffic = p.traffic(state)
        
        box_lines = []
        
        # Сводные показатели
        total_clients = len(clients) if clients else len(traffic) if traffic else 0
        online_clients = sum(1 for c in clients if c.get("online")) if clients else 0
        total_rx = sum(c.get("rx", 0) for c in clients) if clients else 0
        total_tx = sum(c.get("tx", 0) for c in clients) if clients else 0
        
        if not clients and not traffic:
            box_lines.append(f"{YELLOW}Нет активных клиентов или трафика{NC}")
        else:
            if clients:
                box_lines.append(f"{BOLD}{WHITE}Активные сессии:{NC}")
                now_ts = int(datetime.now().timestamp())
                for c in clients:
                    status = f"{GREEN}🟢{NC}" if c.get("online") else f"{RED}🔴{NC}"
                    email = c.get("email", "?")
                    rx = _bytes_auto(c.get("rx", 0))
                    tx = _bytes_auto(c.get("tx", 0))
                    
                    # Форматируем время последнего хендшейка
                    handshake = c.get("last_handshake", 0)
                    if handshake == 0:
                        activity = f"{DIM}не активен{NC}"
                    else:
                        diff = now_ts - handshake
                        if diff < 10:
                            activity = f"{GREEN}активен{NC}"
                        elif diff < 60:
                            activity = f"{GREEN}только что{NC}"
                        elif diff < 3600:
                            activity = f"{GREEN}{diff // 60} мин. назад{NC}"
                        elif diff < 86400:
                            activity = f"{DIM}{diff // 3600} ч. назад{NC}"
                        else:
                            activity = f"{DIM}{diff // 86400} дн. назад{NC}"
                            
                    box_lines.append(f"  {status} {BOLD}{email:<18}{NC}  ↓{rx:<9} ↑{tx:<9}  {activity}")
            elif traffic:
                box_lines.append(f"{BOLD}{WHITE}Статистика трафика:{NC}")
                for email, bytes_total in traffic.items():
                    box_lines.append(f"  {BOLD}{email:<20}{NC}  {_bytes_auto(bytes_total)}")
            
            # Добавляем сводный блок трафика
            box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")
            box_lines.append(f"{BOLD}{WHITE}СВОДНАЯ СТАТИСТИКА ПОТОКА:{NC}")
            box_lines.append(f"  Всего клиентов:  {total_clients}")
            if clients:
                box_lines.append(f"  В сети (online): {GREEN}{online_clients}{NC}")
                box_lines.append(f"  Получено (RX):   {GREEN}{_bytes_auto(total_rx)}{NC}")
                box_lines.append(f"  Отправлено (TX): {GREEN}{_bytes_auto(total_tx)}{NC}")
                box_lines.append(f"  Общий трафик:    {CYAN}{_bytes_auto(total_rx + total_tx)}{NC}")
                
        panel(f"👥  КЛИЕНТЫ: {p.meta.name.upper()}", box_lines)
    except Exception as e:
        error(f"Ошибка получения клиентов: {e}")
    
    print()
    prompt("Нажмите Enter")





# ═════════════════════════════════════════════════════════════════════════════
#  3. Пользователи — полностью переработано
# ═════════════════════════════════════════════════════════════════════════════

def menu_users(state: AppState):
    """Управление пользователями."""
    while True:
        clear()
        title("Пользователи")
        
        # Показать краткую сводку
        total = len(state.users)
        active = sum(1 for u in state.users if get_user_access_status(u)[0])
        restricted = total - active
        info(f"Всего: {total}  |  Активных: {active}  |  Ограничено: {restricted}")
        print()
        
        choice = menu([
            ("1", "📋 Список пользователей", "Просмотр всех пользователей"),
            ("2", "👤 Добавить пользователя", "Создать нового пользователя"),
            ("3", "🔧  Управление пользователем", "Конфиги, блокировка, удаление"),
            ("4", "🔗 Сервер подписок", "Управление фоновым сервисом подписок"),
            ("0", "↩ Назад", ""),
        ], "ПОЛЬЗОВАТЕЛИ")
        
        if choice == "1":
            _show_users(state)
        elif choice == "2":
            _add_user(state)
        elif choice == "3":
            user = _select_user(state)
            if user:
                _user_detail_menu(state, user)
        elif choice == "4":
            menu_subscription_server(state)
        elif choice == "0":
            return


def _user_detail_menu(state: AppState, user: User):
    """Детальное меню пользователя с конфигами и управлением."""
    while True:
        clear()
        update_user_traffic(state)
        
        # Панель информации о пользователе
        available, access_reason = get_user_access_status(user)
        status_icon = f"{GREEN}🟢{NC}" if available else f"{RED}🔴{NC}"
        lim_str = f"{user.traffic_limit_gb:g} GiB" if user.traffic_limit_gb else "∞"
        ttl_str = user.expiry_date[:10] if user.expiry_date else "∞"
        lines = [
            kv("Статус:", f"{status_icon} {access_reason}"),
            kv("Трафик:", f"{_bytes_auto(user.traffic_used_bytes)} / {lim_str}"),
            kv("Действует до:", ttl_str),
            kv("Создан:", user.created_at[:10] if user.created_at else "—"),
        ]
        
        panel(f"Пользователь: {user.email}", lines)
        print()
        
        # Показать доступные протоколы
        from hydra.plugins import registry
        enabled_transports = [
            p for p in registry.enabled(state, PluginCategory.TRANSPORT)
            if p.meta.name != "wdtt"
        ]
        if enabled_transports:
            proto_names = ", ".join(p.meta.name for p in enabled_transports)
            info(f"Включённые протоколы: {proto_names}")
        else:
            warn("Нет включённых транспортных протоколов")
        print()
        
        block_label = "Разблокировать" if user.blocked else "Заблокировать"
        
        choice = menu([
            ("1", "🔗 Ссылки подписки", "Автоопределение клиента и специальные форматы"),
            ("2", "📄 Ручные конфиги", "Ссылки и конфиги отдельных протоколов"),
            ("3", f"🔒🔓 {block_label}", "Переключить статус блокировки"),
            ("4", "📝 Изменить лимит трафика", "Задать квоту трафика в GiB"),
            ("5", "⏳ Изменить срок действия", "Задать дату окончания подписки"),
            ("6", "❌ Удалить", "Удалить пользователя"),
            ("0", "↩ Назад", ""),
        ], f"ПОЛЬЗОВАТЕЛЬ {user.email}")
        
        if choice == "1":
            _show_subscription_links(state, user)
        elif choice == "2":
            _user_configs(state, user)
        elif choice == "3":
            _toggle_block(state, user)
        elif choice == "4":
            new_lim = prompt("Введите лимит трафика в GiB (0 или пусто для безлимита)", default=str(user.traffic_limit_gb or ""))
            try:
                val = float(new_lim) if new_lim.strip() else 0.0
                if not math.isfinite(val) or val < 0:
                    raise ValueError
                user.traffic_limit_gb = val
                save_state(state)
                success(f"Лимит трафика: {f'{val:g} GiB' if val else 'без ограничений'}")
                _reconcile_user_access(state, user)
                prompt("Нажмите Enter")
            except ValueError:
                error("Лимит должен быть неотрицательным конечным числом.")
                prompt("Нажмите Enter")
        elif choice == "5":
            curr_ttl = user.expiry_date[:10] if user.expiry_date else ""
            new_exp = prompt("Введите срок действия подписки (ГГГГ-ММ-ДД, или пусто для безлимита)", default=curr_ttl)
            if not new_exp.strip():
                user.expiry_date = ""
                save_state(state)
                success(f"Подписка для {user.email} сделана бессрочной")
            else:
                try:
                    datetime.strptime(new_exp.strip(), "%Y-%m-%d")
                    user.expiry_date = f"{new_exp.strip()}T23:59:59Z"
                    save_state(state)
                    success(f"Срок действия подписки для {user.email} установлен до {new_exp.strip()}")
                except ValueError:
                    error("Неверный формат даты! Используйте ГГГГ-ММ-ДД.")
                    prompt("Нажмите Enter")
                    continue
            _reconcile_user_access(state, user)
            prompt("Нажмите Enter")
        elif choice == "6":
            if confirm(f"Удалить {user.email}?", default=False):
                orchestrator.remove_user(state, user.email)
                success(f"Пользователь {user.email} удалён")
                prompt("Нажмите Enter")
                return
        elif choice == "0":
            return


def _reconcile_user_access(state: AppState, user: User) -> None:
    """Немедленно применяет новые TTL/квоту к серверным конфигурациям."""
    entitled, reason = get_user_entitlement_status(user)
    if not entitled and not user.blocked:
        orchestrator.block_user(state, user.email)
        warn(f"Доступ отключён: {reason}.")
    elif entitled and user.blocked:
        if confirm("Ограничения больше не превышены. Разблокировать пользователя?", default=True):
            orchestrator.unblock_user(state, user.email)
            success("Пользователь разблокирован")


def install_sub_systemd_service(state: AppState) -> bool:
    """Генерирует и записывает systemd-юнит для сервера подписок."""
    install_dir = "/opt/hydra"
    for candidate in ("/opt/hydra", "/opt/HYDRA-ULTIMATE", "/root/HYDRA-ULTIMATE"):
        if Path(candidate).exists():
            install_dir = candidate
            break
            
    host = "127.0.0.1" if getattr(state.network, "sub_domain", "") else "0.0.0.0"
    content = f"""[Unit]
Description=HYDRA Subscription Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory={install_dir}
Environment=PYTHONPATH={install_dir}
ExecStart=/usr/bin/python3 -m hydra.services.subscriptions.generator --host {host} --port 9443
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    return install_service("hydra-sub", content)


def _obtain_cert_for_sub(state: AppState) -> bool:
    sub_domain = getattr(state.network, "sub_domain", "")
    if not sub_domain:
        error("Сначала настройте домен подписок.")
        return False

    # Проверяем, есть ли уже валидный сертификат
    from pathlib import Path
    cert_path = Path(f"/etc/letsencrypt/live/{sub_domain}/fullchain.pem")
    key_path = Path(f"/etc/letsencrypt/live/{sub_domain}/privkey.pem")
    if cert_path.exists() and key_path.exists():
        try:
            r = subprocess.run(
                ["openssl", "x509", "-checkend", "2592000", "-noout", "-in", str(cert_path)],
                capture_output=True
            )
            if r.returncode == 0:
                success(f"Сертификат для {sub_domain} уже существует и действителен.")
                return True
        except Exception:
            pass
        
    info(f"Получение SSL-сертификата для {sub_domain} через certbot...")
    import shutil
    if not shutil.which("certbot"):
        info("Установка certbot...")
        subprocess.run(["apt-get", "update"], capture_output=True)
        subprocess.run(["apt-get", "install", "-y", "certbot"], capture_output=True)
        
    services_to_stop = ["haproxy", "caddy-naive", "nginx", "apache2"]
    was_running = []
    for s in services_to_stop:
        r = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True)
        if r.stdout.strip() == "active":
            info(f"Временно останавливаем {s} для освобождения порта 80...")
            subprocess.run(["systemctl", "stop", s])
            was_running.append(s)
        
    subprocess.run(["ufw", "allow", "80/tcp"], capture_output=True)
    
    r = subprocess.run([
        "certbot", "certonly", "--standalone",
        "-d", sub_domain,
        "--non-interactive", "--agree-tos",
        "--register-unsafely-without-email",
        "--keep-until-expiring",
    ], capture_output=True, text=True)
    
    for s in reversed(was_running):
        info(f"Запускаем {s} обратно...")
        subprocess.run(["systemctl", "start", s])
        
    if r.returncode == 0:
        success("Сертификат успешно получен!")
        return True
    else:
        error("Ошибка работы certbot!")
        if r.stderr or r.stdout:
            print(f"Вывод: {r.stderr or r.stdout}")
        return False


def menu_subscription_server(state: AppState):
    """Управление сервером подписок."""
    from hydra.core.systemd import is_active as is_svc_active, start, stop, restart
    from hydra.services.subscriptions.generator import find_any_cert
    
    while True:
        clear()
        title("Сервер подписок")
        
        active = is_svc_active("hydra-sub")
        status_str = f"{GREEN}🟢 АКТИВЕН{NC}" if active else f"{RED}🔴 НЕ АКТИВЕН{NC}"
        
        cert_file, key_file = find_any_cert(state)
        cert_status = f"{GREEN}Установлен ({cert_file}){NC}" if cert_file else f"{RED}Отсутствует (Необходим для HTTPS!){NC}"
        
        sub_domain = getattr(state.network, "sub_domain", "")
        domain_status = f"{CYAN}{sub_domain}{NC}" if sub_domain else f"{YELLOW}[НЕ НАСТРОЕН] (Используется IP){NC}"
        
        from hydra.utils.net import public_ip
        host = sub_domain or state.network.domain or state.network.server_ip or public_ip()
        base_url = f"https://{host}"
        if not sub_domain:
            base_url += ":9443"
        base_url += "/sub/<UUID>"
        
        lines = [
            kv("Статус службы:", status_str),
            kv("Домен подписок:", domain_status),
            kv("SSL-сертификат:", cert_status),
            kv("Базовый URL:", f"{CYAN}{base_url}{NC}"),
        ]
        panel("СОСТОЯНИЕ СЕРВЕРА", lines)
        print()
        
        opts = [
            ("1", "▶️  Запустить / Включить автозапуск", "Запустить службу hydra-sub"),
            ("2", "⏹️  Остановить / Отключить автозапуск", "Остановить службу hydra-sub"),
            ("3", "🔄 Перезапустить", "Перезапустить службу hydra-sub"),
            ("4", "🌐 Настроить домен подписок", ""),
        ]
        
        if sub_domain and not cert_file:
            opts.append(("5", "🔑 Получить SSL-сертификат через Certbot", "Standalone HTTP challenge"))
            
        opts.append(("0", "↩ Назад", ""))
        
        choice = menu(opts, "СЕРВЕР ПОДПИСОК")
        
        if choice == "0":
            return
        elif choice == "1":
            if not cert_file:
                error("Нельзя запустить сервер подписок без SSL-сертификата!")
                prompt("Нажмите Enter")
                continue
                
            install_sub_systemd_service(state)
            if start("hydra-sub"):
                success("Служба hydra-sub успешно запущена")
            else:
                error("Не удалось запустить службу. Проверьте systemctl status hydra-sub")
            prompt("Нажмите Enter")
            
        elif choice == "2":
            if stop("hydra-sub"):
                subprocess.run(["systemctl", "disable", "hydra-sub"], capture_output=True)
                success("Служба hydra-sub остановлена и отключена из автозапуска")
            else:
                error("Не удалось остановить службу")
            prompt("Нажмите Enter")
            
        elif choice == "3":
            if not cert_file:
                error("Нельзя перезапустить сервер подписок без SSL-сертификата!")
                prompt("Нажмите Enter")
                continue
            if restart("hydra-sub"):
                success("Служба hydra-sub успешно перезапущена")
            else:
                error("Не удалось перезапустить службу")
            prompt("Нажмите Enter")
            
        elif choice == "4":
            new_domain = prompt("Введите выделенный домен подписок (например, sub.example.com)", default=sub_domain)
            state.network.sub_domain = new_domain.strip()
            save_state(state)
            
            from hydra.core import sni_router
            sni_router.rebuild(state)
            
            success(f"Домен подписок обновлён: {new_domain}")
            install_sub_systemd_service(state)
            prompt("Нажмите Enter")
            
        elif choice == "5" and sub_domain and not cert_file:
            if _obtain_cert_for_sub(state):
                from hydra.core import sni_router
                sni_router.rebuild(state)
                restart("hydra-sub")
            prompt("Нажмите Enter")


def _show_subscription_links(state: AppState, user: User) -> None:
    """Показывает каноническую подписку отдельно от ручных конфигов."""
    clear()
    title(f"Подписка: {user.email}")
    urls = get_subscription_urls(user, state)
    available, reason = get_user_access_status(user)
    panel("ДОСТУП", [
        kv("Статус:", f"{GREEN if available else RED}{reason}{NC}"),
        kv("Обновление:", "каждые 6 часов"),
    ])
    print()
    print(f"  {BOLD}Основная ссылка (рекомендуется){NC}")
    print(f"  {DIM}NekoBox и Throne определяются автоматически по приложению.{NC}")
    print(f"  {CYAN}{urls['auto']}{NC}\n")
    print(f"  {BOLD}Ручной выбор формата{NC}")
    print(f"  NekoBox:       {CYAN}{urls['nekobox']}{NC}")
    print(f"  Throne:        {CYAN}{urls['throne']}{NC}")
    print(f"  Sing-Box JSON: {CYAN}{urls['singbox']}{NC}")
    print(f"\n  {DIM}Ссылка содержит секретный токен — передавайте её только владельцу.{NC}")
    prompt("Нажмите Enter")


def _user_configs(state: AppState, user: User):
    """Показывает конфиги и ссылки для всех протоколов."""
    clear()
    title(f"Конфигурации для пользователя: {user.email}")
    
    # Проверка наличия qrcode
    try:
        import qrcode
    except ImportError:
        warn("Библиотека qrcode не установлена, QR-коды не будут отображаться.")
        info("Установите её командой: pip3 install qrcode")
        print()

    from hydra.plugins import registry
    enabled_transports = [
        p for p in registry.enabled(state, PluginCategory.TRANSPORT)
        if p.meta.name != "wdtt"
    ]
    
    if not enabled_transports:
        warn("Нет включённых транспортных протоколов")
        prompt("Нажмите Enter")
        return
    
    for p in enabled_transports:
        # Ссылки
        links = []
        try:
            if hasattr(p, "client_links"):
                links = p.client_links(user, state)
            else:
                l = p.client_link(user, state)
                if l:
                    links = [l]
        except Exception:
            pass
            
        # Конфиг
        try:
            if p.meta.name == "telemt":
                from hydra.plugins.telemt.plugin import TelemtPlugin
                from hydra.plugins.telemt.telemt_ios_fix import status as ios_status
                from hydra.utils.net import public_ip
                
                ps = state.protocols.setdefault("telemt", state.protocols.get("telemt") or PluginState())
                cfg = ps.config or {}
                port = cfg.get("port", 8443)
                domain = cfg.get("tls_domain")
                if domain is None:
                    domain = state.network.domain
                
                secret = TelemtPlugin._derive_secret(user.uuid)
                server_ip = state.network.server_ip or public_ip()
                tls_secret = TelemtPlugin._make_tls_secret(secret, domain) if domain else secret
                
                box_lines = []
                box_lines.append(f"{YELLOW}{BOLD}Основная ссылка (ПК/Android):{NC}")
                link_main = f"tg://proxy?server={server_ip}&port={port}&secret={tls_secret}"
                link_width = PANEL_W - 6
                for chunk in [link_main[i:i+link_width] for i in range(0, len(link_main), link_width)]:
                    box_lines.append(f"  {CYAN}{chunk}{NC}")
                
                try:
                    ios_st = ios_status()
                    if ios_st.get("enabled"):
                        box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")
                        box_lines.append(f"{YELLOW}{BOLD}Ссылка с iOS-фиксом (порт {ios_st['ext_port']}):{NC}")
                        link_ios = f"tg://proxy?server={server_ip}&port={ios_st['ext_port']}&secret={tls_secret}"
                        for chunk in [link_ios[i:i+link_width] for i in range(0, len(link_ios), link_width)]:
                            box_lines.append(f"  {CYAN}{chunk}{NC}")
                except Exception:
                    pass
                
                panel(f"🔧  {p.meta.name.upper()} CONFIG", box_lines)
                
                continue

            if p.meta.name == "amneziawg":
                ps = state.protocols.get("amneziawg")
                has_mobile = ps and "profiles" in ps.config and "mobile" in ps.config["profiles"]
                profiles = ["desktop"]
                if has_mobile:
                    profiles.append("mobile")

                for prof in profiles:
                    link_prof = ""
                    vpn_link = ""
                    try:
                        link_prof = p.client_link(user, state, profile=prof)
                    except Exception:
                        pass
                    try:
                        vpn_link = p.amnezia_link(user, state, profile=prof)
                    except Exception:
                        pass
                    
                    try:
                        conf = p.generate_client_config(user, state, profile=prof)
                        if conf:
                            box_lines = []
                            label_ru = "ПК / Desktop" if prof == "desktop" else "Смартфон / Mobile"
                            link_width = PANEL_W - 6
                            
                            # Показываем WireGuard/AmneziaWG ссылку
                            if link_prof:
                                box_lines.append(f"{YELLOW}{BOLD}Ссылка для подключения (WireGuard / URL - {label_ru}):{NC}")
                                for chunk in [link_prof[i:i+link_width] for i in range(0, len(link_prof), link_width)]:
                                    box_lines.append(f"  {CYAN}{chunk}{NC}")
                                box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")

                            if vpn_link and vpn_link != link_prof:
                                box_lines.append(f"{YELLOW}{BOLD}Импорт в AmneziaVPN:{NC}")
                                for chunk in [vpn_link[i:i+link_width] for i in range(0, len(vpn_link), link_width)]:
                                    box_lines.append(f"  {CYAN}{chunk}{NC}")
                                box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")

                            
                            # Показываем конфиг
                            box_lines.append(f"{GREEN}{BOLD}Файл конфигурации (Client Config - {label_ru}):{NC}")
                            for line in conf.splitlines():
                                box_lines.append(f"  {DIM}{line.rstrip()}{NC}")
                            
                            panel(f"🔧  {p.meta.name.upper()} {prof.upper()} CONFIG", box_lines)
                            
                            # QR-код (если qrcode установлен)
                            try:
                                import qrcode
                                qr = qrcode.QRCode(border=1)
                                qr.add_data(conf)
                                print(f"\n  {BOLD}{WHITE}Отсканируйте QR-код для быстрого импорта ({label_ru}):{NC}")
                                qr.print_ascii(invert=True)
                            except Exception as e:
                                error(f"  Не удалось создать QR-код: {e}")
                    except Exception as e:
                        error(f"  Ошибка получения конфигурации {p.meta.name} ({prof}): {e}")
                continue

            conf = p.generate_client_config(user, state)
            if conf or links:
                box_lines = []
                
                # Показываем ссылку, если она есть
                if links:
                    label = "Ссылки для подключения (URL):" if len(links) > 1 else "Ссылка для подключения (URL):"
                    box_lines.append(f"{YELLOW}{BOLD}{label}{NC}")
                    # Оборачиваем ссылку по ширине коробки (PANEL_W - 6)
                    link_width = PANEL_W - 6
                    for idx, l in enumerate(links):
                        if idx > 0:
                            box_lines.append(f"  {DIM}{'┄' * (PANEL_W - 8)}{NC}")
                        for chunk in [l[i:i+link_width] for i in range(0, len(l), link_width)]:
                            box_lines.append(f"  {CYAN}{chunk}{NC}")
                    box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")
                
                if conf:
                    box_lines.append(f"{GREEN}{BOLD}Файл конфигурации (Client Config):{NC}")
                    for line in conf.splitlines():
                        box_lines.append(f"  {DIM}{line.rstrip()}{NC}")
                
                panel(f"🔧  {p.meta.name.upper()} CONFIG", box_lines)
                

        except Exception as e:
            error(f"  Ошибка получения конфигурации {p.meta.name}: {e}")
            
    print()
    prompt("Нажмите Enter")


def _show_users(state: AppState):
    clear()
    if not state.users:
        warn("Нет пользователей.")
        prompt("Нажмите Enter")
        return
    title("Список пользователей")
    print()
    update_user_traffic(state)
    print(f"  {BOLD}{'Пользователь':<30} {'Статус':<17} {'Трафик':>20} {'Действует до':>12}{NC}")
    print(f"  {DIM}{'─' * 83}{NC}")
    for u in sorted(state.users, key=lambda item: item.email.casefold()):
        available, reason = get_user_access_status(u)
        color = GREEN if available else RED
        limit = f"{u.traffic_limit_gb:g} GiB" if u.traffic_limit_gb else "∞"
        traffic = f"{_bytes_auto(u.traffic_used_bytes)} / {limit}"
        expiry = u.expiry_date[:10] if u.expiry_date else "∞"
        print(
            f"  {color}{'●'}{NC} {BOLD}{u.email:<28}{NC} "
            f"{color}{reason:<17}{NC} {traffic:>20} {expiry:>12}"
        )
    print()
    prompt("Нажмите Enter")


def _add_user(state: AppState):
    """Добавление нового пользователя с автогенерацией конфигов."""
    clear()
    title("Добавить пользователя")
    
    # Показать какие протоколы создадут конфиги
    from hydra.plugins import registry
    enabled_transports = [
        p for p in registry.enabled(state, PluginCategory.TRANSPORT)
        if p.meta.name != "wdtt"
    ]
    
    if enabled_transports:
        proto_names = ", ".join(p.meta.name for p in enabled_transports)
        info(f"Конфиги будут созданы для: {proto_names}")
    else:
        warn("Нет включённых протоколов — конфиги не будут созданы")
    print()
    
    email = prompt("Email пользователя").strip().lower()
    if not email:
        return
    if not re.fullmatch(r"[^\s@]+@[^\s@]+", email):
        error("Введите корректный email без пробелов.")
        prompt("Нажмите Enter")
        return
    
    # Проверка дубликата
    if any(existing.email.casefold() == email.casefold() for existing in state.users):
        error(f"Пользователь {email} уже существует")
        prompt("Нажмите Enter")
        return
    
    user = User(
        email=email,
        uuid=str(_uuid.uuid4()),
        created_at=datetime.now().isoformat(),
    )
    
    orchestrator.add_user(state, user)
    
    success(f"Пользователь {email} создан")
    if enabled_transports:
        success(f"Конфиги сгенерированы для {len(enabled_transports)} протокол(ов)")
    
    prompt("Нажмите Enter")


def _toggle_block(state: AppState, user: User):
    """Переключает блокировку пользователя."""
    if user.blocked:
        entitled, reason = get_user_entitlement_status(user)
        if not entitled:
            error(f"Нельзя разблокировать: {reason}. Сначала измените лимит или срок действия.")
            prompt("Нажмите Enter")
            return
        orchestrator.unblock_user(state, user.email)
        success(f"{user.email} разблокирован")
    else:
        orchestrator.block_user(state, user.email)
        success(f"{user.email} заблокирован")
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  4. Telegram
# ═════════════════════════════════════════════════════════════════════════════

def menu_telegram(state: AppState):
    while True:
        clear()
        tg = state.telegram
        panel("Telegram", [
            kv("Admin токен:", _ok(bool(tg.admin_token))),
            kv("Admin Chat ID:", tg.admin_chat_id or "—"),
            kv("Admin бот:", f"{_ok(tg.admin_enabled)} {'запущен' if tg.admin_enabled else 'остановлен'}"),
            kv("Client токен:", _ok(bool(tg.bot_token))),
            kv("Client бот:", f"{_ok(tg.bot_enabled)} {'запущен' if tg.bot_enabled else 'остановлен'}"),
        ])
        choice = menu(
            [("1", "🔑 Admin-токен", "@BotFather"),
             ("2", "💬 Admin Chat ID", "@userinfobot"),
             ("3", "🤖 Client-токен", "@BotFather"),
             ("4", "▶️  Запустить admin-бота", "systemd-сервис hydra-tg-admin"),
             ("5", "▶️  Запустить client-бота", "systemd-сервис hydra-tg-bot"),
             ("6", "⏸️  Остановить всех ботов", ""),
             ("0", "↩ Назад", "")],
            "TELEGRAM",
        )
        if choice == "0":
            return
        elif choice == "1":
            t = prompt("Токен admin-бота")
            if t:
                state.telegram.admin_token = t
                save_state(state)
                success("Сохранён")
            prompt("Нажмите Enter")
        elif choice == "2":
            c = prompt("Admin Chat ID (число)")
            if c:
                state.telegram.admin_chat_id = c
                save_state(state)
                success("Сохранён")
            prompt("Нажмите Enter")
        elif choice == "3":
            t = prompt("Токен клиентского бота")
            if t:
                state.telegram.bot_token = t
                save_state(state)
                success("Сохранён")
            prompt("Нажмите Enter")
        elif choice == "4":
            _install_admin_bot(state)
        elif choice == "5":
            _install_client_bot(state)
        elif choice == "6":
            remove_unit("hydra-tg-admin")
            remove_unit("hydra-tg-bot")
            state.telegram.admin_enabled = False
            state.telegram.bot_enabled = False
            save_state(state)
            success("Боты остановлены")
            prompt("Нажмите Enter")


def _install_admin_bot(state: AppState):
    if not state.telegram.admin_token:
        error("Сначала укажите admin-токен (пункт 1)")
        prompt("Нажмите Enter")
        return
    install_service("hydra-tg-admin", f"""[Unit]
Description=HYDRA Admin Bot
After=network.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -c "from hydra.services.telegram.bot import run_admin_bot; run_admin_bot('{state.telegram.admin_token}', '{state.telegram.admin_chat_id}')"
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
""")
    state.telegram.admin_enabled = True
    save_state(state)
    success("Admin-бот запущен (hydra-tg-admin)")
    prompt("Нажмите Enter")


def _install_client_bot(state: AppState):
    if not state.telegram.bot_token:
        error("Сначала укажите client-токен (пункт 3)")
        prompt("Нажмите Enter")
        return
    install_service("hydra-tg-bot", f"""[Unit]
Description=HYDRA Client Bot
After=network.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -c "from hydra.services.telegram.bot import run_client_bot; run_client_bot('{state.telegram.bot_token}', '{state.telegram.admin_chat_id}')"
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
""")
    state.telegram.bot_enabled = True
    save_state(state)
    success("Client-бот запущен (hydra-tg-bot)")
    prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  5. Мониторинг
# ═════════════════════════════════════════════════════════════════════════════

def _unit_active(unit: str) -> bool:
    """Безопасно проверяет systemd-юнит, в том числе вне Linux."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", unit],
            capture_output=True,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def _is_enter_pressed() -> bool:
    import select
    import os
    if os.name == "nt":
        import msvcrt
        if msvcrt.kbhit():
            if msvcrt.getch() in (b'\r', b'\n'):
                return True
        return False
    else:
        i, o, e = select.select([sys.stdin], [], [], 0.0)
        for s in i:
            if s == sys.stdin:
                sys.stdin.readline()
                return True
        return False


def menu_monitoring(state: AppState):
    while True:
        state = load_state()
        clear()
        
        # Сбор быстрых системных метрик для панели
        load_str = "—"
        ram_str = "—"
        if os.name != "nt":
            try:
                avg1, avg5, _ = os.getloadavg()
                load_str = f"{avg1:.2f}, {avg5:.2f}"
            except Exception:
                pass
            try:
                _, _, r_pct = _read_proc_mem()
                ram_str = f"{r_pct:.0f}%"
            except Exception:
                pass
                
        transport_plugins = transports()
        enabled_names = {
            plugin.meta.name for plugin in transport_plugins
            if state.protocols.get(plugin.meta.name)
            and state.protocols[plugin.meta.name].enabled
        }
        running_count = 0
        for plugin in transport_plugins:
            if plugin.meta.name not in enabled_names:
                continue
            try:
                running_count += int(plugin.status().running)
            except Exception:
                pass
        users_count = len(state.users)
        active_users = sum(not user.blocked for user in state.users)
        sync_active = _unit_active("hydra-sync-agent.timer")
        traffic_active = _unit_active("hydra-traffic-daemon.service")
        
        lines = [
            f"  🔌 {BOLD}Протоколы:{NC} {GREEN}{running_count} работают{NC} / {len(enabled_names)} включено",
            f"  👥 {BOLD}Пользователи:{NC} {CYAN}{active_users} активны{NC} / {users_count} всего",
            f"  🖥️  {BOLD}Система:{NC} Load Avg {YELLOW}{load_str}{NC}  │  RAM {YELLOW}{ram_str}{NC}",
            f"  ⚙️  {BOLD}Фоновые службы:{NC} Sync Agent "
            f"{f'{GREEN}●{NC}' if sync_active else f'{DIM}○{NC}'}  Clash API "
            f"{f'{GREEN}●{NC}' if traffic_active else f'{DIM}○{NC}'}",
        ]
        panel("💻  Состояние системы", lines)

        choice = menu(
            [("1", "📊 Потребление трафика", "Сводная статистика по протоколам и пользователям"),
             ("2", "🔌 Подключения и активность", "Активные сессии и недавние запросы пользователей"),
             ("3", "📈 Живой монитор CPU/RAM", "Нагрузка системы, скорость сети и метрики"),
             ("4", "⚙️ Фоновые службы и логи", "Учёт трафика, синхронизация и системные журналы"),
             ("0", "↩ Назад", "")],
            "МОНИТОРИНГ",
        )
        if choice == "0":
            return
        elif choice == "1":
            _show_traffic_combined(state)
        elif choice == "2":
            _show_connections(state)
        elif choice == "3":
            _show_realtime_sys_monitor()
        elif choice == "4":
            _menu_service_settings(state)


def _menu_service_settings(state: AppState):
    while True:
        state = load_state()
        clear()
        sync_active = _unit_active("hydra-sync-agent.timer")
        clash_enabled = bool(getattr(state.network, "clash_api_enabled", False))
        traffic_active = _unit_active("hydra-traffic-daemon.service")
        panel("Фоновые службы", [
            kv("Sync Agent:", f"{GREEN}активно 🟢{NC}" if sync_active else f"{DIM}неактивно ⚪{NC}"),
            kv("Clash API:", (
                f"{GREEN}активно 🟢{NC}" if clash_enabled and traffic_active
                else f"{YELLOW}ошибка службы 🟡{NC}" if clash_enabled
                else f"{DIM}неактивно ⚪{NC}"
            )),
        ])
        choice = menu([
            ("1", "📋 Просмотр системных логов", "Sing-Box, Sync-Agent, Fail2ban и др."),
            ("2", "🔄 Sync Agent", "Проверка лимитов, сроков действия и обновление WARP-списков"),
            ("3", "📊 Clash API", "Локальный API Sing-Box и демон статистики трафика"),
            ("0", "↩ Назад", "")
        ], "СЕРВИСНЫЕ НАСТРОЙКИ")
        
        if choice == "0":
            break
        elif choice == "1":
            _menu_logs(state)
        elif choice == "2":
            _menu_sync_agent(state)
        elif choice == "3":
            _menu_clash_api(state)


def _show_traffic_combined(state: AppState):
    sort_by = "traffic"
    show_zero_users = True

    def share_bar(value: int, total: int, width: int = 11) -> str:
        ratio = min(1.0, value / total) if total > 0 else 0.0
        filled = int(round(ratio * width))
        return (
            f"{CYAN}{'█' * filled}{DIM}{'░' * (width - filled)}{NC} "
            f"{ratio * 100:5.1f}%"
        )

    while True:
        clear()
        title("📊 Потребление трафика")
        print()
        
        # Refresh from the latest on-disk state. This avoids overwriting daemon
        # increments with the stale object that opened the main menu.
        state = refresh_traffic_state()
        by_protocol = protocol_totals(state)
        enabled_names = {
            plugin.meta.name for plugin in enabled(state, PluginCategory.TRANSPORT)
        }
        labels = {
            "amneziawg": "AmneziaWG", "naive": "NaiveProxy",
            "anytls": "AnyTLS", "mieru": "Mieru",
            "trusttunnel": "TrustTunnel", "shadowtls": "ShadowTLS",
            "hysteria2": "Hysteria2", "snell": "Snell",
            "telemt": "Telemt", "wdtt": "qWDTT",
        }
        order = [
            "amneziawg", "naive", "anytls", "mieru", "trusttunnel",
            "shadowtls", "hysteria2", "snell", "telemt", "wdtt",
        ]
        names = [name for name in order if name in enabled_names or by_protocol.get(name, 0)]
        names.extend(sorted(set(by_protocol) - set(names)))

        aggregate_totals = {
            name: int(stats.get("traffic_used_bytes", 0))
            for name, stats in state.install.get("protocol_traffic_totals", {}).items()
            if isinstance(stats, dict)
        }
        user_total = sum(max(0, int(user.traffic_used_bytes)) for user in state.users)
        attributed_user_total = sum(
            max(0, int(stats.get("traffic_used_bytes", 0)))
            for user in state.users
            for stats in user.credentials.values()
            if isinstance(stats, dict)
        )
        legacy_unattributed = max(0, user_total - attributed_user_total)
        protocol_total = sum(by_protocol.values())
        total_traffic = protocol_total + legacy_unattributed
        active_users = sum(not user.blocked for user in state.users)
        limited_users = sum(user.traffic_limit_gb > 0 for user in state.users)

        panel("📊 Сводка трафика", [
            kv("Всего учтено:", f"{BOLD}{CYAN}{_bytes_auto(total_traffic)}{NC}"),
            kv("Пользователи:", f"{active_users} активны / {len(state.users)} всего"),
            kv("С лимитом:", str(limited_users)),
        ])

        print()
        print(f"  {BOLD}По протоколам{NC}")
        print(f"  {BOLD}{'Протокол':<15} {'Трафик':>12}  {'Доля':<18} {'Учёт':<13} {'Статус':<8}{NC}")
        print(f"  {DIM}{'─' * 77}{NC}")
        for name in names:
            status = f"{GREEN}включён{NC}" if name in enabled_names else f"{DIM}история{NC}"
            accounting_text = "общий" if name in aggregate_totals else "по пользов."
            accounting_color = YELLOW if name in aggregate_totals else DIM
            accounting = f"{accounting_color}{accounting_text:<13}{NC}"
            value = by_protocol.get(name, 0)
            print(
                f"  {labels.get(name, name):<15} {GREEN}{_bytes_auto(value):>12}{NC}  "
                f"{share_bar(value, total_traffic):<18} {accounting} {status}"
            )
        if legacy_unattributed:
            print(
                f"  {'Старая статист.':<15} {YELLOW}{_bytes_auto(legacy_unattributed):>12}{NC}  "
                f"{share_bar(legacy_unattributed, total_traffic):<18} {DIM}без разбивки{NC}"
            )
        print()
        
        print(f"  {BOLD}По пользователям{NC}")
        users_sorted = list(state.users)
        if not show_zero_users:
            users_sorted = [user for user in users_sorted if user.traffic_used_bytes > 0]
        if sort_by == "traffic":
            users_sorted.sort(key=lambda u: u.traffic_used_bytes, reverse=True)
        elif sort_by == "name":
            users_sorted.sort(key=lambda u: u.email.lower())
        elif sort_by == "limit":
            users_sorted.sort(key=lambda u: u.traffic_limit_gb, reverse=True)
        elif sort_by == "expiry":
            def get_expiry(u):
                if not u.expiry_date:
                    return "9999-12-31"
                return u.expiry_date
            users_sorted.sort(key=get_expiry)

        print(f"  {BOLD}{'#':<3} {'Пользователь':<20} {'Трафик':>12} {'Лимит':>10} {'Исп.':>7} {'Статус':<9} {'Срок':<10}{NC}")
        print(f"  {DIM}{'─' * 77}{NC}")
        for i, u in enumerate(users_sorted, 1):
            used = u.traffic_used_bytes
            status_text = "блок" if u.blocked else "активен"
            status_color = RED if u.blocked else GREEN
            status_str = f"{status_color}{status_text:<9}{NC}"
            
            expiry_str = "бессрочно"
            if u.expiry_date:
                try:
                    expiry = datetime.fromisoformat(u.expiry_date)
                    now = datetime.now(expiry.tzinfo)
                    delta = expiry - now
                    if delta.days < 0:
                        expiry_str = f"{RED}истёк{NC}"
                    else:
                        expiry_str = f"{delta.days}дн"
                except Exception:
                    expiry_str = u.expiry_date[:10]

            limit_bytes = int(u.traffic_limit_gb * 1073741824)
            lim_str = f"{u.traffic_limit_gb:.1f} GiB" if limit_bytes else "∞"
            usage_str = f"{min(999, used / limit_bytes * 100):.0f}%" if limit_bytes else "—"
            email = u.email if len(u.email) <= 20 else u.email[:17] + "..."
            print(
                f"  {i:<3d} {BOLD}{email:<20}{NC} {_bytes_auto(used):>12} "
                f"{lim_str:>10} {usage_str:>7} {status_str} {expiry_str:<10}"
            )

        if not users_sorted:
            print(f"  {DIM}Нет пользователей с ненулевым трафиком.{NC}")
        print(f"  {DIM}{'─' * 77}{NC}")
        shown = len(users_sorted)
        print(f"  {DIM}Показано: {shown}/{len(state.users)}{NC}")
        print()

        sort_labels = {
            "traffic": "по трафику", "name": "по имени",
            "limit": "по лимиту", "expiry": "по сроку",
        }
        choice = menu([
            ("1", f"{'✓ ' if sort_by == 'traffic' else ''}Сортировать по трафику", ""),
            ("2", f"{'✓ ' if sort_by == 'name' else ''}Сортировать по имени", ""),
            ("3", f"{'✓ ' if sort_by == 'limit' else ''}Сортировать по лимиту", ""),
            ("4", f"{'✓ ' if sort_by == 'expiry' else ''}Сортировать по сроку", ""),
            ("Z", "Показать всех пользователей" if not show_zero_users else "Скрыть пользователей без трафика", ""),
            ("D", "🔍 Статистика пользователя", ""),
            ("0", "↩ Назад", "")
        ], f"УПРАВЛЕНИЕ · {sort_labels[sort_by].upper()}")
        
        if choice == "0":
            break
        elif choice == "1":
            sort_by = "traffic"
        elif choice == "2":
            sort_by = "name"
        elif choice == "3":
            sort_by = "limit"
        elif choice == "4":
            sort_by = "expiry"
        elif choice.upper() == "Z":
            show_zero_users = not show_zero_users
        elif choice.upper() == "D":
            u = _select_user(state, "Выберите пользователя для просмотра деталей")
            if u:
                _show_user_detail(state, u)


def _show_connections(state: AppState):
    import time
    from hydra.plugins.registry import enabled
    from hydra.plugins.base import PluginCategory
    
    while True:
        clear()
        title("🔌 Подключения и активность")
        print()
        
        state = load_state()
        all_clients = []
        from hydra.services.active_connections import tracked_active_connections
        all_clients.extend(tracked_active_connections(state))
        for p in enabled(state, PluginCategory.TRANSPORT):
            # These are represented by the attributed Clash API snapshot. ss
            # sees only internal proxy legs and cannot identify their users.
            if p.meta.name == "naive":
                recent = getattr(p, "recent_connections", None)
                if recent:
                    try:
                        for client in recent(state):
                            row = dict(client)
                            row["plugin"] = "naive"
                            all_clients.append(row)
                    except Exception:
                        pass
                continue
            if p.meta.name in {
                "anytls", "mieru", "trusttunnel", "shadowtls", "hysteria2", "snell",
            }:
                continue
            try:
                try:
                    clients = p.connected_clients(state)
                except TypeError:
                    clients = p.connected_clients()
                    
                for c in clients:
                    row = dict(c)
                    row["plugin"] = p.meta.name
                    all_clients.append(row)
            except Exception:
                pass
        all_clients.sort(key=lambda item: (
            str(item.get("plugin", "")), str(item.get("email", "")).lower(),
        ))
                
        if not all_clients:
            print(f"  {YELLOW}Нет активных подключений в данный момент.{NC}")
            print()
        else:
            print(f"  {BOLD}{'Протокол':<12} {'Пользователь':<30} {'Rx / Tx':<20} {'Активность':<15}{NC}")
            print(f"  {DIM}{'─' * PANEL_W}{NC}")
            for c in all_clients:
                plugin_name = c.get("plugin", "unknown")
                email = c.get("email", "?")
                profiles = c.get("profiles", [])
                if profiles:
                    email = f"{email} [{'/'.join(profiles)}]"
                elif c.get("connections", 0) > 1:
                    email = f"{email} ({c['connections']} сесс.)"
                rx = c.get("rx", 0)
                tx = c.get("tx", 0)
                online = c.get("online", True)
                
                activity = "—"
                handshake = c.get("last_handshake", 0)
                if handshake > 0:
                    elapsed = int(time.time()) - handshake
                    if elapsed < 0:
                        activity = "сейчас"
                    elif elapsed < 60:
                        activity = f"{elapsed} сек"
                    elif elapsed < 3600:
                        activity = f"{elapsed // 60} мин"
                    else:
                        activity = f"{elapsed // 3600} ч"
                elif online:
                    activity = "активен"
                    
                recent = c.get("activity_kind") == "recent"
                status_ico = f"{GREEN}●{NC}" if online else (f"{YELLOW}◐{NC}" if recent else f"{DIM}●{NC}")
                traffic_str = f"{_bytes_auto(rx)} / {_bytes_auto(tx)}" if (rx or tx) else "—"
                
                email_disp = email
                if len(email_disp) > 30:
                    email_disp = email_disp[:27] + "..."
                    
                print(f"  {plugin_name:<12} {status_ico} {BOLD}{email_disp:<28}{NC} {traffic_str:<20} {activity:<15}")
            print()
            print(f"  {DIM}● Активно ◐ Активно (5 мин){NC}")

        from hydra.services.active_connections import traffic_daemon_fresh
        if not state.network.clash_api_enabled:
            print(f"  {YELLOW}AnyTLS/Mieru/TrustTunnel/ShadowTLS не показаны: Clash API и демон статистики выключены.{NC}")
        elif not traffic_daemon_fresh(state):
            print(f"  {YELLOW}Данные Clash API устарели: проверьте службу hydra-traffic-daemon.{NC}")
            
        choice = menu([
            ("R", "🔄 Обновить список", ""),
            ("0", "↩ Назад", "")
        ], "ПОДКЛЮЧЕНИЯ И АКТИВНОСТЬ")
        
        if choice == "0":
            break


def _show_status():
    clear()
    title("🚦 Статус протоколов")
    print()
    
    st = status_all()
    
    print(f"  {BOLD}{'Протокол':<15} {'Порт':<7} {'Состояние':<12} {'Автозапуск':<12}{NC}")
    print(f"  {DIM}{'─' * 55}{NC}")
    
    for name, s in st.items():
        ico = f"{GREEN}запущен{NC}" if s["running"] else (f"{YELLOW}остановлен{NC}" if s["installed"] else f"{DIM}не уст.{NC}")
        port_str = str(s['port']) if s['port'] else "—"
        autostart_str = "вкл" if s.get("enabled", False) else "выкл"
        
        print(f"  {name:<15} {port_str:<7} {ico:<12} {autostart_str:<12}")
        
    print()
    prompt("Нажмите Enter для возврата")


def _read_proc_cpu() -> tuple[float, float]:
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
            if line.startswith("cpu"):
                parts = [float(x) for x in line.split()[1:8]]
                idle = parts[3] + parts[4]
                total = sum(parts)
                return idle, total
    except Exception:
        pass
    return 0.0, 0.0


def _read_proc_mem() -> tuple[int, int, float]:
    try:
        meminfo = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1]) * 1024
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        if not available:
            available = (
                meminfo.get("MemFree", 0) + meminfo.get("Buffers", 0)
                + meminfo.get("Cached", 0) + meminfo.get("SReclaimable", 0)
                - meminfo.get("Shmem", 0)
            )
        used = max(0, total - available)
        pct = (used / total) * 100 if total > 0 else 0.0
        return used, total, pct
    except Exception:
        pass
    return 0, 0, 0.0


def _read_proc_net() -> tuple[int, int]:
    try:
        rx = 0
        tx = 0
        default_ifaces: set[str] = set()
        try:
            with open("/proc/net/route", "r") as routes:
                for route in routes.readlines()[1:]:
                    fields = route.split()
                    if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                        default_ifaces.add(fields[0])
        except Exception:
            pass
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()
            for line in lines[2:]:
                if ":" not in line:
                    continue
                iface = line.split(":", 1)[0].strip()
                if iface == "lo" or (default_ifaces and iface not in default_ifaces):
                    continue
                parts = line.split(":", 1)[1].split()
                if len(parts) >= 9:
                    rx += int(parts[0])
                    tx += int(parts[8])
        return rx, tx
    except Exception:
        pass
    return 0, 0


def _show_realtime_sys_monitor():
    import time
    clear()
    print(f"\n  {BOLD}{CYAN}▸ Запуск живого мониторинга...{NC}")
    print(f"  {DIM}Нажмите [Enter] для возврата в меню.{NC}\n")
    time.sleep(0.5)
    
    has_psutil = False
    try:
        import psutil
        has_psutil = True
    except ImportError:
        pass

    if has_psutil:
        try:
            prev_net = _read_proc_net()
        except Exception:
            prev_net = None
    else:
        prev_net = _read_proc_net()
        prev_cpu_idle, prev_cpu_total = _read_proc_cpu()
        
    last_time = time.time()
    
    while True:
        try:
            if _is_enter_pressed():
                break
                
            clear()
            title("📈 Живой мониторинг системы")
            print(f"  {DIM}Нажмите [Enter] для возврата в меню. Обновление каждую секунду.{NC}")
            print()
            
            if has_psutil:
                import psutil
                cpu = psutil.cpu_percent(interval=0)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage("/")
                
                cpu_str = f"{cpu:.1f}%"
                ram_str = f"{mem.percent:.1f}%  ({_bytes_auto(mem.used)} / {_bytes_auto(mem.total)})"
                disk_str = f"{disk.percent:.1f}%  ({_bytes_auto(disk.used)} / {_bytes_auto(disk.total)})"
                
                try:
                    curr_net = _read_proc_net()
                    now = time.time()
                    dt = now - last_time
                    if dt <= 0:
                        dt = 1.0
                    rx_speed = (curr_net[0] - prev_net[0]) / dt
                    tx_speed = (curr_net[1] - prev_net[1]) / dt
                    prev_net = curr_net
                    last_time = now
                except Exception:
                    rx_speed, tx_speed = 0.0, 0.0
            else:
                curr_cpu_idle, curr_cpu_total = _read_proc_cpu()
                diff_total = curr_cpu_total - prev_cpu_total
                diff_idle = curr_cpu_idle - prev_cpu_idle
                if diff_total > 0:
                    cpu_val = (diff_total - diff_idle) / diff_total * 100
                else:
                    cpu_val = 0.0
                prev_cpu_total = curr_cpu_total
                prev_cpu_idle = curr_cpu_idle
                cpu_str = f"{cpu_val:.1f}%"
                
                r_used, r_total, r_pct = _read_proc_mem()
                ram_str = f"{r_pct:.1f}%  ({_bytes_auto(r_used)} / {_bytes_auto(r_total)})"
                
                try:
                    import shutil
                    d_total, d_used, d_free = shutil.disk_usage("/")
                    d_pct = (d_used / d_total) * 100 if d_total > 0 else 0.0
                    disk_str = f"{d_pct:.1f}%  ({_bytes_auto(d_used)} / {_bytes_auto(d_total)})"
                except Exception:
                    disk_str = "н/д"
                    
                curr_rx, curr_tx = _read_proc_net()
                now = time.time()
                dt = now - last_time
                if dt <= 0:
                    dt = 1.0
                rx_speed = (curr_rx - prev_net[0]) / dt
                tx_speed = (curr_tx - prev_net[1]) / dt
                prev_net = (curr_rx, curr_tx)
                last_time = now
                
            lines = [
                kv("Загрузка CPU:", cpu_str),
                kv("Использование RAM:", ram_str),
                kv("Дисковое пространство:", disk_str),
                f"  {DIM}{'─' * (PANEL_W - 2)}{NC}",
                kv("Сетевой вход (Rx):", f"{GREEN}{_bytes_auto(int(rx_speed))}/s{NC}"),
                kv("Сетевой выход (Tx):", f"{CYAN}{_bytes_auto(int(tx_speed))}/s{NC}"),
            ]
            panel("Текущие параметры", lines)
            
            time.sleep(1)
            
        except (KeyboardInterrupt, SystemExit):
            break
        except Exception as e:
            error(f"Ошибка мониторинга: {e}")
            time.sleep(2)


def _menu_logs(state: AppState):
    lines_count = 30
    while True:
        try:
            from hydra.services.traffic_daemon import maintain_traffic_log
            maintain_traffic_log()
        except Exception:
            pass
        clear()
        title("📋 Просмотр системных логов")
        print()
        
        # Каждый пункт явно указывает реальный источник. Большинство сервисов
        # пишут stdout/stderr в journald, а не в выдуманный log-файл.
        log_options = [
            ("1", "📋 Sing-Box", "journal", "sing-box"),
            ("2", "🔄 Sync Agent", "file", "/var/log/hydra/sync-agent.log"),
            ("3", "📊 Clash API", "file", "/var/log/hydra/traffic-daemon.log"),
            ("4", "🔗 qWDTT", "journal", "wdtt"),
            ("5", "🌐 Caddy L4", "journal", "caddy-l4"),
            ("6", "📨 Telemt", "journal", "telemt"),
            ("7", "🔐 DNSCrypt", "journal", "dnscrypt-proxy"),
            ("8", "🔒 Fail2ban", "journal", "fail2ban"),
            ("9", "🌐 Naive access", "file", "/var/log/caddy-naive/access.log"),
            ("A", "🍯 Honeypot events", "file", "/var/log/hydra-honeypot.log"),
            ("B", "📦 Сервер подписок", "journal", "hydra-sub"),
            ("C", "🤖 Telegram Admin Bot", "journal", "hydra-tg-admin"),
            ("D", "🤖 Telegram Client Bot", "journal", "hydra-tg-bot"),
            ("E", "🛠 HYDRA install", "file", "/var/log/hydra/install.log"),
        ]
            
        print(f"  {BOLD}Текущий лимит строк для просмотра:{NC} {GREEN}{lines_count}{NC}\n")
        
        opts = []
        for key, name, source_type, source in log_options:
            source_label = source if source_type == "file" else f"journalctl -u {source}"
            opts.append((key, name, f"{source_label} · {_log_source_status(source_type, source)}"))
            
        opts += [
            ("-", "", ""),
            ("L", f"📝 Изменить лимит строк ({lines_count})", ""),
            ("0", "↩ Назад", "")
        ]
        
        choice = menu(opts, "ВЫБОР ЛОГ-ФАЙЛА")
        if choice == "0":
            break
        elif choice.upper() == "L":
            try:
                new_limit = int(prompt("Введите количество строк", str(lines_count)))
                if new_limit > 0:
                    lines_count = new_limit
            except ValueError:
                warn("Введите корректное число.")
                prompt("Нажмите Enter")
        else:
            selected_source = None
            selected_type = ""
            selected_title = ""
            for key, name, source_type, source in log_options:
                if choice == key:
                    selected_source = source
                    selected_type = source_type
                    selected_title = name
                    break
                    
            if selected_source:
                _show_log_source(selected_title, selected_type, selected_source, lines_count)


def _unit_known(unit: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "show", "--property=LoadState", "--value", unit],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == "loaded"
    except (OSError, subprocess.TimeoutExpired):
        return False


def _log_source_status(source_type: str, source: str) -> str:
    if source_type == "file":
        path = Path(source)
        if not path.exists():
            return "ещё не создан"
        try:
            return f"{_bytes_auto(path.stat().st_size)}"
        except OSError:
            return "недоступен"
    if _unit_active(source):
        return "активно"
    return "остановлено" if _unit_known(source) else "не установлено"


def _read_log_source(source_type: str, source: str, num_lines: int) -> tuple[list[str], str]:
    if source_type == "file":
        path = Path(source)
        if not path.exists():
            return [], "Файл ещё не создан."
        try:
            from collections import deque
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                return [line.rstrip("\n") for line in deque(handle, maxlen=num_lines)], ""
        except OSError as exc:
            return [], f"Ошибка чтения файла: {exc}"
    try:
        result = subprocess.run(
            ["journalctl", "-u", source, "-n", str(num_lines),
             "--no-pager", "-o", "short-iso"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f"Не удалось прочитать journalctl: {exc}"
    output = (result.stdout or "").strip()
    if result.returncode != 0:
        return [], (result.stderr or output or "journalctl завершился с ошибкой").strip()
    lines = [line for line in output.splitlines() if line.strip() and line.strip() != "-- No entries --"]
    return lines, "" if lines else "В журнале пока нет записей."


def _show_log_source(title_text: str, source_type: str, source: str, num_lines: int):
    source_label = source if source_type == "file" else f"journalctl -u {source}"
    while True:
        clear()
        title(f"{title_text} ({num_lines} строк)")
        print(f"  {DIM}Источник: {source_label}{NC}")
        print()

        lines, message = _read_log_source(source_type, source, num_lines)
        for line in lines:
            print(f"  {DIM}{line}{NC}")
        if message:
            warn(message)
        print()

        choice = menu([
            ("R", "🔄 Обновить", ""),
            ("W", "👀 Следить в реальном времени", ""),
            ("0", "↩ Назад", "")
        ], "ПРОСМОТР ЛОГА")

        if choice == "0":
            break
        if choice.upper() == "W":
            if source_type == "file":
                _watch_log_file(title_text, source)
            else:
                _watch_journal(title_text, source)


def _show_log_file(title_text: str, path_str: str, num_lines: int):
    """Обратная совместимость для внутренних меню с файловыми логами."""
    _show_log_source(title_text, "file", path_str, num_lines)


def _watch_log_file(title_text: str, path_str: str):
    import time
    path = Path(path_str)
    clear()
    title(f"👀 Слежение: {title_text}")
    print(f"  {DIM}Файл: {path_str}{NC}")
    print(f"  {DIM}Нажмите [Enter] для выхода из режима слежения.{NC}")
    print(f"  {DIM}{'─' * PANEL_W}{NC}")
    print()
    
    if not path.exists():
        error("Файл лога не найден.")
        prompt("Нажмите Enter")
        return
        
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)
            while True:
                if _is_enter_pressed():
                    break
                line = f.readline()
                if line:
                    print(f"  {DIM}{line.strip()}{NC}")
                else:
                    time.sleep(0.5)
    except KeyboardInterrupt:
        pass


def _watch_journal(title_text: str, unit: str):
    import select
    import time

    clear()
    title(f"👀 Слежение: {title_text}")
    print(f"  {DIM}Источник: journalctl -u {unit}{NC}")
    print(f"  {DIM}Нажмите [Enter] для выхода из режима слежения.{NC}")
    print(f"  {DIM}{'─' * PANEL_W}{NC}")
    print()

    try:
        process = subprocess.Popen(
            ["journalctl", "-u", unit, "-f", "-n", "0", "--no-pager", "-o", "short-iso"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except OSError as exc:
        error(f"Не удалось запустить journalctl: {exc}")
        prompt("Нажмите Enter")
        return

    try:
        while True:
            if _is_enter_pressed():
                break
            if process.stdout is not None:
                ready, _, _ = select.select([process.stdout], [], [], 0.25)
                if ready:
                    line = process.stdout.readline()
                    if line:
                        print(f"  {DIM}{line.rstrip()}{NC}")
                        continue
            if process.poll() is not None:
                warn("journalctl завершил работу.")
                time.sleep(1)
                break
    except KeyboardInterrupt:
        pass
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()


def _sync_agent_log_snapshot(
    log_path: Path,
    now_timestamp: float | None = None,
) -> tuple[str, str, bool]:
    """Return the latest non-empty log line and its freshness."""
    lines, message = _read_log_source("file", str(log_path), 5)
    last_line = next((line for line in reversed(lines) if line.strip()), "")
    if not last_line:
        return message or "нет логов", "нет данных", True

    try:
        current = datetime.now().timestamp() if now_timestamp is None else now_timestamp
        age_seconds = max(0, int(current - log_path.stat().st_mtime))
    except OSError:
        return last_line, "время неизвестно", True

    if age_seconds < 60:
        freshness = "только что"
    elif age_seconds < 3600:
        freshness = f"{age_seconds // 60} мин назад"
    elif age_seconds < 86400:
        freshness = f"{age_seconds // 3600} ч назад"
    else:
        freshness = f"{age_seconds // 86400} дн назад"
    # The timer runs every five minutes; after two missed intervals the status
    # should visibly indicate that the displayed record is no longer current.
    return last_line, freshness, age_seconds > 600


def _menu_sync_agent(state: AppState):
    while True:
        state = load_state()
        clear()
        
        timer_active = _unit_active("hydra-sync-agent.timer")
            
        log_path = Path("/var/log/hydra/sync-agent.log")
        last_log_line, log_freshness, log_stale = _sync_agent_log_snapshot(log_path)
        freshness_color = RED if timer_active and log_stale else DIM
                
        lines = [
            kv("Таймер (5 мин):", f"{GREEN}активен 🟢{NC}" if timer_active else f"{RED}отключен 🔴{NC}"),
            kv("Лог-файл:", f"{_bytes_auto(log_path.stat().st_size) if log_path.exists() else 'не создан'}"),
            kv("Последняя запись:", f"{DIM}{last_log_line}{NC}"),
            kv("Актуальность:", f"{freshness_color}{log_freshness}{NC}"),
        ]
        panel("Управление Sync Agent", lines)
        
        warp_auto = state.install.get("sync_warp_enabled", True)
        limits_auto = state.install.get("sync_limits_enabled", True)
        updates_auto = state.install.get("sync_updates_enabled", True)

        toggle_label = "⏹ Отключить Sync Agent" if timer_active else "▶ Включить Sync Agent"
        toggle_desc = "Остановить периодическую синхронизацию" if timer_active else "Проверять лимиты и сроки каждые 5 минут"
        
        choice = menu([
            ("1", toggle_label, toggle_desc),
            ("2", "⚡ Запустить сейчас", "Однократно проверить лимиты, сроки, WARP и обновление Sing-Box"),
            ("3", "📋 Показать лог", "Последние 30 строк sync-agent.log"),
            ("-", "", ""),
            ("4", f"🔄 Автообновление списков WARP: {GREEN}[ВКЛ]{NC}" if warp_auto else f"🔄 Автообновление списков WARP: {RED}[ВЫКЛ]{NC}",
             "Раз в 24 часа скачивать свежие правила WARP"),
            ("5", f"👥 Автопроверка лимитов: {GREEN}[ВКЛ]{NC}" if limits_auto else f"👥 Автопроверка лимитов: {RED}[ВЫКЛ]{NC}",
             "Блокировать пользователей при превышении трафика/TTL"),
            ("6", f"🆙 Автопроверка обновлений ядра: {GREEN}[ВКЛ]{NC}" if updates_auto else f"🆙 Автопроверка обновлений ядра: {RED}[ВЫКЛ]{NC}",
             "Раз в 24 часа проверять наличие обновлений Sing-Box"),
            ("0", "↩ Назад", "")
        ], "SYNC AGENT")
        
        if choice == "0":
            break
        elif choice == "1":
            if timer_active:
                info("Отключение Sync Agent...")
                if remove_unit("hydra-sync-agent"):
                    success("Sync Agent отключён")
                else:
                    error("Не удалось отключить Sync Agent")
            else:
                project_root = Path(__file__).resolve().parent.parent.parent
                ok = install_timer("hydra-sync-agent",
                    f"""[Unit]
Description=HYDRA Sync Agent
After=network.target
[Service]
Type=oneshot
User=root
WorkingDirectory={project_root}
Environment=PYTHONPATH={project_root}
ExecStart=/usr/bin/python3 -m hydra.services.sync_agent
""",
                    """[Unit]
Description=HYDRA Sync Agent Timer
[Timer]
OnCalendar=*:0/5
Persistent=true
[Install]
WantedBy=timers.target
""")
                if ok:
                    success("Sync Agent включён (каждые 5 минут)")
                else:
                    error("Не удалось включить Sync Agent")
            prompt("Нажмите Enter")
        elif choice == "2":
            info("Запуск ручной синхронизации...")
            try:
                from hydra.services.sync_agent import run_sync
                ok, message = run_sync(
                    force_update_check=True,
                    force_all_checks=True,
                )
                if ok:
                    success("Синхронизация успешно выполнена")
                else:
                    warn(f"Синхронизация завершена с ошибками: {message}")
            except Exception as e:
                error(f"Ошибка при синхронизации: {e}")
            prompt("Нажмите Enter")
        elif choice == "3":
            _show_log_file("Sync Agent", str(log_path), 30)
        elif choice == "4":
            state, _ = update_state(
                lambda latest: latest.install.__setitem__("sync_warp_enabled", not warp_auto)
            )
        elif choice == "5":
            state, _ = update_state(
                lambda latest: latest.install.__setitem__("sync_limits_enabled", not limits_auto)
            )
        elif choice == "6":
            state, _ = update_state(
                lambda latest: latest.install.__setitem__("sync_updates_enabled", not updates_auto)
            )


def _menu_clash_api(state: AppState):
    while True:
        state = load_state()
        clear()
        
        enabled_status = getattr(state.network, "clash_api_enabled", False)
        daemon_active = _unit_active("hydra-traffic-daemon.service")
            
        lines = [
            kv("Clash API:", f"{GREEN}активно 🟢{NC}" if enabled_status and daemon_active else f"{DIM}неактивно ⚪{NC}"),
            kv("Демон статистики:", f"{GREEN}активно 🟢{NC}" if daemon_active else f"{DIM}неактивно ⚪{NC}"),
        ]
        panel("Clash API", lines)
        
        toggle_label = "⏹ Отключить Clash API" if enabled_status else "▶ Включить Clash API"
        toggle_desc = "Отключить Clash API и демон статистики" if enabled_status else "Включить локальный Clash API и демон статистики"
        choice = menu([
            ("1", toggle_label, toggle_desc),
            ("0", "↩ Назад", "")
        ], "CLASH API")
        
        if choice == "0":
            break
        elif choice == "1":
            desired = not enabled_status
            state, _ = update_state(lambda latest: setattr(latest.network, "clash_api_enabled", desired))
            info("Пересборка конфигурации Sing-Box...")
            from hydra.core.orchestrator import apply_config
            if apply_config(state):
                success("Clash API включён" if desired else "Clash API отключён")
            else:
                state, _ = update_state(
                    lambda latest: setattr(latest.network, "clash_api_enabled", enabled_status)
                )
                apply_config(state)
                error("Не удалось применить настройку; прежнее состояние восстановлено")
            prompt("Нажмите Enter")


# ═════════════════════════════════════════════════════════════════════════════
#  6. Безопасность — полноценное меню
# ═════════════════════════════════════════════════════════════════════════════

def menu_security(state: AppState):
    from hydra.plugins.registry import get as get_plugin
    while True:
        clear()
        st = status_all()

        security_p_lines = []
        p_f2b = get_plugin("fail2ban")
        p_hp = get_plugin("honeypot")
        p_ipb = get_plugin("ipban")
        
        plugins_list = [p for p in [p_f2b, p_hp, p_ipb] if p is not None]

        for p in plugins_list:
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}●{NC}" if s.get("running") else (f"{YELLOW}●{NC}" if s.get("installed") else f"{DIM}●{NC}")
            st_txt = "вкл" if s.get("enabled") else "выкл"
            security_p_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{st_txt:>4}{NC}")

        panel("Безопасность", [
            f"  {BOLD}Плагины безопасности:{NC}",
            *security_p_lines
        ])

        opts: list[tuple[str, str, str]] = []
        for i, p in enumerate(plugins_list, 1):
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}✓{NC}" if s.get("running") else (f"{YELLOW}⚠{NC}" if s.get("installed") else f"{RED}✗{NC}")
            opts.append((str(i),
                         f"{ico} {p.meta.name}",
                         f"{p.meta.description}"))
        
        opts += [
            ("-", "", ""),
            ("A", "✅ Включить всё", "Fail2ban + Honeypot + IPBan"),
            ("B", "❌ Выключить всё", ""),
            ("0", "↩ Назад", "")
        ]

        choice = menu(opts, "БЕЗОПАСНОСТЬ")
        if choice == "0":
            return
        elif choice == "A":
            errors = []
            for p in plugins_list:
                try:
                    _toggle_security_plugin(state, p.meta.name, force_enable=True)
                except Exception as e:
                    errors.append(f"{p.meta.name}: {e}")
            if errors:
                from hydra.ui.tui import warn
                for err in errors:
                    warn(err)
                success("Часть служб безопасности включена (см. ошибки выше)")
            else:
                success("Все службы безопасности включены")
            prompt("Нажмите Enter")
        elif choice == "B":
            errors = []
            for p in plugins_list:
                try:
                    _toggle_security_plugin(state, p.meta.name, force_enable=False)
                except Exception as exc:
                    errors.append(f"{p.meta.name}: {exc}")
            if errors:
                for err in errors:
                    warn(err)
                warn("Часть служб безопасности не удалось выключить")
            else:
                success("Все службы безопасности выключены")
            prompt("Нажмите Enter")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(plugins_list):
                    p = plugins_list[idx]
                    menu_plugin(state, p)
            except ValueError:
                pass


def _toggle_security_plugin(state: AppState, name: str, force_enable: bool | None = None):
    """Toggle a security plugin through the transactional orchestrator."""
    from hydra.plugins.registry import get as get_plugin
    p = get_plugin(name)
    if not p:
        return

    proto = get_protocol(state, name)
    if force_enable is True:
        target_enable = True
    elif force_enable is False:
        target_enable = False
    else:
        target_enable = not (proto and proto.enabled)

    if target_enable:
        if proto and not proto.installed:
            ok = orchestrator.install_plugin(state, name)
            if not ok:
                raise RuntimeError(f"Не удалось установить плагин {name}")
        if not orchestrator.enable(state, name):
            raise RuntimeError(f"Не удалось включить плагин {name}")
    else:
        if not orchestrator.disable(state, name):
            raise RuntimeError(f"Не удалось выключить плагин {name}")


def _menu_amneziawg(state: AppState, p):
    from hydra.core.state import get_protocol
    
    while True:
        clear()
        ps = get_protocol(state, p.meta.name)
        
        try:
            st = p.status()
            profiles = p.get_profiles(state) if st.installed else []
            details = [("Профили", len(profiles))]
            details.extend(
                ("", f"{prof['label']} · {prof['interface']} · :{prof['port']} · {prof['preset']}")
                for prof in profiles
            )
            protocol_status_panel(
                p.meta.name, installed=st.installed, enabled=st.enabled,
                running=st.running, port=st.port, details=details,
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name, installed=ps.installed, enabled=ps.enabled,
                running=False, port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )
        
        options = []
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
                options.append(("3", "👤 Профили AWG", "Управление профилями (Desktop/Mobile)"))
                options.append(("4", "🔄 Ротация обфускации", "Ротировать параметры обфускации без downtime"))
                options.append(("5", "⚙️ Оптимизация VPS", "Hardware-aware sysctl/swap/NIC автотюнинг"))
                options.append(("6", "🎲 Генератор обфускации", "Пошаговый мастер генерации обфускации"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))
            
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, protocol_menu_title(p.meta.name))
        
        if choice == "0":
            break
            
        elif choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if orchestrator.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error("Ошибка применения конфигурации")
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if orchestrator.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error("Ошибка применения конфигурации")
            else:
                try:
                    if orchestrator.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error("Ошибка применения конфигурации")
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")
            
        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)
            
        elif choice == "3" and ps.installed and ps.enabled:
            _manage_awg_profiles(state, p)
            
        elif choice == "4" and ps.installed and ps.enabled:
            _rotate_awg_obfuscation(state, p)
            
        elif choice == "5" and ps.installed and ps.enabled:
            _tune_awg_hardware(state, p)
            
        elif choice == "6" and ps.installed and ps.enabled:
            _awg_generate_wizard_menu(state, p)
            
        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = orchestrator.reinstall_plugin(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")
                
        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить AmneziaWG?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")


def _manage_awg_profiles(state: AppState, p):
    while True:
        clear()
        profiles = p.get_profiles(state)
        lines = []
        for i, prof in enumerate(profiles, 1):
            lines.append(f"  {i}. {prof['label']} ({prof['interface']}) on port {prof['port']}")
            lines.append(f"     Preset: {prof['preset']}")
            lines.append(f"     Network: {prof['network']}")
        panel("📁 УПРАВЛЕНИЕ ПРОФИЛЯМИ AWG", lines)
        
        options = []
        has_mobile = any(prof["name"] == "mobile" for prof in profiles)
        if not has_mobile:
            options.append(("1", "➕ Добавить мобильный профиль", "Создать профиль с мобильным пресетом"))
        else:
            options.append(("2", "❌ Удалить мобильный профиль", "Удалить профиль с мобильным пресетом"))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "AWG PROFILES")
        if choice == "0":
            break
            
        elif choice == "1" and not has_mobile:
            res = _awg_generate_wizard(state, p)
            if res:
                strategy, carrier = res
                carrier_str = carrier if carrier else "generic"
                preset_name = f"{strategy}:{carrier_str}"
                info(f"Создание профиля с пресетом {preset_name}...")
                if p.add_profile("mobile", preset_name, state):
                    success("Мобильный профиль успешно создан!")
                else:
                    error("Не удалось создать мобильный профиль")
                prompt("Нажмите Enter")
                
        elif choice == "2" and has_mobile:
            if confirm("Удалить мобильный профиль?", default=False):
                info("Удаление...")
                if p.remove_profile("mobile", state):
                    success("Профиль удален")
                else:
                    error("Ошибка удаления")
                prompt("Нажмите Enter")


def _rotate_awg_obfuscation(state: AppState, p):
    profiles = p.get_profiles(state)
    options = []
    for idx, prof in enumerate(profiles, 1):
        options.append((str(idx), f"Ротировать {prof['label']} ({prof['interface']})", f"Текущий пресет: {prof['preset']}"))
    options.append(("0", "Отмена", ""))
    
    choice = menu(options, "РОТАЦИЯ ОБФУСКАЦИИ")
    if choice == "0" or not choice.isdigit():
        return
        
    p_idx = int(choice) - 1
    if 0 <= p_idx < len(profiles):
        prof = profiles[p_idx]
        
        res = _awg_generate_wizard(state, p)
        if res:
            strategy, carrier = res
            carrier_str = carrier if carrier else "generic"
            preset_name = f"{strategy}:{carrier_str}"
            info("Генерация новых параметров обфускации и hot-reload...")
            if p.rotate_obfuscation(state, profile=prof["name"], preset=preset_name):
                success("Параметры успешно ротированы без downtime!")
                info("Клиенты автоматически получат новые настройки при обновлении подписки.")
            else:
                error("Ошибка ротации")
            prompt("Нажмите Enter")


def _tune_awg_hardware(state: AppState, p):
    info("Анализ и оптимизация VPS...")
    from hydra.plugins.amneziawg.tuning import hw_tune_all
    report = hw_tune_all()
    
    lines = []
    
    # sysctl
    sysctl_changed = sum(1 for v in report["sysctl"].values() if v.get("changed"))
    lines.append("🎛️  Параметры sysctl:")
    if sysctl_changed:
        lines.append(f"     Применено {sysctl_changed} новых оптимизаций.")
    else:
        lines.append("     Все параметры sysctl уже оптимальны.")
        
    # swap
    swap = report["swap"]
    lines.append("💾  Файл подкачки (Swap):")
    if swap["changed"]:
        lines.append(f"     Создан /swapfile размером {swap['target_swap_mb']}M.")
    else:
        lines.append(f"     Текущий swap ({swap['current_swap_mb']}M) достаточен.")
        
    # nic
    nic = report["nic"]
    lines.append("🔌  Сетевой интерфейс:")
    if nic["changed"]:
        lines.append(f"     Включены offloads {nic['changed']} на {nic['iface']}.")
    elif nic["skipped"]:
        lines.append(f"     Пропущено: {nic['skipped']}.")
        
    panel("✅ VPS TUNING REPORT", lines)
    prompt("Нажмите Enter")


def _menu_mieru(state: AppState, p):
    from hydra.core.state import get_protocol
    
    while True:
        clear()
        ps = get_protocol(state, p.meta.name)
        
        # Статус
        try:
            st = p.status()
            current_preset = p.get_current_preset(state)
            
            details = [("Обфускация", f"{BOLD}{CYAN}{current_preset}{NC}")]
            details.extend((st.info or {}).items())
            protocol_status_panel(
                p.meta.name, installed=st.installed, enabled=st.enabled,
                running=st.running, port=st.port, details=details,
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name, installed=ps.installed, enabled=ps.enabled,
                running=False, port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )
        
        options = []
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
                options.append(("3", "🔒 Обфускация трафика", f"Текущий пресет: {current_preset}"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))
            
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))
        
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, protocol_menu_title(p.meta.name))
        
        if choice == "0":
            break
            
        elif choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if orchestrator.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error("Ошибка применения конфигурации")
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if orchestrator.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error("Ошибка применения конфигурации")
            else:
                try:
                    if orchestrator.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error("Ошибка применения конфигурации")
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")
            
        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)
            
        elif choice == "3" and ps.installed and ps.enabled:
            _menu_mieru_obfuscation(state, p)
            
        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = orchestrator.reinstall_plugin(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")
                
        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить Mieru?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return


def _menu_mieru_obfuscation(state: AppState, p):
    from hydra.plugins.mieru.presets import list_presets
    
    while True:
        clear()
        current_preset = p.get_current_preset(state)
        presets = list_presets()
        
        lines = [
            f"Текущий пресет обфускации: {BOLD}{CYAN}{current_preset}{NC}",
            "",
            "Смена пресета перегенерирует конфигурацию sing-box.",
            "Клиенты получат новые настройки при обновлении подписки.",
        ]
        panel("🔒 ОБФУСКАЦИЯ ТРАФИКА MIERU", lines)
        print()
        
        options = []
        for idx, pr in enumerate(presets, 1):
            marker = "  "
            if pr["name"] == current_preset:
                marker = "• "
            options.append((str(idx), f"{marker}{pr['label']}", pr["description"]))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "ОБФУСКАЦИЯ MIERU")
        if choice == "0":
            break
            
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(presets):
                preset_name = presets[idx]["name"]
                info(f"Применяю пресет обфускации {preset_name}...")
                if p.set_preset(state, preset_name):
                    success(f"Пресет {preset_name} успешно применён!")
                else:
                    error("Не удалось применить пресет")
                prompt("Нажмите Enter")


def _menu_anytls(state: AppState, p):
    from hydra.core.state import get_protocol
    
    while True:
        clear()
        ps = get_protocol(state, p.meta.name)
        
        # Статус
        try:
            st = p.status()
            current_preset = p.get_current_preset(state)
            from hydra.plugins.anytls.presets import get_preset
            preset_label = get_preset(current_preset)["label"]
            
            details = [("Обфускация", f"{BOLD}{CYAN}{preset_label}{NC}")]
            details.extend((st.info or {}).items())
            protocol_status_panel(
                p.meta.name, installed=st.installed, enabled=st.enabled,
                running=st.running, port=st.port, details=details,
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name, installed=ps.installed, enabled=ps.enabled,
                running=False, port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )
        
        options = []
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
                options.append(("3", "🔒 Обфускация трафика", f"Текущий режим: {preset_label}"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))
            
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))
        
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, protocol_menu_title(p.meta.name))
        
        if choice == "0":
            break
            
        elif choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if orchestrator.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error("Ошибка применения конфигурации")
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if orchestrator.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error("Ошибка применения конфигурации")
            else:
                try:
                    if orchestrator.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error("Ошибка применения конфигурации")
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")
            
        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)
            
        elif choice == "3" and ps.installed and ps.enabled:
            _menu_anytls_obfuscation(state, p)
            
        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = orchestrator.reinstall_plugin(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")
                
        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить AnyTLS?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return


def _menu_anytls_obfuscation(state: AppState, p):
    from hydra.plugins.anytls.presets import list_presets, get_preset
    
    while True:
        clear()
        current_preset = p.get_current_preset(state)
        presets = list_presets()
        preset_label = get_preset(current_preset)["label"]
        
        lines = [
            f"Текущий режим обфускации: {BOLD}{CYAN}{preset_label}{NC}",
            "",
            "Смена режима перегенерирует конфигурацию sing-box.",
            "Клиенты получат новые настройки при подключении/обновлении.",
        ]
        panel("🔒 ОБФУСКАЦИЯ ТРАФИКА ANYTLS", lines)
        print()
        
        options = []
        for idx, pr in enumerate(presets, 1):
            marker = "  "
            if pr["name"] == current_preset:
                marker = "• "
            options.append((str(idx), f"{marker}{pr['label']}", pr["description"]))
            
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, "ОБФУСКАЦИЯ ANYTLS")
        if choice == "0":
            break
            
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(presets):
                preset_name = presets[idx]["name"]
                info(f"Применяю пресет обфускации {preset_name}...")
                if p.set_preset(state, preset_name):
                    success(f"Пресет {preset_name} успешно применён!")
                else:
                    error("Не удалось применить пресет")
                prompt("Нажмите Enter")


def _menu_trusttunnel(state: AppState, p):
    """Подменю управления TrustTunnel."""
    from hydra.core.state import get_protocol

    while True:
        clear()
        ps = get_protocol(state, p.meta.name)

        try:
            st = p.status()
            domain = ps.config.get("domain", "") if ps.config else ""
            transport = ps.config.get("transport", "tcp") if ps.config else "tcp"
            transport_labels = {
                "tcp": "HTTP/2 TCP",
                "quic": "QUIC UDP",
                "both": "HTTP/2 + QUIC",
            }
            details = [
                ("Домен", domain),
                ("Транспорт", transport_labels.get(transport, "HTTP/2 TCP")),
            ]
            details.extend((st.info or {}).items())
            protocol_status_panel(
                p.meta.name, installed=st.installed, enabled=st.enabled,
                running=st.running, port=st.port, details=details,
            )
        except Exception as exc:
            protocol_status_panel(
                p.meta.name, installed=ps.installed, enabled=ps.enabled,
                running=False, port=ps.port,
                error=str(exc) or exc.__class__.__name__,
            )

        options = []
        if not ps.installed:
            options.append(("1", "🔧 Установить", p.meta.description))
        else:
            if ps.enabled:
                options.append(("1", "⏸️  Выключить", "Отключить протокол"))
                options.append(("2", "👥 Клиенты", "Подключённые клиенты и трафик"))
            else:
                options.append(("1", "▶️  Включить", "Активировать протокол"))

            options.append(("3", "🌐 Транспорт", "HTTP/2 TCP / QUIC UDP / оба"))
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))

        options.append(("0", "↩ Назад", ""))

        choice = menu(options, protocol_menu_title(p.meta.name))

        if choice == "0":
            break

        elif choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    try:
                        if orchestrator.enable(state, p.meta.name):
                            success("Протокол включён и применён")
                        else:
                            error("Ошибка применения конфигурации")
                    except Exception as e:
                        error(f"Ошибка активации протокола: {e}")
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                if orchestrator.disable(state, p.meta.name):
                    success("Протокол выключен")
                else:
                    error("Ошибка применения конфигурации")
            else:
                try:
                    if orchestrator.enable(state, p.meta.name):
                        success("Протокол включён")
                    else:
                        error("Ошибка применения конфигурации")
                except Exception as e:
                    error(f"Ошибка активации протокола: {e}")
            prompt("Нажмите Enter")

        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)

        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                ok = orchestrator.reinstall_plugin(state, p.meta.name)
                if ok:
                    success("Переустановлено!")
                else:
                    error("Ошибка установки")
                prompt("Нажмите Enter")

        elif choice == "9" and ps.installed:
            if confirm("Вы уверены, что хотите полностью удалить TrustTunnel?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                success("Удалено")
                prompt("Нажмите Enter")
                return

        elif choice == "3" and ps.installed:
            current = ps.config.get("transport", "tcp")
            mode_choice = menu([
                ("1", "HTTP/2 TCP", "Стабильный режим по умолчанию"),
                ("2", "QUIC UDP", "Экспериментальный HTTP/3 через Caddy UDP proxy"),
                ("3", "HTTP/2 + QUIC", "Две клиентские ссылки"),
                ("0", "Отмена", "Оставить текущий режим"),
            ], "ТРАНСПОРТ TRUSTTUNNEL")
            selected = {"1": "tcp", "2": "quic", "3": "both"}.get(mode_choice)
            if selected is not None:
                if selected == current:
                    info("Этот транспорт уже выбран")
                elif p.set_transport(state, selected):
                    success("Транспорт изменён")
                else:
                    error(
                        "Не удалось применить транспорт. Проверьте конфликт UDP/443, "
                        "сертификат и журнал sing-box; прежняя конфигурация восстановлена."
                    )
                prompt("Нажмите Enter")








def _awg_generate_wizard_menu(state: AppState, p):
    profiles = p.get_profiles(state)
    options = []
    for idx, prof in enumerate(profiles, 1):
        options.append((str(idx), f"Применить к {prof['label']} ({prof['interface']})", f"Текущий пресет: {prof['preset']}"))
    options.append(("0", "Отмена", ""))
    
    choice = menu(options, "ВЫБЕРИТЕ ПРОФИЛЬ ДЛЯ ГЕНЕРАЦИИ")
    if choice == "0" or not choice.isdigit():
        return
        
    p_idx = int(choice) - 1
    if 0 <= p_idx < len(profiles):
        prof = profiles[p_idx]
        res = _awg_generate_wizard(state, p)
        if res:
            strategy, carrier = res
            carrier_str = carrier if carrier else "generic"
            preset_name = f"{strategy}:{carrier_str}"
            info("Генерация новых параметров обфускации и hot-reload...")
            if p.rotate_obfuscation(state, profile=prof["name"], preset=preset_name):
                success("Параметры успешно применены!")
                info("Клиенты автоматически получат новые настройки при обновлении подписки.")
            else:
                error("Ошибка применения параметров.")
            prompt("Нажмите Enter")


def _awg_generate_wizard(state: AppState, p) -> tuple[str, str | None] | None:
    from hydra.plugins.amneziawg.presets import list_strategies, list_carriers, generate_params, STRATEGIES, CARRIER_OVERRIDES

    # Step 1: Select Strategy
    strategies = list_strategies()
    strat_opts = []
    for idx, s in enumerate(strategies, 1):
        strat_opts.append((str(idx), s["label"], s["description"]))
    strat_opts.append(("0", "Отмена", ""))
    
    choice = menu(strat_opts, "ШАГ 1: ВЫБЕРИТЕ СТРАТЕГИЮ (ТИП СЕТИ)")
    if choice == "0" or not choice.isdigit():
        return None
        
    s_idx = int(choice) - 1
    if not (0 <= s_idx < len(strategies)):
        return None
        
    strategy = strategies[s_idx]["name"]
    carrier = None
    
    # Step 2: Select Carrier if mobile
    if strategy == "mobile":
        carriers = list_carriers(strategy)
        carrier_opts = []
        for idx, c in enumerate(carriers, 1):
            carrier_opts.append((str(idx), c["label"], c["description"]))
        carrier_opts.append(("0", "Отмена", ""))
        
        c_choice = menu(carrier_opts, "ШАГ 2: ВЫБЕРИТЕ ОПЕРАТОРА СВЯЗИ")
        if c_choice == "0" or not c_choice.isdigit():
            return None
            
        c_idx = int(c_choice) - 1
        if not (0 <= c_idx < len(carriers)):
            return None
            
        carrier = carriers[c_idx]["name"]
        if carrier == "generic":
            carrier = None

    # Step 3: Loop for Preview & Regeneration
    while True:
        params = generate_params(strategy=strategy, carrier=carrier)
        
        strat_label = STRATEGIES[strategy].label
        carrier_label = "Универсальный мобильный"
        if carrier:
            carrier_label = CARRIER_OVERRIDES[carrier].label
        elif strategy != "mobile":
            carrier_label = "Не требуется (проводной/stealth)"
            
        lines = [
            f"  Стратегия:  {strat_label}",
            f"  Оператор:   {carrier_label}",
            "",
            f"  Jc   = {params['Jc']:<6}  S1 = {params['S1']:<6}  H1 = {params['H1']}",
            f"  Jmin = {params['Jmin']:<6}  S2 = {params['S2']:<6}  H2 = {params['H2']}",
            f"  Jmax = {params['Jmax']:<6}  S3 = {params['S3']:<6}  H3 = {params['H3']}",
            f"                  S4 = {params['S4']:<6}  H4 = {params['H4']}",
            "",
            f"  I1   = {params['I1'] if params['I1'] else 'Отсутствует'}",
            "",
            f"  {GREEN}ⓘ{NC}  S1({params['S1']}) + 56 = {int(params['S1'])+56} != S2({params['S2']}) — сигнатура WireGuard устранена",
            f"  {GREEN}ⓘ{NC}  Заголовки H1-H4 полностью уникальны и рандомизированы",
        ]
        
        clear()
        panel("🎲 СГЕНЕРИРОВАННЫЕ ПАРАМЕТРЫ ОБФУСКАЦИИ", lines)
        
        confirm_opts = [
            ("1", "✅ Применить эти параметры", "Сохранить и перезапустить туннель с ними"),
            ("2", "🔄 Перегенерировать", "Сгенерировать другие случайные значения"),
            ("0", "❌ Отмена", "Выйти без сохранения"),
        ]
        
        ans = menu(confirm_opts, "ПОДТВЕРЖДЕНИЕ ГЕНЕРАЦИИ")
        if ans == "1":
            return strategy, carrier
        elif ans == "2":
            continue
        else:
            return None
