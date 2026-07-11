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
from datetime import datetime
from pathlib import Path

from hydra.core.state import (
    AppState, User, save_state, find_user, get_protocol,
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
from hydra.services.subscriptions.generator import get_subscription_url
from hydra.services.traffic import collect_traffic, update_user_traffic
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt, panel, kv,
    confirm, _bytes_auto, _bar, _ok,
    BANNER, GREEN, CYAN, YELLOW, RED, BOLD, DIM, WHITE, NC,
    PANEL_W,
)



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
    global _cached_pub_ip, _cached_country_flag, _network_fetched
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


def _sys_info(state: AppState | None = None) -> list[str]:
    """Возвращает строки с информацией о системе и сети."""
    lines = []
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        boot = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot
        d, r = divmod(int(uptime.total_seconds()), 86400)
        h, m = divmod(r, 3600)
        m, _ = divmod(m, 60)
        lines.append(kv("CPU:", f"{cpu:.0f}%"))
        lines.append(kv("RAM:", f"{mem.percent:.0f}%  ({_bytes_auto(mem.used)} / {_bytes_auto(mem.total)})"))
        lines.append(kv("Диск:", f"{disk.percent:.0f}%  ({_bytes_auto(disk.used)} / {_bytes_auto(disk.total)})"))
        lines.append(kv("Uptime:", f"{d}д {h:02d}:{m:02d}"))
    except ImportError:
        # Резервный сбор метрик через стандартную библиотеку и /proc (на Linux)
        try:
            import shutil
            
            # 1. Диск через shutil (стандартная библиотека)
            total_d, used_d, free_d = shutil.disk_usage("/")
            disk_pct = (used_d / total_d) * 100 if total_d > 0 else 0
            
            # 2. Метрики для Unix-систем
            uptime_str = "—"
            load_str = "—"
            mem_str = "—"
            
            if os.name != "nt":
                # Uptime из /proc/uptime
                uptime_file = Path("/proc/uptime")
                if uptime_file.exists():
                    with open(uptime_file, "r") as f:
                        uptime_sec = float(f.readline().split()[0])
                    d, r = divmod(int(uptime_sec), 86400)
                    h, m = divmod(r, 3600)
                    m, _ = divmod(m, 60)
                    uptime_str = f"{d}д {h:02d}:{m:02d}"
                
                # Средняя нагрузка (Load Average)
                avg1, avg5, _ = os.getloadavg()
                load_str = f"{avg1:.2f}, {avg5:.2f}"
                
                # RAM из /proc/meminfo
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
                    m_pct = (m_used / m_total) * 100 if m_total > 0 else 0
                    mem_str = f"{m_pct:.0f}%  ({_bytes_auto(m_used)} / {_bytes_auto(m_total)})"
            
            if load_str != "—":
                lines.append(kv("Load Avg:", load_str))
            if mem_str != "—":
                lines.append(kv("RAM:", mem_str))
            lines.append(kv("Диск:", f"{disk_pct:.0f}%  ({_bytes_auto(used_d)} / {_bytes_auto(total_d)})"))
            if uptime_str != "—":
                lines.append(kv("Uptime:", uptime_str))
        except Exception:
            pass
    except Exception:
        pass
        
    # Добавление сетевой информации (асинхронно, без фризов интерфейса)
    try:
        from hydra.utils.net import local_ip
        loc = local_ip()
        
        # Получаем внешний IP (берем из кэша, если пуст — пробуем AppState)
        pub_ip = _cached_pub_ip
        if pub_ip == "Получение..." and state and state.network.server_ip:
            pub_ip = state.network.server_ip
            
        flag_suffix = f" {_cached_country_flag}" if _cached_country_flag else ""
        # Если публичный и локальный совпадают (нет NAT), выводим один IP для красоты
        if pub_ip == loc:
            lines.append(kv("IP (Public):", f"{CYAN}{pub_ip}{NC}{flag_suffix}"))
        else:
            lines.append(kv("IP (Pub/Loc):", f"{CYAN}{pub_ip}{NC}{flag_suffix} / {DIM}{loc}{NC}"))
            
        dns_display = _cached_dns
        try:
            import subprocess
            import re
            r = subprocess.run(["systemctl", "is-active", "dnscrypt-proxy"], capture_output=True, text=True, timeout=1)
            if r.stdout.strip() == "active":
                conf_path = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
                if conf_path.exists():
                    content = conf_path.read_text(encoding="utf-8")
                    m = re.search(r"^server_names\s*=\s*\[(.*?)\]", content, flags=re.MULTILINE | re.DOTALL)
                    if m:
                        names_str = m.group(1)
                        names = [n.strip("'\" ") for n in names_str.split(",") if n.strip("'\" ")]
                        if names:
                            dns_display = f"{GREEN}DNSCrypt ({', '.join(names)}){NC}"
                        else:
                            dns_display = f"{GREEN}DNSCrypt (весь пул){NC}"
                    else:
                        dns_display = f"{GREEN}DNSCrypt (активен){NC}"
                else:
                    dns_display = f"{GREEN}DNSCrypt (активен){NC}"
        except Exception:
            pass

        lines.append(kv("DNS:", dns_display))
    except Exception:
        pass

    return lines


def _select_user(state: AppState, prompt_text: str = "") -> User | None:
    """Показывает нумерованный список пользователей и возвращает выбранного."""
    if not state.users:
        warn("Нет пользователей.")
        return None

    update_user_traffic(state)
    print(f"\n  {CYAN}Пользователи:{NC}\n")
    for i, u in enumerate(state.users, 1):
        ico = f"{RED}🔴{NC}" if u.blocked else f"{GREEN}🟢{NC}"
        used = _bytes_auto(u.traffic_used_bytes)
        lim = f"{u.traffic_limit_gb} GB" if u.traffic_limit_gb else "∞"
        ttl = u.expiry_date[:10] if u.expiry_date else "∞"
        print(f"  {i}. {ico} {BOLD}{u.email:<24}{NC}  {used} / {lim}  TTL: {ttl}")
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
    """Детальная информация о пользователе + ссылки."""
    clear()
    update_user_traffic(state)
    used = user.traffic_used_bytes
    lim = int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0
    ico = f"{RED}🔴{NC}" if user.blocked else f"{GREEN}🟢{NC}"

    protos = []
    for p in enabled(state):
        link = ""
        try:
            link = p.client_link(user, state) or ""
        except Exception:
            pass
        protos.append(f"  {p.meta.name:<14} {GREEN}{p.status().port or '—'}{NC}  {DIM}{link[:50]}{NC}")

    panel(f"Пользователь {user.email}", [
        kv("Статус:", f"{'ЗАБЛОКИРОВАН' if user.blocked else 'АКТИВЕН'}"),
        kv("UUID:", user.uuid),
        kv("Трафик:", f"{_bytes_auto(used)} / {user.traffic_limit_gb or '∞'} GB"),
        *([kv("Прогресс:", _bar(used, lim))] if user.traffic_limit_gb else []),
        kv("TTL:", user.expiry_date[:10] if user.expiry_date else "∞"),
        kv("Создан:", user.created_at[:10] if user.created_at else "—"),
        kv("Telegram ID:", str(user.telegram_id or "—")),
        "",
        f"  {BOLD}Протоколы:{NC}",
        *protos,
    ])
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
                if vpn_link:
                    try:
                        import qrcode
                        qr = qrcode.QRCode()
                        qr.add_data(vpn_link)
                        qr.print_ascii()
                    except ImportError:
                        pass
                elif link:
                    try:
                        import qrcode
                        qr = qrcode.QRCode()
                        qr.add_data(link)
                        qr.print_ascii()
                    except ImportError:
                        pass
                if conf:
                    print(f"  {DIM}{'─' * PANEL_W}{NC}")
                    for line in conf.splitlines():
                        print(f"  {DIM}{line}{NC}")
                    print(f"  {DIM}{'─' * PANEL_W}{NC}")
                print()
            continue

        conf = ""
        link = ""
        try:
            conf = p.generate_client_config(user, state) or ""
        except Exception:
            pass
        try:
            link = p.client_link(user, state) or ""
        except Exception:
            pass
        if not conf and not link:
            continue
        print(f"  {CYAN}── {BOLD}{p.meta.name}{NC}{CYAN}{'─' * (PANEL_W - 10 - len(p.meta.name))}{NC}")
        if link:
            print(f"  {GREEN}Ссылка:{NC}  {link}")
            try:
                import qrcode
                qr = qrcode.QRCode()
                qr.add_data(link)
                qr.print_ascii()
            except ImportError:
                pass
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
        print(BANNER)

        sb_ok = singbox_installed() and is_running()
        plugins = status_all()

        active_t = sum(1 for p in transports() if plugins.get(p.meta.name, {}).get("running"))
        total_t = len(transports())

        active_e = sum(1 for p in enhancements() if plugins.get(p.meta.name, {}).get("running"))
        total_e = len(enhancements())

        active_s = sum(1 for p in sec_plugins() if plugins.get(p.meta.name, {}).get("running"))
        total_s = len(sec_plugins())

        u_active = sum(1 for u in state.users if not u.blocked)

        lines = [
            kv("Sing-Box:", f"{_ok(sb_ok)}  {singbox_version() or 'не установлен'}"),
            kv("Протоколы:", f"{GREEN}{active_t}{NC}/{total_t} активны"),
            kv("Сетевые службы:", f"{GREEN}{active_e}{NC}/{total_e} активны"),
            kv("Безопасность:", f"{GREEN}{active_s}{NC}/{total_s} активны"),
            kv("Пользователи:", f"{GREEN if u_active else YELLOW}{u_active}{NC} из {len(state.users)}"),
        ]
        lines += _sys_info(state)
        panel("Состояние", lines)

        choice = menu(
            [
                ("1", "📦 Ядро и система",       "Установка Sing-Box, зависимости, применить конфиг"),
                ("2", "🧩 Протоколы",           f"Транспорты (Naive, AmneziaWG, Mieru...)  [{active_t}/{total_t}]"),
                ("3", "👥 Пользователи",        f"Создание, лимиты, TTL, подписки  [{u_active} активно]"),
                ("4", "🤖 Telegram-боты",       "Admin-панель и клиентский бот"),
                ("5", "📊 Мониторинг",          "Трафик, статус, sync-агент, логи"),
                ("6", "🔒 Безопасность",        f"Fail2ban, Honeypot, IPBan  [{active_s}/{total_s}]"),
                ("7", "🌐 Сетевые службы",      f"DNSCrypt, WARP (DNS и маршрутизация)  [{active_e}/{total_e}]"),
                ("8", "🛠️  Тестирование и отладка", "Проверка скорости, блокировок, GeoIP и CPU"),
                ("0", "🚪 Выход", ""),
            ],
            "HYDRA MULTI-PROXY MANAGER",
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
        clear()
        ok_i = singbox_installed()
        ok_r = is_running()
        ver = singbox_version()

        panel("Sing-Box", [
            kv("Статус:", f"{_ok(ok_r)} {'запущен' if ok_r else 'остановлен'}"),
            kv("Версия:", ver or "—"),
            kv("Конфиг:", f"{DIM}/etc/sing-box/config.json{NC}"),
            kv("Лог:", f"{DIM}/var/log/sing-box/sing-box.log{NC}"),
        ])

        choice = menu(
            [
                ("1", "📦 Установить Sing-Box Extended" if not ok_i else "🔄 Переустановить",
                 "shtorm-7/sing-box-extended"),
                ("2", "▶️  Запустить" if not ok_r else "⏸️  Остановить", ""),
                ("3", "🔄 Применить конфиг",
                 "Собрать /etc/sing-box/config.json и перезагрузить"),
                ("0", "↩ Назад", ""),
            ],
            "ЯДРО И СИСТЕМА",
        )

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
            ico = f"{GREEN}●{NC}" if s.get("running") else (f"{YELLOW}●{NC}" if s.get("installed") else f"{DIM}●{NC}")
            port = f":{s['port']}" if s.get("port") else ""
            st_txt = "вкл" if s.get("enabled") else "выкл"
            transport_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{st_txt:>4}{NC}  порт{port}")

        lines = [
            f"  {BOLD}Транспорты:{NC}",
            *transport_lines,
        ]
        panel("Протоколы", lines)

        all_p = transports()
        opts: list[tuple[str, str, str]] = []
        for i, p in enumerate(all_p, 1):
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}✓{NC}" if s.get("running") else (f"{YELLOW}⚠{NC}" if s.get("installed") else f"{RED}✗{NC}")
            opts.append((str(i),
                         f"{ico} {p.meta.name}",
                         f"порт {s['port']}" if s.get("port") else "не установлен"))
        opts += [("-", "", ""), ("0", "↩ Назад", "")]

        choice = menu(opts, "УПРАВЛЕНИЕ ПРОТОКОЛАМИ")
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
    if p.meta.name == "mieru":
        _menu_mieru(state, p)
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
        
        # Статус
        try:
            st = p.status()
            lines = [
                f"  Статус:      {'🟢 Работает' if st.running else '🔴 Остановлен'}",
                f"  Установлен:  {_ok(st.installed)}",
                f"  Включён:     {_ok(st.enabled)}",
            ]
            if st.port:
                lines.append(f"  Порт:        {st.port}")
            if st.info:
                for k, v in st.info.items():
                    lines.append(f"  {k}: {v}")
            panel(f"🛡️ {p.meta.name.upper()} CONTROL", lines)
        except Exception:
            panel(p.meta.name.upper(), ["  Статус недоступен"])
        print()
        
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
            
            options.append(("8", "🔄 Переустановить", "Переустановка протокола"))
            options.append(("9", "❌ Удалить", "Полное удаление"))
        
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, p.meta.name.upper())
        
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
        
        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    try:
                        orchestrator.enable(state, p.meta.name)
                    except Exception as e:
                        error(f"Ошибка активации/настройки: {e}")
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
        active = sum(1 for u in state.users if not u.blocked)
        info(f"Всего: {total}  |  Активных: {active}")
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
        status_icon = f"{GREEN}🟢{NC}" if not user.blocked else f"{RED}🔴{NC}"
        sub_url = get_subscription_url(user, state)
        lim_str = f"{user.traffic_limit_gb} GB" if user.traffic_limit_gb else "∞"
        ttl_str = user.expiry_date[:10] if user.expiry_date else "∞"
        lines = [
            f"  Email:    {status_icon} {user.email}",
            f"  UUID:     {user.uuid}",
            f"  Трафик:   {_bytes_auto(user.traffic_used_bytes)} / {lim_str}",
            f"  TTL:      {ttl_str}",
            f"  Создан:   {user.created_at[:10] if user.created_at else '—'}",
        ]
        
        prefix = "  Подписка: "
        link_width = 60
        chunks = [sub_url[i:i+link_width] for i in range(0, len(sub_url), link_width)]
        if chunks:
            lines.append(f"{prefix}{CYAN}{chunks[0]}{NC}")
            for chunk in chunks[1:]:
                lines.append(f"{' ' * len(prefix)}{CYAN}{chunk}{NC}")
        else:
            lines.append(f"{prefix}{CYAN}{NC}")

        panel(f"Пользователь: {user.email}", lines)
        print()
        
        # Показать доступные протоколы
        from hydra.plugins import registry
        enabled_transports = registry.enabled(state, PluginCategory.TRANSPORT)
        if enabled_transports:
            proto_names = ", ".join(p.meta.name for p in enabled_transports)
            info(f"Включённые протоколы: {proto_names}")
        else:
            warn("Нет включённых транспортных протоколов")
        print()
        
        block_label = "Разблокировать" if user.blocked else "Заблокировать"
        
        choice = menu([
            ("1", "📄 Конфиги и ссылки", "Показать конфиги всех протоколов"),
            ("2", f"🔒🔓 {block_label}", "Переключить статус блокировки"),
            ("3", "📝 Изменить лимит трафика", "Задать квоту трафика в GB"),
            ("4", "⏳ Изменить срок действия подписки", "Задать дату окончания TTL"),
            ("5", "❌ Удалить", "Удалить пользователя"),
            ("0", "↩ Назад", ""),
        ], f"ПОЛЬЗОВАТЕЛЬ {user.email}")
        
        if choice == "1":
            _user_configs(state, user)
        elif choice == "2":
            _toggle_block(state, user)
        elif choice == "3":
            new_lim = prompt("Введите лимит трафика в GB (0 или пусто для безлимита)", default=str(user.traffic_limit_gb or ""))
            try:
                val = float(new_lim) if new_lim.strip() else 0.0
                user.traffic_limit_gb = val
                save_state(state)
                success(f"Лимит трафика для {user.email} установлен в {val or '∞'} GB")
                
                # Если пользователь был заблокирован, проверяем возможность авторазблокировки
                limit_bytes = int(val * 1073741824) if val else 0
                if user.blocked and (limit_bytes == 0 or user.traffic_used_bytes <= limit_bytes):
                    is_expired = False
                    if user.expiry_date:
                        try:
                            expiry = datetime.fromisoformat(user.expiry_date)
                            now = datetime.now(expiry.tzinfo)
                            if expiry < now:
                                is_expired = True
                        except Exception:
                            pass
                    if not is_expired:
                        if confirm(f"Пользователь {user.email} теперь укладывается в лимиты. Разблокировать его?", default=True):
                            orchestrator.unblock_user(state, user.email)
                            success("Пользователь разблокирован")
                prompt("Нажмите Enter")
            except ValueError:
                error("Неверный формат числа!")
                prompt("Нажмите Enter")
        elif choice == "4":
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
                    
            # Авторазблокировка при соответствии лимитам
            if user.blocked:
                limit_bytes = int(user.traffic_limit_gb * 1073741824) if user.traffic_limit_gb else 0
                is_traffic_exceeded = limit_bytes > 0 and user.traffic_used_bytes > limit_bytes
                is_expired = False
                if user.expiry_date:
                    try:
                        expiry = datetime.fromisoformat(user.expiry_date)
                        now = datetime.now(expiry.tzinfo)
                        if expiry < now:
                            is_expired = True
                    except Exception:
                        pass
                if not is_expired and not is_traffic_exceeded:
                    if confirm(f"Пользователь {user.email} теперь укладывается в лимиты. Разблокировать его?", default=True):
                        orchestrator.unblock_user(state, user.email)
                        success("Пользователь разблокирован")
            prompt("Нажмите Enter")
        elif choice == "5":
            if confirm(f"Удалить {user.email}?", default=False):
                orchestrator.remove_user(state, user.email)
                success(f"Пользователь {user.email} удалён")
                prompt("Нажмите Enter")
                return
        elif choice == "0":
            return


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
            ("4", "🌐 Настроить домен подписок", "Задать выделенный домен для скрытия порта"),
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

    # Ссылка на подписку
    sub_url = get_subscription_url(user, state)
    print(f"  {YELLOW}{BOLD}Base64 Subscription (v2rayNG, Shadowrocket, NekoBox, Karing):{NC}")
    print(f"  {CYAN}{sub_url}{NC}")
    print()
    
    from hydra.plugins import registry
    enabled_transports = registry.enabled(state, PluginCategory.TRANSPORT)
    
    if not enabled_transports:
        warn("Нет включённых транспортных протоколов")
        prompt("Нажмите Enter")
        return
    
    for p in enabled_transports:
        # Ссылка
        link = ""
        try:
            link = p.client_link(user, state)
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
                
                # QR-код (если qrcode установлен)
                try:
                    import qrcode
                    qr = qrcode.QRCode(border=1)
                    qr.add_data(link_main)
                    print(f"\n  {BOLD}{WHITE}Отсканируйте QR-код для быстрого импорта (Основной):{NC}")
                    qr.print_ascii(invert=True)
                except ImportError:
                    pass
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
                            
                            # Показываем WireGuard/AmneziaWG ссылку
                            if link_prof:
                                box_lines.append(f"{YELLOW}{BOLD}Ссылка для подключения (WireGuard / URL - {label_ru}):{NC}")
                                link_width = PANEL_W - 6
                                for chunk in [link_prof[i:i+link_width] for i in range(0, len(link_prof), link_width)]:
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
                                target = vpn_link if vpn_link else (link_prof if link_prof else conf)
                                qr.add_data(target)
                                print(f"\n  {BOLD}{WHITE}Отсканируйте QR-код для импорта в Amnezia VPN ({label_ru}):{NC}")
                                qr.print_ascii(invert=True)
                            except ImportError:
                                pass
                    except Exception as e:
                        error(f"  Ошибка получения конфигурации {p.meta.name} ({prof}): {e}")
                continue

            conf = p.generate_client_config(user, state)
            if conf:
                box_lines = []
                
                # Показываем ссылку, если она есть
                if link:
                    box_lines.append(f"{YELLOW}{BOLD}Ссылка для подключения (URL):{NC}")
                    # Оборачиваем ссылку по ширине коробки (PANEL_W - 6)
                    link_width = PANEL_W - 6
                    for chunk in [link[i:i+link_width] for i in range(0, len(link), link_width)]:
                        box_lines.append(f"  {CYAN}{chunk}{NC}")
                    box_lines.append(f"{DIM}{'─' * (PANEL_W - 4)}{NC}")
                
                # Показываем конфиг
                box_lines.append(f"{GREEN}{BOLD}Файл конфигурации (Client Config):{NC}")
                for line in conf.splitlines():
                    box_lines.append(f"  {DIM}{line.rstrip()}{NC}")
                
                panel(f"🔧  {p.meta.name.upper()} CONFIG", box_lines)
                
                # QR-код (если qrcode установлен)
                try:
                    import qrcode
                    qr = qrcode.QRCode(border=1)
                    target = link if link else conf
                    qr.add_data(target)
                    print(f"\n  {BOLD}{WHITE}Отсканируйте QR-код для быстрого импорта:{NC}")
                    qr.print_ascii(invert=True)
                except ImportError:
                    pass
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
    for u in state.users:
        ico = f"{RED}🔴{NC}" if u.blocked else f"{GREEN}🟢{NC}"
        used = u.traffic_used_bytes
        print(f"  {ico} {BOLD}{u.email}{NC}")
        print(f"     Трафик: {_bytes_auto(used)}     UUID: {DIM}{u.uuid[:20]}...{NC}")
        print()
    prompt("Нажмите Enter")


def _add_user(state: AppState):
    """Добавление нового пользователя с автогенерацией конфигов."""
    clear()
    title("Добавить пользователя")
    
    # Показать какие протоколы создадут конфиги
    from hydra.plugins import registry
    enabled_transports = registry.enabled(state, PluginCategory.TRANSPORT)
    
    if enabled_transports:
        proto_names = ", ".join(p.meta.name for p in enabled_transports)
        info(f"Конфиги будут созданы для: {proto_names}")
    else:
        warn("Нет включённых протоколов — конфиги не будут созданы")
    print()
    
    email = prompt("Email пользователя")
    if not email:
        return
    
    # Проверка дубликата
    if find_user(state, email):
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
                
        active_protos = [p for p in state.protocols.values() if p.enabled]
        protos_count = len(active_protos)
        users_count = len(state.users)
        
        lines = [
            f"  📋 {BOLD}Сводный мониторинг и управление лимитами трафика{NC}",
            "────────────────────────────────────────────────────────",
            f"  🔌 {BOLD}Активные протоколы:{NC} {GREEN}{protos_count:<3}{NC} │  👥 {BOLD}Всего клиентов:{NC} {CYAN}{users_count}{NC}",
            f"  🚀 {BOLD}Нагрузка Load Avg:{NC}   {YELLOW}{load_str:<3}{NC} │  💾 {BOLD}Память RAM:{NC}     {RED}{ram_str}{NC}"
        ]
        panel("💻  Мониторинг системы", lines)

        choice = menu(
            [("1", "📊 Потребление трафика", "Сводная статистика по протоколам и пользователям"),
             ("2", "🔌 Активные подключения", "Сессии пользователей в реальном времени"),
             ("3", "📈 Живой монитор CPU/RAM", "Нагрузка системы, скорость сети и метрики"),
             ("4", "🔧 Сервисные настройки", "Управление Clash API, Sync Agent, системные логи"),
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
        clear()
        choice = menu([
            ("1", "📋 Просмотр системных логов", "Sing-Box, Sync-Agent, Fail2ban и др."),
            ("2", "🔄 Управление Sync Agent", "Контроль фоновой службы синхронизации"),
            ("3", "🔧 Настройки Clash API", "Локальный порт и секретный ключ статистики"),
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
    while True:
        clear()
        title("📊 Потребление трафика")
        print()
        
        # 1. Выводим трафик по протоколам
        from hydra.plugins.registry import get as get_plugin
        
        awg_traffic = 0
        p_awg = get_plugin("amneziawg")
        if p_awg:
            try:
                awg_traffic = sum(p_awg.traffic(state).values())
            except Exception:
                pass
                
        naive_traffic = 0
        p_naive = get_plugin("naive")
        if p_naive:
            try:
                naive_traffic = sum(p_naive.traffic(state).values())
            except Exception:
                pass
                
        anytls_traffic = 0
        for u in state.users:
            anytls_traffic += u.credentials.get("anytls", {}).get("traffic_used_bytes", 0)
            
        mieru_traffic = 0
        for u in state.users:
            mieru_traffic += u.credentials.get("mieru", {}).get("traffic_used_bytes", 0)

        trusttunnel_traffic = 0
        for u in state.users:
            trusttunnel_traffic += u.credentials.get("trusttunnel", {}).get("traffic_used_bytes", 0)
            
        total_traffic = awg_traffic + naive_traffic + anytls_traffic + mieru_traffic + trusttunnel_traffic
        
        print(f"  {BOLD}Трафик по протоколам:{NC}")
        print(f"  {BOLD}{'Протокол':<15} {'Потребление':<20}{NC}")
        print(f"  {DIM}{'─' * 38}{NC}")
        print(f"  AmneziaWG       {GREEN}{_bytes_auto(awg_traffic):<20}{NC}")
        print(f"  NaiveProxy      {GREEN}{_bytes_auto(naive_traffic):<20}{NC}")
        print(f"  AnyTLS          {GREEN}{_bytes_auto(anytls_traffic):<20}{NC}")
        print(f"  Mieru           {GREEN}{_bytes_auto(mieru_traffic):<20}{NC}")
        print(f"  TrustTunnel     {GREEN}{_bytes_auto(trusttunnel_traffic):<20}{NC}")
        print(f"  {DIM}{'─' * 38}{NC}")
        print(f"  {BOLD}ИТОГО:          {CYAN}{_bytes_auto(total_traffic):<20}{NC}")
        print()
        
        # 2. Выводим трафик по пользователям
        print(f"  {BOLD}Потребление трафика по пользователям:{NC}")
        print()
        
        update_user_traffic(state)
        users_sorted = list(state.users)
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
            
        print(f"  {BOLD}{'#':<3} {'Пользователь':<25} {'Использовано':<15} {'Лимит':<10} {'Статус':<10} {'Срок':<12}{NC}")
        print(f"  {DIM}{'─' * 77}{NC}")
        for i, u in enumerate(users_sorted, 1):
            used = u.traffic_used_bytes
            status_str = f"{RED}Блок{NC}" if u.blocked else f"{GREEN}Активен{NC}"
            
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
            
            lim_str = f"{u.traffic_limit_gb:.1f} GB" if u.traffic_limit_gb else "∞"
            print(f"  {i:<3d} {BOLD}{u.email:<25}{NC} {_bytes_auto(used):<15} {lim_str:<10} {status_str:<10} {expiry_str:<12}")
            
        print(f"  {DIM}{'─' * 77}{NC}")
        print("  Сортировка: " + (f"{BOLD}[Трафик]{NC}" if sort_by == "traffic" else "[Трафик]") + " " +
                             (f"{BOLD}[Имя]{NC}" if sort_by == "name" else "[Имя]") + " " +
                             (f"{BOLD}[Лимит]{NC}" if sort_by == "limit" else "[Лимит]") + " " +
                             (f"{BOLD}[Срок]{NC}" if sort_by == "expiry" else "[Срок]"))
        print()
        
        choice = menu([
            ("1", "Сортировать по трафику", ""),
            ("2", "Сортировать по имени", ""),
            ("3", "Сортировать по лимиту", ""),
            ("4", "Сортировать по сроку подписки", ""),
            ("D", "🔍 Детальная информация пользователя", ""),
            ("0", "↩ Назад", "")
        ], "УПРАВЛЕНИЕ ТРАФИКОМ")
        
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
        title("🔌 Активные подключения")
        print()
        
        all_clients = []
        for p in enabled(state, PluginCategory.TRANSPORT):
            try:
                try:
                    clients = p.connected_clients(state)
                except TypeError:
                    clients = p.connected_clients()
                    
                for c in clients:
                    c["plugin"] = p.meta.name
                    all_clients.append(c)
            except Exception:
                pass
                
        if not all_clients:
            print(f"  {YELLOW}Нет активных подключений в данный момент.{NC}")
            print()
        else:
            print(f"  {BOLD}{'Протокол':<12} {'Пользователь / IP':<30} {'Трафик Rx/Tx':<20} {'Активность':<15}{NC}")
            print(f"  {DIM}{'─' * PANEL_W}{NC}")
            for c in all_clients:
                plugin_name = c.get("plugin", "unknown")
                email = c.get("email", "?")
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
                    
                status_ico = f"{GREEN}●{NC}" if online else f"{DIM}●{NC}"
                traffic_str = f"{_bytes_auto(rx)} / {_bytes_auto(tx)}" if (rx or tx) else "—"
                
                email_disp = email
                if len(email_disp) > 30:
                    email_disp = email_disp[:27] + "..."
                    
                print(f"  {plugin_name:<12} {status_ico} {BOLD}{email_disp:<28}{NC} {traffic_str:<20} {activity:<15}")
            print()
            
        choice = menu([
            ("R", "🔄 Обновить список", ""),
            ("0", "↩ Назад", "")
        ], "АКТИВНЫЕ ПОДКЛЮЧЕНИЯ")
        
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
        free = meminfo.get("MemFree", 0)
        buffers = meminfo.get("Buffers", 0)
        cached = meminfo.get("Cached", 0)
        used = total - free - buffers - cached
        pct = (used / total) * 100 if total > 0 else 0.0
        return used, total, pct
    except Exception:
        pass
    return 0, 0, 0.0


def _read_proc_net() -> tuple[int, int]:
    try:
        rx = 0
        tx = 0
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()
            for line in lines[2:]:
                if ":" not in line:
                    continue
                if "lo:" in line:
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
            prev_net = psutil.net_io_counters()
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
                    curr_net = psutil.net_io_counters()
                    now = time.time()
                    dt = now - last_time
                    if dt <= 0:
                        dt = 1.0
                    rx_speed = (curr_net.bytes_recv - prev_net.bytes_recv) / dt
                    tx_speed = (curr_net.bytes_sent - prev_net.bytes_sent) / dt
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
        clear()
        title("📋 Просмотр системных логов")
        print()
        
        log_options = [
            ("1", "📋 Sing-Box Core log", "/var/log/sing-box/sing-box.log"),
            ("2", "🔄 Sync Agent log", "/var/log/hydra/sync-agent.log"),
            ("3", "📡 Traffic Daemon log", "/var/log/hydra/traffic-daemon.log")
        ]
        
        f2b_log = Path("/var/log/fail2ban.log")
        hp_log = Path("/var/log/hydra-honeypot.log")
        caddy_log = Path("/var/log/caddy-naive/access.log")
        
        if f2b_log.exists():
            log_options.append(("4", "🔒 Fail2ban log", str(f2b_log)))
        if hp_log.exists():
            log_options.append(("5", "🍯 Honeypot log", str(hp_log)))
        if caddy_log.exists():
            log_options.append(("6", "🌐 Naive Caddy Access log", str(caddy_log)))
            
        print(f"  {BOLD}Текущий лимит строк для просмотра:{NC} {GREEN}{lines_count}{NC}\n")
        
        opts = []
        for key, name, path in log_options:
            exists_str = "доступен" if Path(path).exists() else "не найден"
            opts.append((key, name, f"{path} ({exists_str})"))
            
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
            selected_path = None
            selected_title = ""
            for key, name, path in log_options:
                if choice == key:
                    selected_path = path
                    selected_title = name
                    break
                    
            if selected_path:
                _show_log_file(selected_title, selected_path, lines_count)


def _show_log_file(title_text: str, path_str: str, num_lines: int):
    path = Path(path_str)
    while True:
        clear()
        title(f"{title_text} ({num_lines} строк)")
        print(f"  {DIM}Файл: {path_str}{NC}")
        print()
        
        if not path.exists():
            error("Файл лога не найден.")
            print()
        else:
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                for line in lines[-num_lines:]:
                    print(f"  {DIM}{line}{NC}")
            except Exception as e:
                error(f"Ошибка при чтении лога: {e}")
            print()
            
        choice = menu([
            ("R", "🔄 Обновить", ""),
            ("W", "👀 Следить за логом в реальном времени (Watch)", ""),
            ("0", "↩ Назад", "")
        ], "ПРОСМОТР ЛОГА")
        
        if choice == "0":
            break
        elif choice.upper() == "W":
            _watch_log_file(title_text, path_str)


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


def _menu_sync_agent(state: AppState):
    while True:
        clear()
        
        timer_active = False
        r_timer = subprocess.run(["systemctl", "is-active", "hydra-sync-agent.timer"], capture_output=True, text=True)
        if r_timer.returncode == 0 and r_timer.stdout.strip() == "active":
            timer_active = True
            
        log_path = Path("/var/log/hydra/sync-agent.log")
        last_log_line = "нет логов"
        if log_path.exists():
            try:
                lines = log_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                if lines:
                    last_log_line = lines[-1]
            except Exception:
                pass
                
        lines = [
            kv("Таймер (5 мин):", f"{GREEN}активен 🟢{NC}" if timer_active else f"{RED}отключен 🔴{NC}"),
            kv("Лог-файл:", f"{_bytes_auto(log_path.stat().st_size) if log_path.exists() else 'не создан'}"),
            kv("Последняя запись:", f"{DIM}{last_log_line}{NC}"),
        ]
        panel("Управление Sync Agent", lines)
        
        choice = menu([
            ("1", "⚡ Запустить синхронизацию сейчас", "Принудительно проверить лимиты и TTL"),
            ("2", "✅ Включить таймер (каждые 5 мин)", "Создать и запустить systemd timer"),
            ("3", "❌ Отключить таймер", "Остановить и удалить systemd timer"),
            ("4", "📋 Показать лог sync-agent", "Последние 30 строк лога sync-agent.log"),
            ("0", "↩ Назад", "")
        ], "SYNC AGENT")
        
        if choice == "0":
            break
        elif choice == "1":
            info("Запуск ручной синхронизации...")
            try:
                from hydra.services.sync_agent import run_sync
                run_sync()
                success("Синхронизация успешно выполнена")
            except Exception as e:
                error(f"Ошибка при синхронизации: {e}")
            prompt("Нажмите Enter")
        elif choice == "2":
            install_timer("hydra-sync-agent",
                """[Unit]
Description=HYDRA Sync Agent
After=network.target
[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/hydra
Environment=PYTHONPATH=/opt/hydra
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
            success("Sync Agent таймер установлен и запущен (каждые 5 мин)")
            prompt("Нажмите Enter")
        elif choice == "3":
            info("Удаление таймера...")
            try:
                remove_unit("hydra-sync-agent.timer")
                remove_unit("hydra-sync-agent.service")
                success("Sync Agent таймер удалён")
            except Exception as e:
                error(f"Ошибка при удалении: {e}")
            prompt("Нажмите Enter")
        elif choice == "4":
            _show_log_file("Sync Agent", str(log_path), 30)


def _menu_clash_api(state: AppState):
    while True:
        clear()
        
        enabled_status = getattr(state.network, "clash_api_enabled", False)
        port = getattr(state.network, "clash_api_port", 9090)
        secret = getattr(state.network, "clash_api_secret", "")
        
        daemon_active = False
        r_daemon = subprocess.run(["systemctl", "is-active", "hydra-traffic-daemon.service"], capture_output=True, text=True)
        if r_daemon.returncode == 0 and r_daemon.stdout.strip() == "active":
            daemon_active = True
            
        lines = [
            kv("Clash API:", f"{GREEN}включен 🟢{NC}" if enabled_status else f"{RED}выключен 🔴{NC}"),
            kv("Порт (localhost):", str(port)),
            kv("Секретный ключ:", secret or "(не установлен)"),
            kv("Служба статистики:", f"{GREEN}активна 🟢{NC}" if daemon_active else f"{RED}не активна 🔴{NC}"),
        ]
        panel("Настройки Clash API", lines)
        
        choice = menu([
            ("1", "Включить / Выключить Clash API", "Включение также запустит фоновую службу сбора статистики"),
            ("2", "Изменить порт", "Изменить локальный порт API"),
            ("3", "Изменить секретный ключ", "Задать пароль авторизации"),
            ("0", "↩ Назад", "")
        ], "CLASH API")
        
        if choice == "0":
            break
        elif choice == "1":
            state.network.clash_api_enabled = not enabled_status
            save_state(state)
            info("Пересборка конфигурации Sing-Box...")
            from hydra.core.orchestrator import apply_config
            apply_config(state)
            success("Статус изменен")
            prompt("Нажмите Enter")
        elif choice == "2":
            try:
                new_port = int(prompt("Введите новый порт (1024-65535)", str(port)))
                if 1024 <= new_port <= 65535:
                    state.network.clash_api_port = new_port
                    save_state(state)
                    info("Применение нового порта...")
                    from hydra.core.orchestrator import apply_config
                    apply_config(state)
                    success("Порт изменен")
                else:
                    warn("Неверный диапазон.")
            except ValueError:
                warn("Некорректное число.")
            prompt("Нажмите Enter")
        elif choice == "3":
            new_secret = prompt("Введите секретный ключ (пусто для сброса)", secret)
            state.network.clash_api_secret = new_secret
            save_state(state)
            info("Применение ключа...")
            from hydra.core.orchestrator import apply_config
            apply_config(state)
            success("Ключ изменен")
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
            for p in plugins_list:
                try:
                    _toggle_security_plugin(state, p.meta.name, force_enable=False)
                except Exception:
                    pass
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
    """Включает/выключает security-плагин через его on_enable/on_disable."""
    from hydra.plugins.registry import get as get_plugin
    p = get_plugin(name)
    if not p:
        return

    proto = get_protocol(state, name)
    enabled_val = False

    # Determine target state
    if force_enable is True:
        target_enable = True
    elif force_enable is False:
        target_enable = False
    else:
        target_enable = not (proto and proto.enabled)

    if target_enable:
        # If not installed, install first
        if proto and not proto.installed:
            ok = orchestrator.install_plugin(state, name)
            if not ok:
                raise RuntimeError(f"Не удалось установить плагин {name}")
        p.on_enable(state)
        if proto:
            proto.enabled = True
        enabled_val = True
    else:
        p.on_disable(state)
        if proto:
            proto.enabled = False
        enabled_val = False
            
    if name == "fail2ban":
        state.security.fail2ban_enabled = enabled_val
    elif name == "honeypot":
        state.security.honeypot_enabled = enabled_val
    elif name == "ipban":
        state.security.ipban_enabled = enabled_val
        
    save_state(state)
    orchestrator.apply_config(state)


def _menu_amneziawg(state: AppState, p):
    from hydra.core.state import get_protocol
    
    while True:
        clear()
        ps = get_protocol(state, p.meta.name)
        
        # Статус
        try:
            st = p.status()
            if not st.installed:
                lines = [
                    "  Статус:      🔴 Остановлен",
                    "  Установлен:  🔴 Нет",
                    "  Включён:     🔴 Нет",
                    "  ⚠️ AWG не установлен в системе",
                ]
            else:
                lines = [
                    f"  Статус:      {'🟢 Работает' if st.running else '🔴 Остановлен'}",
                    f"  Установлен:  {_ok(st.installed)}",
                    f"  Включён:     {_ok(st.enabled)}",
                ]
                profiles = p.get_profiles(state)
                lines.append(f"  Профили:     {len(profiles)} active")
                for prof in profiles:
                    lines.append(f"    - {prof['label']} ({prof['interface']}) on port {prof['port']} [{prof['preset']}]")
            
            panel("🛡️ AMNEZIAWG CONTROL", lines)
        except Exception:
            panel("AMNEZIAWG CONTROL", ["  Статус недоступен: AWG не установлен"])
        print()
        
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
        
        choice = menu(options, "AMNEZIAWG")
        
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
                orchestrator.uninstall_plugin(state, p.meta.name)
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    try:
                        orchestrator.enable(state, p.meta.name)
                        success("Переустановлено!")
                    except Exception as e:
                        error(f"Ошибка активации: {e}")
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
            
            lines = [
                f"  Статус:      {'🟢 Работает' if st.running else '🔴 Остановлен'}",
                f"  Установлен:  {_ok(st.installed)}",
                f"  Включён:     {_ok(st.enabled)}",
            ]
            if st.port:
                lines.append(f"  Порт:        {st.port}")
            lines.append(f"  Обфускация:  {BOLD}{CYAN}{current_preset}{NC}")
            if st.info:
                for k, v in st.info.items():
                    lines.append(f"  {k}: {v}")
            panel("🛡️ MIERU CONTROL", lines)
        except Exception:
            panel("MIERU CONTROL", ["  Статус недоступен"])
        print()
        
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
        
        choice = menu(options, "MIERU")
        
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
                orchestrator.uninstall_plugin(state, p.meta.name)
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    try:
                        orchestrator.enable(state, p.meta.name)
                        success("Переустановлено!")
                    except Exception as e:
                        error(f"Ошибка активации: {e}")
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
