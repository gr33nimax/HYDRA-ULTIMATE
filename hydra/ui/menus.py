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
from hydra.services.subscriptions.generator import start_sub_server
from hydra.services.traffic import collect_traffic
from hydra.ui.tui import (
    clear, title, info, success, warn, error, menu, prompt, panel, kv,
    confirm, _bytes_auto, _bar, _ok,
    BANNER, GREEN, CYAN, YELLOW, RED, BOLD, DIM, WHITE, NC,
    PANEL_W,
)

_sub_server = None


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

# 2. Определение IP адресов
_cached_pub_ip = "Получение..."
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
    global _cached_pub_ip, _network_fetched
    try:
        from hydra.utils.net import public_ip
        ip = public_ip()
        _cached_pub_ip = ip
    except Exception:
        _cached_pub_ip = "127.0.0.1"
    _network_fetched = True

# Инициализируем IP-адреса на этапе импорта модуля
try:
    from hydra.utils.net import local_ip
    loc = local_ip()
    if loc and not _is_private_ip(loc):
        # Локальный IP-адрес уже публичный — используем его сразу и не делаем сетевых curl-запросов!
        _cached_pub_ip = loc
        _network_fetched = True
    else:
        # Локальный IP приватный (сервер за NAT) — опрашиваем внешнюю сеть в фоне
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
            
        # Если публичный и локальный совпадают (нет NAT), выводим один IP для красоты
        if pub_ip == loc:
            lines.append(kv("IP (Public):", f"{CYAN}{pub_ip}{NC}"))
        else:
            lines.append(kv("IP (Pub/Loc):", f"{CYAN}{pub_ip}{NC} / {DIM}{loc}{NC}"))
            
        lines.append(kv("DNS:", _cached_dns))
    except Exception:
        pass

    return lines


def _select_user(state: AppState, prompt_text: str = "") -> User | None:
    """Показывает нумерованный список пользователей и возвращает выбранного."""
    if not state.users:
        warn("Нет пользователей.")
        return None

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
    traffic = collect_traffic(state)
    used = traffic.get(user.email, user.traffic_used_bytes)
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
    global _sub_server
    if _sub_server is None:
        try:
            _sub_server = start_sub_server(state)
        except Exception:
            pass

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
            kv("Транспорты:", f"{GREEN}{active_t}{NC}/{total_t} активны"),
            kv("Службы сети:", f"{GREEN}{active_e}{NC}/{total_e} активны"),
            kv("Безопасность:", f"{GREEN}{active_s}{NC}/{total_s} активны"),
            kv("Пользователей:", f"{GREEN if u_active else YELLOW}{u_active}{NC} из {len(state.users)}"),
        ]
        lines += _sys_info(state)
        panel("Состояние", lines)

        choice = menu(
            [
                ("1", "⚙️  Ядро и система",     "Установка Sing-Box, зависимости, применить конфиг"),
                ("2", "🧩 Протоколы",           f"Транспорты (Naive, AmneziaWG, Mieru...)  [{active_t}/{total_t}]"),
                ("3", "👥 Пользователи",        f"Создание, лимиты, TTL, подписки  [{u_active} активно]"),
                ("4", "🤖 Telegram-боты",       "Admin-панель и клиентский бот"),
                ("5", "📊 Мониторинг",          "Трафик, статус, sync-агент, логи"),
                ("6", "🔒 Безопасность",        f"Fail2ban, Honeypot, IPBan  [{active_s}/{total_s}]"),
                ("7", "🌐 Сетевые службы",      f"DNSCrypt, WARP (DNS и маршрутизация)  [{active_e}/{total_e}]"),
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
            panel(f"{p.meta.name.upper()} v{p.meta.version}", lines)
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
                was_enabled = ps.enabled
                orchestrator.uninstall_plugin(state, p.meta.name)
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    if was_enabled:
                        try:
                            orchestrator.enable(state, p.meta.name)
                        except Exception as e:
                            error(f"Ошибка активации: {e}")
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
            ("3", "⚙️  Управление пользователем", "Конфиги, блокировка, удаление"),
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
        elif choice == "0":
            return


def _user_detail_menu(state: AppState, user: User):
    """Детальное меню пользователя с конфигами и управлением."""
    while True:
        clear()
        
        # Панель информации о пользователе
        status_icon = f"{GREEN}🟢{NC}" if not user.blocked else f"{RED}🔴{NC}"
        lines = [
            f"  Email:    {status_icon} {user.email}",
            f"  UUID:     {user.uuid[:8]}...",
            f"  Трафик:   {_bytes_auto(user.traffic_used_bytes)}",
            f"  Создан:   {user.created_at[:10] if user.created_at else '—'}",
        ]
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
            ("3", "❌ Удалить", "Удалить пользователя"),
            ("0", "↩ Назад", ""),
        ], f"ПОЛЬЗОВАТЕЛЬ {user.email}")
        
        if choice == "1":
            _user_configs(state, user)
        elif choice == "2":
            _toggle_block(state, user)
        elif choice == "3":
            if confirm(f"Удалить {user.email}?", default=False):
                orchestrator.remove_user(state, user.email)
                success(f"Пользователь {user.email} удалён")
                prompt("Нажмите Enter")
                return
        elif choice == "0":
            return


def _user_configs(state: AppState, user: User):
    """Показывает конфиги и ссылки для всех протоколов."""
    clear()
    title(f"Конфигурации для пользователя: {user.email}")
    
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
                
                panel(f"⚙️  {p.meta.name.upper()} CONFIG", box_lines)
                
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
    traffic = collect_traffic(state)
    for u in state.users:
        ico = f"{RED}🔴{NC}" if u.blocked else f"{GREEN}🟢{NC}"
        used = traffic.get(u.email, u.traffic_used_bytes)
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

def menu_monitoring(state: AppState):
    while True:
        clear()
        traffic = collect_traffic(state)
        total = sum(traffic.values())
        lines = [
            kv("Трафик всего:", _bytes_auto(total)),
            kv("Пользователей:", str(len(state.users))),
        ]
        lines += _sys_info(state)
        panel("Мониторинг", lines)

        choice = menu(
            [("1", "📊 Трафик по пользователям", ""),
             ("2", "🔌 Статус протоколов", ""),
             ("3", "📋 Лог Sing-Box", "tail -20 /var/log/sing-box/sing-box.log"),
             ("4", "🔄 Sync Agent", "systemd timer, каждые 5 мин"),
             ("0", "↩ Назад", "")],
            "МОНИТОРИНГ",
        )
        if choice == "0":
            return
        elif choice == "1":
            _show_traffic(state)
        elif choice == "2":
            _show_status()
        elif choice == "3":
            _show_singbox_log()
        elif choice == "4":
            _install_sync_agent(state)


def _show_traffic(state: AppState):
    clear()
    traffic = collect_traffic(state)
    title("Трафик")
    print()
    for u in state.users:
        used = traffic.get(u.email, u.traffic_used_bytes)
        lim = int(u.traffic_limit_gb * 1073741824) if u.traffic_limit_gb else 0
        ico = f"{RED}🔴{NC}" if u.blocked else f"{GREEN}🟢{NC}"
        print(f"  {ico} {BOLD}{u.email}{NC}")
        print(f"     {_bytes_auto(used)} / {u.traffic_limit_gb or '∞'} GB")
        print(f"     {_bar(used, lim)}")
        print()
    prompt("Нажмите Enter")


def _show_status():
    clear()
    title("Статус протоколов")
    print()
    for name, s in status_all().items():
        ico = f"{GREEN}●{NC}" if s["running"] else (f"{YELLOW}●{NC}" if s["installed"] else f"{DIM}●{NC}")
        port = f":{s['port']}" if s["port"] else ""
        print(f"  {ico} {name:<14} порт{port:<6} {'запущен' if s['running'] else 'стоп'}")
    print()
    prompt("Нажмите Enter")


def _show_singbox_log():
    clear()
    title("Лог Sing-Box (последние 30 строк)")
    print()
    try:
        log = Path("/var/log/sing-box/sing-box.log")
        if log.exists():
            lines = log.read_text(encoding="utf-8").strip().split("\n")
            for line in lines[-30:]:
                print(f"  {DIM}{line}{NC}")
        else:
            warn("Лог-файл не найден")
    except Exception as e:
        error(f"Ошибка чтения лога: {e}")
    print()
    prompt("Нажмите Enter")


def _install_sync_agent(state: AppState):
    install_timer("hydra-sync-agent",
        """[Unit]
Description=HYDRA Sync Agent
After=network.target
[Service]
Type=oneshot
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
    success("Sync Agent установлен (каждые 5 мин)")
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
            for p in plugins_list:
                _toggle_security_plugin(state, p.meta.name, force_enable=True)
            success("Все службы безопасности включены")
            prompt("Нажмите Enter")
        elif choice == "B":
            for p in plugins_list:
                _toggle_security_plugin(state, p.meta.name, force_enable=False)
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
    if force_enable is True:
        p.on_enable(state)
        if proto:
            proto.enabled = True
        enabled_val = True
    elif force_enable is False:
        p.on_disable(state)
        if proto:
            proto.enabled = False
        enabled_val = False
    else:
        # toggle
        if proto and proto.enabled:
            p.on_disable(state)
            proto.enabled = False
            enabled_val = False
        else:
            p.on_enable(state)
            if proto:
                proto.enabled = True
            enabled_val = True
            
    if name == "fail2ban":
        state.security.fail2ban_enabled = enabled_val
    elif name == "honeypot":
        state.security.honeypot_enabled = enabled_val
        
    save_state(state)
    orchestrator.apply_config(state)
