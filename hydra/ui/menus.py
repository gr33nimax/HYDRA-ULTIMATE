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

def _sys_info() -> list[str]:
    """Возвращает строки с информацией о системе."""
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
        lines.append(kv("PSUTIL:", f"{YELLOW}не установлен{NC}"))
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
        active_p = sum(1 for s in plugins.values() if s["running"])
        total_p = len(plugins)
        u_active = sum(1 for u in state.users if not u.blocked)

        lines = [
            kv("Sing-Box:", f"{_ok(sb_ok)}  {singbox_version() or 'не установлен'}"),
            kv("Протоколов:", f"{GREEN}{active_p}{NC}/{total_p} запущено"),
            kv("Пользователей:", f"{GREEN if u_active else YELLOW}{u_active}{NC} из {len(state.users)}"),
        ]
        lines += _sys_info()
        panel("Состояние", lines)

        choice = menu(
            [
                ("1", "⚙️  Ядро и система",     f"Установка Sing-Box, зависимости, применить конфиг"),
                ("2", "🧩 Протоколы",           f"NaiveProxy, Mieru, AmneziaWG, DNSCrypt, WARP  [{active_p}/{total_p}]"),
                ("3", "👥 Пользователи",        f"Создание, лимиты, TTL, подписки  [{u_active} активно]"),
                ("4", "🤖 Telegram-боты",       f"Admin-панель и клиентский бот"),
                ("5", "📊 Мониторинг",          f"Трафик, статус, sync-агент, логи"),
                ("6", "🛡️  Безопасность",       f"GeoIP, fail2ban, honeypot, IPBan"),
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
                ("1", "📦 Установить Sing-Box" if not ok_i else "🔄 Переустановить",
                 "Официальный репозиторий / GitHub .deb"),
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
            if install_singbox():
                success(f"Sing-Box {singbox_version()} установлен")
                if start_singbox():
                    success("Запущен")
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
            info("Собираю конфиг...")
            cfg = generate_config(state, collect_fragments(state))
            if write_config(cfg):
                success("Конфиг записан")
                if reload_singbox():
                    success("Sing-Box перезагружен")
                else:
                    warn("Перезагрузка не удалась")
            else:
                error("Ошибка валидации конфига")
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

        enhancement_lines = []
        for p in enhancements():
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}●{NC}" if s.get("running") else (f"{YELLOW}●{NC}" if s.get("installed") else f"{DIM}●{NC}")
            port = f":{s['port']}" if s.get("port") else ""
            enhancement_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{'вкл' if s.get('enabled') else 'выкл':>4}{NC}  порт{port}")

        security_p_lines = []
        for p in sec_plugins():
            s = st.get(p.meta.name, {})
            ico = f"{GREEN}●{NC}" if s.get("running") else (f"{YELLOW}●{NC}" if s.get("installed") else f"{DIM}●{NC}")
            security_p_lines.append(f"  {ico} {p.meta.name:<14} {DIM}{'вкл' if s.get('enabled') else 'выкл':>4}{NC}")

        lines = [
            f"  {BOLD}Транспорты:{NC}",
            *transport_lines,
            "",
            f"  {BOLD}Улучшения:{NC}",
            *enhancement_lines,
        ]
        if security_p_lines:
            lines += ["", f"  {BOLD}Безопасность:{NC}", *security_p_lines]
        panel("Протоколы", lines)

        all_p = transports() + enhancements() + sec_plugins()
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


def menu_plugin(state: AppState, p):
    """Универсальное меню плагина."""
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
            options.append(("9", "🗑  Удалить", "Полное удаление"))
        
        options.append(("0", "↩ Назад", ""))
        
        choice = menu(options, p.meta.name.upper())
        
        if choice == "1":
            if not ps.installed:
                info("Установка...")
                ok = orchestrator.install_plugin(state, p.meta.name)
                if ok:
                    success("Установлено!")
                    orchestrator.enable(state, p.meta.name)
                else:
                    error("Ошибка установки")
            elif ps.enabled:
                orchestrator.disable(state, p.meta.name)
                success("Протокол выключен")
            else:
                orchestrator.enable(state, p.meta.name)
                success("Протокол включён")
            prompt("Нажмите Enter")
        
        elif choice == "2" and ps.installed and ps.enabled:
            _show_plugin_clients(state, p)
        
        elif choice == "8" and ps.installed:
            if confirm("Переустановить?", default=False):
                orchestrator.uninstall_plugin(state, p.meta.name)
                ok = orchestrator.install_plugin(state, p.meta.name)
                msg = "Переустановлено!" if ok else "Ошибка переустановки"
                (success if ok else error)(msg)
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
            ("3", "🗑  Удалить", "Удалить пользователя"),
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
                
                panel(f"🛡️  {p.meta.name.upper()} CONFIG", box_lines)
                
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
        lines += _sys_info()
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
    while True:
        clear()
        sec = state.security
        st = status_all()

        panel("Безопасность", [
            kv("GeoIP:", f"{_ok(sec.geoip_block_enabled)}  (РФ, порт {sec.geoip_port})"),
            kv("Fail2ban:", _ok(sec.fail2ban_enabled)),
            kv("Honeypot:", _ok(sec.honeypot_enabled)),
            kv("IPBan:", _ok(st.get("ipban", {}).get("enabled", False))),
        ])

        choice = menu(
            [
                ("1", f"🌍 GeoIP         [{_ok(sec.geoip_block_enabled)}]", "Блокировка РФ по ipset"),
                ("2", f"🛡️  Fail2ban     [{_ok(sec.fail2ban_enabled)}]", "Защита от брутфорса"),
                ("3", f"🪤 Honeypot      [{_ok(sec.honeypot_enabled)}]", "Ловушка для сканеров"),
                ("4", f"🚫 IPBan         [{_ok(st.get('ipban', {}).get('enabled', False))}]", "Блокировка по IP"),
                ("-", "", ""),
                ("A", "✅ Включить всё", "GeoIP + Fail2ban + Honeypot + IPBan"),
                ("B", "❌ Выключить всё", ""),
                ("0", "↩ Назад", ""),
            ],
            "БЕЗОПАСНОСТЬ",
        )

        if choice == "0":
            return
        elif choice == "1":
            sec.geoip_block_enabled = not sec.geoip_block_enabled
            save_state(state)
            _toggle_security_plugin(state, "geoip")
            success(f"GeoIP {'включён' if sec.geoip_block_enabled else 'выключен'}")
            prompt("Нажмите Enter")
        elif choice == "2":
            sec.fail2ban_enabled = not sec.fail2ban_enabled
            save_state(state)
            _toggle_security_plugin(state, "fail2ban")
            success(f"Fail2ban {'включён' if sec.fail2ban_enabled else 'выключен'}")
            prompt("Нажмите Enter")
        elif choice == "3":
            sec.honeypot_enabled = not sec.honeypot_enabled
            save_state(state)
            _toggle_security_plugin(state, "honeypot")
            success(f"Honeypot {'включён' if sec.honeypot_enabled else 'выключен'}")
            prompt("Нажмите Enter")
        elif choice == "4":
            _toggle_security_plugin(state, "ipban")
            success("IPBan переключён")
            prompt("Нажмите Enter")
        elif choice.upper() == "A":
            sec.geoip_block_enabled = True
            sec.fail2ban_enabled = True
            sec.honeypot_enabled = True
            save_state(state)
            for name in ("geoip", "fail2ban", "honeypot", "ipban"):
                _toggle_security_plugin(state, name, force_enable=True)
            success("Всё включено")
            prompt("Нажмите Enter")
        elif choice.upper() == "B":
            sec.geoip_block_enabled = False
            sec.fail2ban_enabled = False
            sec.honeypot_enabled = False
            save_state(state)
            for name in ("geoip", "fail2ban", "honeypot", "ipban"):
                _toggle_security_plugin(state, name, force_enable=False)
            success("Всё выключено")
            prompt("Нажмите Enter")


def _toggle_security_plugin(state: AppState, name: str, force_enable: bool | None = None):
    """Включает/выключает security-плагин через его on_enable/on_disable."""
    from hydra.plugins.registry import get as get_plugin
    p = get_plugin(name)
    if not p:
        return

    proto = get_protocol(state, name)
    if force_enable is True:
        p.on_enable(state)
        if proto:
            proto.enabled = True
    elif force_enable is False:
        p.on_disable(state)
        if proto:
            proto.enabled = False
    else:
        # toggle
        if proto and proto.enabled:
            p.on_disable(state)
            proto.enabled = False
        else:
            p.on_enable(state)
            if proto:
                proto.enabled = True
    save_state(state)
